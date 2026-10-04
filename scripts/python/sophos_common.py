"""Sophos Central API helper (OAuth2 client-credentials flow)."""
import time

import requests

from entity_common import need_env

TOKEN_URL = "https://id.sophos.com/api/v2/oauth2/token"
WHOAMI_URL = "https://api.central.sophos.com/whoami/v1"


class SophosCentral:
    def __init__(self):
        self.client_id = need_env("SOPHOS_CLIENT_ID")
        self.client_secret = need_env("SOPHOS_CLIENT_SECRET")
        self.session = requests.Session()
        self._token_expiry = 0
        self._authenticate()

    def _authenticate(self):
        r = requests.post(TOKEN_URL, data={
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "token"}, timeout=30)
        r.raise_for_status()
        tok = r.json()
        self._token_expiry = time.time() + tok["expires_in"] - 60
        self.session.headers["Authorization"] = f"Bearer {tok['access_token']}"
        who = self.session.get(WHOAMI_URL, timeout=30)
        who.raise_for_status()
        who = who.json()
        if who.get("idType") != "tenant":
            raise SystemExit("Credentials are not tenant-level. Create them inside the tenant.")
        self.tenant_id = who["id"]
        self.base = who["apiHosts"]["dataRegion"]
        self.session.headers["X-Tenant-ID"] = self.tenant_id

    def request(self, method, path, **kw):
        if time.time() > self._token_expiry:
            self._authenticate()
        for attempt in range(4):
            r = self.session.request(method, self.base + path, timeout=60, **kw)
            if r.status_code == 429:
                time.sleep(int(r.headers.get("Retry-After", 2 ** attempt)))
                continue
            r.raise_for_status()
            return r.json()
        raise RuntimeError("Sophos API rate limit persisted after retries")

    def paged(self, method, path, params=None, body=None):
        """Yield every item from a paginated endpoint (follows pages.nextKey)."""
        params, body = dict(params or {}), dict(body or {})
        while True:
            if method == "GET":
                data = self.request("GET", path, params=params)
            else:
                data = self.request(method, path, json=body)
            yield from data.get("items", [])
            nxt = data.get("pages", {}).get("nextKey")
            if not nxt:
                break
            if method == "GET":
                params["pageFromKey"] = nxt
            else:
                body["pageFromKey"] = nxt
