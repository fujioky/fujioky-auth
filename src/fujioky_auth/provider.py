"""OIDC network boundary. Never log tokens, client secrets or provider bodies."""
import time

import httpx
from authlib.integrations.starlette_client import OAuth
from authlib.jose import JsonWebToken


class InvalidToken(ValueError):
    pass


class ProviderUnavailable(RuntimeError):
    pass


class LogtoProvider:
    def __init__(self, config):
        self.config = config
        self.oauth = OAuth()
        if config.ready:
            self.oauth.register(name="sso", client_id=config.client_id, client_secret=config.client_secret,
                                server_metadata_url=config.issuer + "/.well-known/openid-configuration",
                                client_kwargs={"scope": config.scopes, "code_challenge_method": "S256"})
        self._metadata = None
        self._keys = None
        self._metadata_at = self._keys_at = 0

    async def metadata(self):
        if self._metadata and time.time() - self._metadata_at < 600:
            return self._metadata
        if not self.config.ready:
            raise ProviderUnavailable("Login is not configured")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(self.config.issuer + "/.well-known/openid-configuration")
                r.raise_for_status()
            result = r.json()
            if result.get("issuer") != self.config.issuer:
                raise ValueError("Issuer mismatch")
        except (httpx.HTTPError, ValueError):
            raise ProviderUnavailable("OIDC discovery unavailable") from None
        self._metadata, self._metadata_at = result, time.time()
        return result

    async def endpoint(self, key):
        value = (await self.metadata()).get(key, "")
        if not isinstance(value, str) or not value.startswith("https://"):
            raise ProviderUnavailable("OIDC endpoint unavailable")
        return value

    async def jwks(self, force=False):
        if self._keys and time.time() - self._keys_at < (30 if force else 600):
            return self._keys
        try:
            url = await self.endpoint("jwks_uri")
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url)
                r.raise_for_status()
            result = r.json()
            if not isinstance(result.get("keys"), list):
                raise ValueError()
        except (httpx.HTTPError, ValueError):
            raise ProviderUnavailable("OIDC keys unavailable") from None
        self._keys, self._keys_at = result, time.time()
        return result

    async def validate_jwt(self, raw, *, logout=False, sub=None):
        if not isinstance(raw, str) or len(raw) > 16000:
            raise InvalidToken("Invalid JWT")
        options = {"iss": {"essential": True, "value": self.config.issuer},
                   "aud": {"essential": True, "value": self.config.client_id},
                   "iat": {"essential": True}, "exp": {"essential": not logout}}
        claims = None
        for force in (False, True):
            keys = await self.jwks(force=force)
            try:
                claims = JsonWebToken(["RS256", "ES256"]).decode(raw, keys, claims_options=options)
                claims.validate(leeway=30)
                break
            except Exception:
                if force:
                    raise InvalidToken("JWT validation failed") from None
        current = int(time.time())
        for key in ("iat", "exp"):
            value = claims.get(key)
            if key in claims and (not isinstance(value, (int, float)) or isinstance(value, bool)):
                raise InvalidToken("Invalid timestamp")
        if claims["iat"] > current + 30:
            raise InvalidToken("Future token")
        if logout:
            event = "http://schemas.openid.net/event/backchannel-logout"
            if (claims["iat"] < current - 300 or "nonce" in claims
                    or not isinstance(claims.get("events"), dict) or claims["events"].get(event) != {}
                    or not isinstance(claims.get("jti"), str) or not claims["jti"]
                    or not any(isinstance(claims.get(k), str) and claims[k] for k in ("sub", "sid"))):
                raise InvalidToken("Invalid logout token")
            for key in ("sub", "sid"):
                if key in claims and (not isinstance(claims[key], str) or not claims[key]):
                    raise InvalidToken("Invalid logout subject")
        elif (not isinstance(claims.get("sub"), str) or not claims["sub"] or "events" in claims
              or (sub is not None and claims["sub"] != sub)):
            raise InvalidToken("Invalid ID token subject")
        return dict(claims)

    async def refresh(self, refresh_token):
        url = await self.endpoint("token_endpoint")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(url, auth=(self.config.client_id, self.config.client_secret),
                                      data={"grant_type": "refresh_token", "refresh_token": refresh_token})
            if r.status_code == 400 and r.json().get("error") == "invalid_grant":
                raise InvalidToken("Refresh token revoked or expired")
            r.raise_for_status()
            token = r.json()
            if not token.get("access_token") or not isinstance(token.get("expires_in"), (int, float)) or token["expires_in"] <= 0:
                raise ValueError()
            if str(token.get("token_type", "")).lower() != "bearer":
                raise ValueError()
            return token
        except (httpx.HTTPError, ValueError) as exc:
            if isinstance(exc, InvalidToken):
                raise
            raise ProviderUnavailable("Token refresh temporarily unavailable") from None

    async def userinfo(self, access_token):
        url = await self.endpoint("userinfo_endpoint")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(url, headers={"Authorization": "Bearer " + access_token})
                if r.status_code == 401:
                    raise InvalidToken("Access token rejected")
                r.raise_for_status()
            return r.json()
        except (httpx.HTTPError, ValueError) as exc:
            if isinstance(exc, InvalidToken):
                raise
            raise ProviderUnavailable("Profile temporarily unavailable") from None

    async def revoke(self, refresh_token):
        url = await self.endpoint("revocation_endpoint")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.post(url, auth=(self.config.client_id, self.config.client_secret),
                                      data={"token": refresh_token, "token_type_hint": "refresh_token"})
                r.raise_for_status()
        except httpx.HTTPError:
            raise ProviderUnavailable("Remote revocation unavailable") from None
