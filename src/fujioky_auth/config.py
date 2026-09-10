from dataclasses import dataclass


@dataclass(frozen=True)
class AuthConfig:
    app_name: str
    base_url: str
    issuer: str
    client_id: str
    client_secret: str
    session_secret: str
    cookie_name: str
    session_ttl: int = 14 * 86400
    scopes: str = "openid profile email offline_access"
    dev_login: bool = False
    account_center: str = ""

    @property
    def ready(self):
        return bool(self.issuer and self.client_id and self.client_secret and self.session_secret)

    @property
    def callback(self):
        return self.base_url + "/auth/callback"

    @classmethod
    def from_settings(cls, settings):
        return cls(app_name=settings.app_name, base_url=settings.base_url,
                   issuer=settings.oidc_issuer, client_id=settings.oidc_client_id,
                   client_secret=settings.oidc_client_secret, session_secret=settings.session_secret,
                   cookie_name=settings.cookie_name, session_ttl=settings.session_ttl,
                   scopes=settings.oidc_scopes, dev_login=settings.dev_login,
                   account_center=getattr(settings, "oidc_account_center", ""))
