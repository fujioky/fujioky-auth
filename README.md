# fujioky-auth

A reusable Python package for FastAPI applications using Logto. Version 0.2.1.
No extra authentication service or database is required. Each application retains
its own users, database, cookie, Logto client and authorization policy.

## Responsibilities

- OIDC authorization code + S256 PKCE, state and nonce validation through Authlib.
- Opaque, host-only, HttpOnly/Secure session cookies. Session records and Logto sid/sub live in the app database.
- Authenticated encryption of provider tokens at rest, with an app-specific key derived from SESSION_SECRET.
- Refresh token rotation, a database lease preventing concurrent refreshes across workers, bounded sessions, and profile sync.
- RP-initiated Logto logout and validated, replay-safe OIDC back-channel logout.
- Device list/revocation and links to the Logto-hosted account center.
- Optional transactional on_revoke hook for app-specific delegated access.

Business data, admin roles, SMTP, and MCP OAuth grants are **not** owned by this package.
Only accounts with verified email can claim legacy email-only users. A different
subject cannot silently take over an already-bound email. Profile updates retain
the local user ID, preserving associations with private data.

## Install

Install the versioned source from GitHub (not published to PyPI):

```sh
pip install "fujioky-auth @ git+https://github.com/fujioky/fujioky-auth.git@v0.2.1"
```

For development:

```sh
git clone https://github.com/fujioky/fujioky-auth.git
cd fujioky-auth
pip install -e '.[test]'
python -m pytest
```

Download a wheel from [GitHub Releases](https://github.com/fujioky/fujioky-auth/releases),
or build one locally with `pip install build` followed by `python -m build`.

## Application adapter

The app supplies SQLAlchemy Base/get_db, its User model and a user-upsert callback.
User objects must expose id, sub, email, name, avatar and is_admin. The optional
upsert_standard_user helper works with the BIDE/NOTE user schema.
Instantiate exactly one AuthManager per application's metadata:

```python
from fujioky_auth import AuthConfig, AuthManager
from starlette.middleware.sessions import SessionMiddleware

manager = AuthManager(
    AuthConfig.from_settings(settings),
    base=Base, get_db=get_db, user_model=User, upsert_user=upsert_user,
)
app.add_middleware(
    SessionMiddleware, secret_key=settings.session_secret,
    session_cookie=settings.app_name + "_oidc",
    same_site="lax", https_only=True, max_age=600,
)
app.include_router(manager.router)
# Register manager models before initializing the database.
Base.metadata.create_all(engine)

# Route dependencies:
# Depends(manager.current_user) -> User or None
# Depends(manager.require_user) -> signed-in User
# Depends(manager.require_admin) -> app-approved admin
```

The cookie middleware stores only short-lived OIDC state and CSRF values, not
provider access/refresh/ID tokens. Do not restore the old user-id signed cookie
or its renewal middleware. Install the router and middleware in your application
entrypoint, and register the manager models before database initialization.

## Environment and Logto console

```dotenv
OIDC_ISSUER=https://auth.example.com/oidc
OIDC_CLIENT_ID=<this application's existing Logto ID>
OIDC_CLIENT_SECRET=<this application's existing Logto secret>
OIDC_SCOPES=openid profile email offline_access
OIDC_ACCOUNT_CENTER=https://auth.example.com/account
SESSION_SECRET=<strong independent random secret per app>
SESSION_TTL_DAYS=14
DEV_LOGIN=0
```

For every new app, register its own normal Logto Web application. Reusing this
Python package does not mean reusing another application's client secret or cookies.
The user's Logto login session provides SSO between the apps.

Register each application's callback (`/auth/callback`), post-logout
redirect (`/auth/logged-out`) and back-channel logout (`/auth/backchannel-logout`)
under its own hostname. Enable refresh token rotation and select the session
lifetime appropriate for your deployment. All domains in this document are examples.

Enable Account API in Logto's Sign-in & account → Account center. Allow editing
name/avatar and the account fields you intend to offer. The app provides profile,
security, email and password links; available security options still depend on
your tenant configuration and plan. No MFA, passkey or paid capability is silently enabled.
Spacemail and social providers remain configured in Logto connectors.

The package requests offline_access with prompt=consent, so the nonstandard
"always issue refresh token" override is unnecessary. Refresh expiry is governed
by Logto; local sessions have a separate absolute lifetime and cannot renew forever.

## Logout semantics and operational limits

- GET /auth/logout shows confirmation; POST requires a session-bound CSRF token.
- Local session revocation succeeds even if Logto is unavailable. In that case
  the UI explicitly says other apps may still be signed in.
- Back-channel tokens require a trusted signature, matching issuer/audience,
  recent iat, logout event, jti, and sid or sub; nonce is prohibited.
- sid targets matching sessions; a subject-only notification targets all of that
  user's sessions in this app. Valid repeated notifications return 200 without reapplying.
- BIDE's optional revoke hook also revokes MCP grants created by the affected
  local session. Natural browser-session expiry does not revoke offline MCP
  access; explicit logout/device revocation/provider logout does.
- Logto outages return a retryable 503 when refresh is required. Revoked/expired
  refresh credentials invalidate the local session. Provider tokens are never logged.
- Changing SESSION_SECRET invalidates old cookies and encrypted provider tokens.
- Existing legacy signed cookies require a one-time fresh login after upgrade.
- Back-channel delivery needs public HTTPS endpoints. Configure the console and
  deploy the app before testing cross-app logout. Cloud-side behavior has not
  been verified just by passing local tests.

Sources: [Logto sign-out](https://docs.logto.io/end-user-flows/sign-out),
[Account center](https://docs.logto.io/end-user-flows/account-settings/by-account-center-ui),
[OIDC back-channel logout](https://openid.net/specs/openid-connect-backchannel-1_0.html).

## Shared account interface

`/auth/account` opens the Logto-hosted account center and synchronizes profile
changes when the user returns to the application.
Place `<span data-lyra-auth></span>` in the application header and load
`<script src="/auth/ui.js" defer></script>` once. Signed-in users see an avatar;
hover or keyboard focus reveals shortcuts, and clicking opens the hosted account center.
Touch users enter the account center directly. Device and app authorization
shortcuts remain available in the local navigation.

Optional `AuthConfig.profile_links` adds application-specific destinations:

```python
profile_links=({"href": "/oauth/connections", "label": "Authorized applications",
                "description": "Manage client access"},)
```

Only local paths are accepted. Each application retains independent sessions
and displays only the current user's information.
