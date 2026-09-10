import asyncio
import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from datetime import datetime

from cryptography.fernet import Fernet, InvalidToken as InvalidCiphertext
from fastapi import Depends, HTTPException, Request
from sqlalchemy import delete, select, update

from .models import create_models
from .provider import InvalidToken, LogtoProvider, ProviderUnavailable

log = logging.getLogger("fujioky.auth")


def now():
    return int(time.time())


def digest(raw):
    return hashlib.sha256(raw.encode()).hexdigest()


class AuthManager:
    """One instance per app. All mutable state lives in that app's database.

    upsert_user(db, claims) must return (local_user, created). Authorization roles
    are entirely the application's decision. on_revoke(db, session_ids) runs in
    the same transaction, allowing an app to revoke delegated access as well.
    """
    def __init__(self, config, *, base, get_db, user_model, upsert_user, on_revoke=None):
        self.config = config
        self.User = user_model
        self.get_db = get_db
        self.upsert_user = upsert_user
        self.on_revoke = on_revoke
        self.Session, self.LogoutEvent = create_models(base, user_model.__tablename__)
        self.provider = LogtoProvider(config)
        key = hashlib.sha256(("fujioky-auth:tokens:v1:" + config.app_name + ":" + config.session_secret).encode()).digest()
        self._cookie_key = key
        self.cipher = Fernet(base64.urlsafe_b64encode(key))

        async def current_user(request: Request, db=Depends(get_db)):
            return await self.resolve_user(request, db)

        async def require_user(user=Depends(current_user)):
            if not user:
                raise HTTPException(401, {"error": "需要登录"})
            return user

        async def require_admin(user=Depends(require_user)):
            if not user.is_admin:
                raise HTTPException(403, {"error": "需要管理员"})
            return user

        self.current_user = current_user
        self.require_user = require_user
        self.require_admin = require_admin
        from .web import build_router
        self.router = build_router(self)

    def session_id(self, raw):
        return hmac.new(self._cookie_key, raw.encode(), hashlib.sha256).hexdigest()

    def encrypt(self, token):
        return self.cipher.encrypt(json.dumps(token).encode()).decode()

    def decrypt(self, value):
        if not value:
            return {}
        try:
            return json.loads(self.cipher.decrypt(value.encode()))
        except (InvalidCiphertext, ValueError):
            raise InvalidToken("Session encryption key changed") from None

    def create_session(self, db, user, claims, token, agent=""):
        if not self.config.session_secret:
            raise InvalidToken("SESSION_SECRET required")
        raw = secrets.token_urlsafe(48)
        expires = now() + self.config.session_ttl
        access_exp = int(token.get("expires_at") or (now() + float(token.get("expires_in", 3600)))) if token else expires
        db.execute(delete(self.Session).where(self.Session.expires < now() - 31 * 86400))
        row = self.Session(id=self.session_id(raw), user_id=user.id, issuer=self.config.issuer,
                           sub=claims["sub"], sid=str(claims.get("sid") or ""),
                           tokens=self.encrypt(token) if token else "", token_expires=access_exp,
                           expires=expires, created=now(), last_seen=now(), agent=agent[:300])
        db.add(row)
        db.commit()
        return raw

    def session(self, request, db):
        raw = request.cookies.get(self.config.cookie_name, "")
        if not raw or len(raw) > 200:
            return None
        return db.get(self.Session, self.session_id(raw))

    def revoke_sessions(self, db, ids):
        if not ids:
            return
        db.execute(update(self.Session).where(self.Session.id.in_(ids)).values(revoked=True, tokens=""))
        if self.on_revoke:
            self.on_revoke(db, ids)

    async def resolve_user(self, request, db):
        if getattr(request.state, "user_checked", False):
            return getattr(request.state, "user", None)
        request.state.user_checked = True
        row = self.session(request, db)
        if not row or row.revoked or row.expires <= now() or row.issuer != self.config.issuer:
            return None
        if row.tokens and row.token_expires <= now() + 60:
            try:
                await self.refresh_session(db, row.id)
            except InvalidToken:
                self.revoke_sessions(db, [row.id])
                db.commit()
                return None
            except ProviderUnavailable:
                raise HTTPException(503, {"error": "登录服务暂时不可用，请稍后重试"}) from None
            db.expire_all()
            row = db.get(self.Session, row.id)
            if not row or row.revoked:
                return None
        user = db.get(self.User, row.user_id)
        if user:
            request.state.user = user
            request.state.auth_session = row
            if row.last_seen < now() - 300:
                row.last_seen = now()
                db.commit()
        return user

    async def refresh_session(self, db, ident):
        lease = secrets.token_urlsafe(24)
        for _ in range(100):
            db.expire_all()
            row = db.get(self.Session, ident)
            if not row or row.revoked or row.expires <= now():
                raise InvalidToken("Session ended")
            if row.token_expires > now() + 60:
                return
            acquired = db.execute(update(self.Session).where(self.Session.id == ident,
                self.Session.revoked.is_(False), self.Session.refresh_until <= now(),
                self.Session.token_expires <= now() + 60).values(refresh_until=now()+45, refresh_owner=lease)).rowcount
            db.commit()
            if acquired:
                break
            await asyncio.sleep(.1)
        else:
            raise ProviderUnavailable("Session refresh busy")
        try:
            row = db.get(self.Session, ident)
            old = self.decrypt(row.tokens)
            if not old.get("refresh_token"):
                raise InvalidToken("Session requires login")
            new = await self.provider.refresh(old["refresh_token"])
            claims = None
            if new.get("id_token"):
                claims = await self.provider.validate_jwt(new["id_token"], sub=row.sub)
                if claims.get("sid") and row.sid and claims["sid"] != row.sid:
                    raise InvalidToken("Session identity changed")
            merged = {**old, **new}
            expiry = now() + int(new["expires_in"])
            merged["expires_at"] = expiry
            changed = db.execute(update(self.Session).where(self.Session.id == ident,
                self.Session.refresh_owner == lease, self.Session.revoked.is_(False)).values(
                    tokens=self.encrypt(merged), token_expires=expiry)).rowcount
            db.commit()  # Persist rotation before further network requests.
            if not changed:
                raise InvalidToken("Session ended during refresh")
            try:
                profile = await self.provider.userinfo(new["access_token"])
            except ProviderUnavailable:
                profile = None  # Access is valid; profile can catch up on the next refresh/login.
            if profile is not None:
                if not isinstance(profile, dict) or profile.get("sub") != row.sub:
                    raise InvalidToken("Userinfo identity mismatch")
                self.upsert_user(db, {**(claims or {}), **profile})
        except ValueError as exc:
            self.revoke_sessions(db, [ident])
            db.commit()
            raise InvalidToken("Invalid refreshed identity") from exc
        finally:
            db.execute(update(self.Session).where(self.Session.id == ident, self.Session.refresh_owner == lease)
                       .values(refresh_until=0, refresh_owner=""))
            db.commit()

    async def remote_revoke(self, token):
        if token.get("refresh_token"):
            try:
                await self.provider.revoke(token["refresh_token"])
            except ProviderUnavailable:
                log.warning("Provider revocation unavailable; local session is already revoked")

    def set_cookie(self, response, raw):
        response.set_cookie(self.config.cookie_name, raw, max_age=self.config.session_ttl, path="/",
                            httponly=True, secure=self.config.base_url.startswith("https"), samesite="lax")

    def clear_cookie(self, response):
        response.delete_cookie(self.config.cookie_name, path="/")


def upsert_standard_user(db, model, claims, is_admin):
    """Verified-email migration adapter for the existing BIDE/NOTE user schema."""
    sub, email = str(claims.get("sub") or ""), str(claims.get("email") or "").lower()
    if not sub:
        raise ValueError("Missing subject")
    if email and claims.get("email_verified") is not True:
        raise ValueError("Verified email required")
    user = db.scalar(select(model).where(model.sub == sub))
    created = False
    if not user:
        email = email or f"{sub}@no-email.local"
        user = db.scalar(select(model).where(model.email == email))
        if user and user.sub and user.sub != sub:
            raise ValueError("Email already bound to another identity")
        if not user:
            user = model(email=email)
            db.add(user)
            created = True
        user.sub = sub
    if email:
        collision = db.scalar(select(model).where(model.email == email, model.id != user.id)) if user.id else None
        if collision:
            raise ValueError("Email already owned by another account")
        user.email = email
    user.name = str(claims.get("name") or claims.get("username") or claims.get("preferred_username") or user.name or user.email.split("@")[0])[:120]
    user.avatar = str(claims.get("picture") or user.avatar or "")[:600]
    user.is_admin = is_admin(claims)
    user.last_login = datetime.utcnow()
    db.commit()
    return user, created
