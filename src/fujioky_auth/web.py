import hashlib
import hmac
import html
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from .manager import digest, now
from .provider import InvalidToken, ProviderUnavailable

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"}
PAGE_HEADERS = {**NO_STORE, "X-Frame-Options": "DENY", "Content-Security-Policy":
                "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"}


def safe_next(value):
    value = str(value or "")
    if not value.startswith("/") or value.startswith("//") or "\\" in value or any(ord(c) < 32 for c in value):
        return "/"
    return value[:300]


def csrf(request, action):
    nonce = request.session.setdefault("auth_csrf", secrets.token_urlsafe(32))
    return hmac.new(nonce.encode(), action.encode(), hashlib.sha256).hexdigest()


def check_csrf(request, action, value, origin):
    if (not request.session.get("auth_csrf") or not hmac.compare_digest(csrf(request, action), str(value or ""))
            or request.headers.get("origin") not in (None, origin)):
        raise HTTPException(403, {"error": "页面已过期，请重新打开"})


async def form(request):
    if request.headers.get("content-type", "").split(";")[0] != "application/x-www-form-urlencoded":
        raise HTTPException(400, {"error": "Expected form encoding"})
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 20000:
            raise HTTPException(413)
    try:
        pairs = parse_qsl(body.decode(), keep_blank_values=True, max_num_fields=20)
    except (UnicodeError, ValueError):
        raise HTTPException(400) from None
    result = dict(pairs)
    if len(result) != len(pairs):
        raise HTTPException(400, {"error": "Duplicate parameter"})
    return result


def page(config, title, body):
    esc = html.escape
    return HTMLResponse('''<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'''+esc(title)+" · "+esc(config.app_name.upper())+'''</title><style>body{font:17px/1.7 system-ui;background:#f5f5f3;color:#202623;padding:28px 16px}main{max-width:660px;margin:4vh auto;background:white;padding:30px;border-radius:16px}h1{font-size:26px}a{color:#24553f}button{font:inherit;border:0;border-radius:8px;background:#163f2e;color:white;padding:10px 20px;cursor:pointer}article{border-top:1px solid #ddd;padding:16px 0}.muted{color:#626b65;overflow-wrap:anywhere}</style><main><a href="/">'''+esc(config.app_name.upper())+"</a><h1>"+esc(title)+"</h1>"+body+"</main></html>", headers=PAGE_HEADERS)


def hidden(name, value):
    return f'<input type="hidden" name="{html.escape(name)}" value="{html.escape(str(value))}">'


def build_router(manager):
    cfg, get_db = manager.config, manager.get_db
    async def host(request: Request):
        if request.headers.get("host", "").lower() != urlsplit(cfg.base_url).netloc.lower():
            raise HTTPException(404)
    router = APIRouter(dependencies=[Depends(host)])

    @router.get("/auth/whoami")
    async def whoami(user=Depends(manager.current_user)):
        return JSONResponse({"signedIn": bool(user), "admin": bool(user and user.is_admin),
                             "name": user.name if user else None, "email": user.email if user else None,
                             "avatar": user.avatar if user else "", "authReady": cfg.ready}, headers=NO_STORE)

    @router.get("/auth/login")
    async def login(request: Request, next: str = "/", reauthenticate: bool = False):
        if not cfg.ready:
            raise HTTPException(503, {"error": "auth not configured"})
        request.session["next"] = safe_next(next)
        prompts = []
        if reauthenticate:
            prompts.append("login")
        if "offline_access" in cfg.scopes.split():
            prompts.append("consent")
        return await manager.provider.oauth.sso.authorize_redirect(request, cfg.callback,
                            **({"prompt": " ".join(prompts)} if prompts else {}))

    @router.get("/auth/callback")
    async def callback(request: Request, db=Depends(get_db)):
        if not cfg.ready:
            return RedirectResponse("/?autherr=notconfigured")
        back = safe_next(request.session.pop("next", "/"))
        try:
            token = await manager.provider.oauth.sso.authorize_access_token(request)
            claims = dict(token.get("userinfo") or {})  # Authlib validated state, nonce and ID token.
            if not token.get("id_token") or not claims.get("sub"):
                raise InvalidToken("Missing validated ID token")
            if not claims.get("email") or "email_verified" not in claims:
                more = await manager.provider.userinfo(token["access_token"])
                if more.get("sub") != claims["sub"]:
                    raise InvalidToken("Userinfo subject mismatch")
                claims.update(more)
            user, created = manager.upsert_user(db, claims)
            previous = manager.session(request, db)
            if previous:
                # Rotate local login without revoking previously delegated grants.
                previous.revoked, previous.tokens = True, ""
                db.commit()
            raw = manager.create_session(db, user, claims, token, request.headers.get("user-agent", ""))
        except Exception:
            db.rollback()
            # Exceptions may contain provider response bodies; never log them.
            return RedirectResponse("/?autherr=login", status_code=302, headers=NO_STORE)
        response = RedirectResponse(back, status_code=302, headers=NO_STORE)
        manager.set_cookie(response, raw)
        hook = getattr(request.app.state, "on_login", None)
        if hook:
            try:
                hook(request, user, created)
            except Exception:
                pass
        return response

    @router.get("/auth/dev")
    def dev_login(request: Request, email: str, admin: int = 0, db=Depends(get_db)):
        if not cfg.dev_login:
            raise HTTPException(404)
        claims = {"sub": "dev:" + email, "email": email, "email_verified": True,
                  "name": email.split("@")[0], "roles": ["admin"] if admin else []}
        user, _ = manager.upsert_user(db, claims)
        raw = manager.create_session(db, user, claims, {}, request.headers.get("user-agent", ""))
        response = RedirectResponse("/", status_code=302, headers=NO_STORE)
        manager.set_cookie(response, raw)
        return response

    @router.get("/auth/logout")
    def logout_page(request: Request, next: str = "/", db=Depends(get_db)):
        row = manager.session(request, db)
        if not row:
            response = RedirectResponse(safe_next(next), status_code=302, headers=NO_STORE)
            manager.clear_cookie(response)
            return response
        body = '<p>退出本应用，并结束当前统一登录会话。其他应用会在收到注销通知后退出。</p>'
        body += '<form method="post" action="/auth/logout">'+hidden("csrf",csrf(request,"logout:"+row.id))+hidden("next",safe_next(next))+'<button>确认退出</button></form>'
        return page(cfg, "退出登录", body)

    @router.post("/auth/logout")
    async def logout(request: Request, db=Depends(get_db)):
        data = await form(request)
        row = manager.session(request, db)
        if not row:
            raise HTTPException(401)
        check_csrf(request,"logout:"+row.id,data.get("csrf"),cfg.base_url)
        try:
            token = manager.decrypt(row.tokens)
        except InvalidToken:
            token = {}
        manager.revoke_sessions(db, [row.id])
        db.commit()  # Local revocation succeeds even if Logto is down.
        back = safe_next(data.get("next"))
        request.session.clear()
        target = back
        if cfg.ready and token.get("id_token"):
            try:
                endpoint = await manager.provider.endpoint("end_session_endpoint")
                state = secrets.token_urlsafe(32)
                request.session["logout"] = {"state": state, "next": back, "expires": now()+600}
                target = endpoint + "?" + urlencode({"id_token_hint":token["id_token"], "client_id":cfg.client_id,
                            "post_logout_redirect_uri":cfg.base_url+"/auth/logged-out", "state":state})
            except ProviderUnavailable:
                target = "/auth/logged-out?local_only=1"
        await manager.remote_revoke(token)
        response = RedirectResponse(target, status_code=303, headers=NO_STORE)
        manager.clear_cookie(response)
        return response

    @router.get("/auth/logged-out")
    def logged_out(request: Request, state: str = "", local_only: bool = False):
        pending = request.session.pop("logout", {})
        if local_only:
            return page(cfg, "已退出本应用", "<p>统一登录服务暂时不可用，其他应用可能仍保持登录。</p>")
        if (not pending or pending.get("expires",0) < now()
                or not hmac.compare_digest(str(pending.get("state","")),state)):
            raise HTTPException(400, {"error":"退出登录回调已过期或无效"})
        return RedirectResponse(safe_next(pending.get("next")), status_code=302, headers=NO_STORE)

    @router.post("/auth/backchannel-logout")
    async def backchannel(request: Request, db=Depends(get_db)):
        data = await form(request)
        try:
            claims = await manager.provider.validate_jwt(data.get("logout_token"), logout=True)
        except InvalidToken:
            return JSONResponse({"error":"invalid_logout_token"},status_code=400,headers=NO_STORE)
        except ProviderUnavailable:
            return JSONResponse({"error":"temporarily_unavailable"},status_code=503,headers=NO_STORE)
        ident = digest(cfg.issuer+":"+claims["jti"])
        db.execute(delete(manager.LogoutEvent).where(manager.LogoutEvent.expires < now()))
        if db.get(manager.LogoutEvent,ident):
            return Response(status_code=200,headers=NO_STORE)
        db.add(manager.LogoutEvent(id=ident,expires=now()+600))
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return Response(status_code=200,headers=NO_STORE)
        query = select(manager.Session.id).where(manager.Session.issuer==cfg.issuer,
                            manager.Session.created <= claims["iat"], manager.Session.revoked.is_(False))
        if claims.get("sid"):
            query = query.where(manager.Session.sid==claims["sid"])
        if claims.get("sub"):
            query = query.where(manager.Session.sub==claims["sub"])
        manager.revoke_sessions(db,list(db.scalars(query)))
        db.commit()
        return Response(status_code=200,headers=NO_STORE)

    @router.get("/auth/sessions")
    async def sessions(request: Request, db=Depends(get_db), user=Depends(manager.current_user)):
        if not user:
            return RedirectResponse("/auth/login?next=/auth/sessions",status_code=302,headers=NO_STORE)
        rows = db.scalars(select(manager.Session).where(manager.Session.user_id==user.id,
                           manager.Session.revoked.is_(False),manager.Session.expires>now()).order_by(manager.Session.created.desc())).all()
        body = '<p>'+html.escape(user.email)+'</p><p><a href="/auth/account">账号与安全设置</a></p>'
        for row in rows:
            label = "当前设备" if row.id==request.state.auth_session.id else "其他设备"
            date = datetime.fromtimestamp(row.created, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            body += '<article><strong>'+label+'</strong><p class="muted">'+html.escape(row.agent or "未知浏览器")+'<br>'+date+'</p>'
            body += '<form method="post" action="/auth/sessions/revoke">'+hidden("session_id",row.id)+hidden("csrf",csrf(request,"revoke:"+row.id+":"+str(user.id)))+'<button>退出此设备</button></form></article>'
        return page(cfg,"登录设备",body)

    @router.post("/auth/sessions/revoke")
    async def revoke_device(request: Request, db=Depends(get_db), user=Depends(manager.require_user)):
        data = await form(request)
        ident = data.get("session_id","")
        check_csrf(request,"revoke:"+ident+":"+str(user.id),data.get("csrf"),cfg.base_url)
        row = db.get(manager.Session,ident)
        if not row or row.user_id!=user.id:
            raise HTTPException(404)
        try:
            token = manager.decrypt(row.tokens)
        except InvalidToken:
            token = {}
        manager.revoke_sessions(db,[row.id])
        db.commit()
        await manager.remote_revoke(token)
        response = RedirectResponse("/auth/sessions",status_code=303,headers=NO_STORE)
        if row.id==request.state.auth_session.id:
            manager.clear_cookie(response)
        return response

    @router.get("/auth/account")
    async def account(section: str = "security", user=Depends(manager.require_user)):
        if not cfg.account_center:
            raise HTTPException(503,{"error":"账号中心尚未配置"})
        if section not in ("profile","security","email","password"):
            raise HTTPException(400)
        url = cfg.account_center.rstrip("/")+"/"+section+"?"+urlencode({"redirect":cfg.base_url+"/auth/account/return"})
        return RedirectResponse(url,status_code=302,headers=NO_STORE)

    @router.get("/auth/account/return")
    async def account_return(request: Request, db=Depends(get_db), user=Depends(manager.require_user)):
        row = request.state.auth_session
        try:
            tokens = manager.decrypt(row.tokens)
            profile = await manager.provider.userinfo(tokens["access_token"])
            if profile.get("sub")!=row.sub:
                raise InvalidToken("Account identity changed")
            manager.upsert_user(db,profile)
        except (InvalidToken,ValueError,KeyError):
            manager.revoke_sessions(db,[row.id])
            db.commit()
            return RedirectResponse("/auth/login?next=/auth/sessions",status_code=302,headers=NO_STORE)
        except ProviderUnavailable:
            raise HTTPException(503,{"error":"账号资料暂时无法同步，请稍后重试"}) from None
        return RedirectResponse("/auth/sessions",status_code=302,headers=NO_STORE)

    return router
