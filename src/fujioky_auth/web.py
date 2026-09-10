import hashlib
import hmac
import html
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, quote

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError

from .manager import digest, now
from .provider import AccountDenied, InvalidToken, ProviderUnavailable
from .ui import CSS, JS

NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache", "Referrer-Policy": "no-referrer"}
PAGE_HEADERS = {**NO_STORE, "Referrer-Policy": "same-origin", "Cache-Control": "no-store, no-transform", "X-Frame-Options": "DENY", "Content-Security-Policy":
                "default-src 'none'; script-src 'self'; connect-src 'self'; img-src 'self' https: data:; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"}


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


def page(config, title, body, form_redirect=None):
    headers = dict(PAGE_HEADERS)
    if form_redirect:
        target = urlsplit(form_redirect)
        destination = target.scheme + "://" + quote(target.netloc, safe="[]:.-")
        headers["Content-Security-Policy"] = headers["Content-Security-Policy"].replace(
            "form-action 'self';", "form-action 'self' " + destination + ";")
    esc = html.escape
    styling = CSS
    if config.standalone:
        from .portal_style import STYLE
        styling += STYLE
        body = '<nav class="account-tabs" aria-label="账户导航"><a href="/auth/account">个人资料</a><a href="/security">账号与安全</a><a href="/sessions">登录设备</a><a href="/apps">已授权应用</a></nav>'+body
        active = {'个人资料':'/auth/account','账号与安全':'/security','登录设备':'/sessions','已授权应用':'/apps'}.get(title)
        if active: body = body.replace('href="'+active+'"', 'aria-current="page" href="'+active+'"', 1)
        body = body.replace('/auth/account?section=security','/security').replace('href="/auth/sessions"','href="/sessions"')
    if config.standalone:
        body += '<footer class="account-footer">FUJIOKY · OKY &amp; Company</footer>'
    return HTMLResponse('<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+esc(title)+' · '+esc(config.app_name.upper())+'</title><style>'+styling+'</style><header><a class="brand" href="/">'+esc(config.app_name.upper())+'</a><span data-lyra-auth></span></header><main><h1>'+esc(title)+'</h1>'+body+'</main><script src="/auth/ui.js" defer></script></html>', headers=headers)


def hidden(name, value):
    return f'<input type="hidden" name="{html.escape(name)}" value="{html.escape(str(value))}">'


def build_router(manager):
    cfg, get_db = manager.config, manager.get_db
    async def host(request: Request):
        if request.headers.get("host", "").lower() != urlsplit(cfg.base_url).netloc.lower():
            raise HTTPException(404)
    router = APIRouter(dependencies=[Depends(host)])

    def links():
        return [dict(x) for x in cfg.profile_links
                if isinstance(x, dict) and x.get("label") and x.get("href")
                and safe_next(x["href"]) == x["href"]
                and x["href"] != "/"]

    @router.get("/auth/ui.js")
    async def account_script():
        return Response(JS, media_type="application/javascript", headers={"Cache-Control":"public, max-age=300"})

    @router.get("/auth/whoami")
    async def whoami(user=Depends(manager.current_user)):
        return JSONResponse({"signedIn": bool(user), "admin": bool(user and user.is_admin),
                             "name": user.name if user else None, "email": user.email if user else None,
                             "avatar": user.avatar if user else "", "authReady": cfg.ready,
                             "accountBase": cfg.base_url if cfg.standalone else cfg.portal_url, "profileLinks": links() if user else []}, headers=NO_STORE)

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
    async def logout_page(request: Request, next: str = "/", db=Depends(get_db)):
        row = manager.session(request, db)
        if not row:
            response = RedirectResponse(safe_next(next), status_code=302, headers=NO_STORE)
            manager.clear_cookie(response)
            return response
        body = '<p>退出本应用，并结束当前统一登录会话。其他应用会在收到注销通知后退出。</p>'
        body += '<form method="post" action="/auth/logout">'+hidden("csrf",csrf(request,"logout:"+row.id))+hidden("next",safe_next(next))+'<button>确认退出</button></form>'
        destination = cfg.issuer
        if cfg.ready:
            try:
                destination = await manager.provider.endpoint("end_session_endpoint")
            except ProviderUnavailable:
                pass
        return page(cfg, "退出登录", body, form_redirect=destination)

    @router.post("/auth/logout")
    async def logout(request: Request, db=Depends(get_db)):
        data = await form(request)
        row = manager.session(request, db)
        if not row:
            response = RedirectResponse(safe_next(data.get("next")), status_code=303, headers=NO_STORE)
            manager.clear_cookie(response)
            return response
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
        async def delivered():
            relay = getattr(request.app.state, "relay_logout", None)
            if relay:
                try:
                    await relay(data["logout_token"])
                except ProviderUnavailable:
                    return JSONResponse({"error":"temporarily_unavailable"},status_code=503,headers=NO_STORE)
            return Response(status_code=200,headers=NO_STORE)
        if db.get(manager.LogoutEvent,ident):
            return await delivered()
        db.add(manager.LogoutEvent(id=ident,expires=now()+600))
        try:
            db.flush()
        except IntegrityError:
            db.rollback()
            return await delivered()
        query = select(manager.Session.id).where(manager.Session.issuer==cfg.issuer,
                            manager.Session.created <= claims["iat"], manager.Session.revoked.is_(False))
        if claims.get("sid"):
            query = query.where(manager.Session.sid==claims["sid"])
        if claims.get("sub"):
            query = query.where(manager.Session.sub==claims["sub"])
        manager.revoke_sessions(db,list(db.scalars(query)))
        db.commit()
        return await delivered()

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

    def profile_page(request, user, values, message="", status=200):
        esc = html.escape
        name, avatar = str(values.get("name") or ""), str(values.get("avatar") or "")
        picture = ('<img class="profile-avatar" referrerpolicy="no-referrer" src="'+esc(avatar, quote=True)+'" alt="头像">') if avatar.startswith("https://") else '<span class="profile-avatar">'+esc((name or "U")[:1].upper())+'</span>'
        body = '<div class="profile-intro">'+picture+'<div><h2>'+esc(name or "个人账户")+'</h2><p class="muted">'+esc(user.email)+'</p></div></div>'
        if message:
            body += '<p role="status">'+esc(message)+'</p>'
        body += '<form method="post" action="/auth/account">'+hidden("csrf",csrf(request,"profile:"+str(user.id)))+"""
<label class="profile-field">显示姓名<input name="name" autocomplete="name" maxlength="120" required value="""+'"'+esc(name,quote=True)+'"'+""" ></label>
<label class="profile-field">头像图片地址<input name="avatar" type="url" maxlength="600" placeholder="https://…" value="""+'"'+esc(avatar,quote=True)+'"'+""" ></label>
<p class="muted">使用 HTTPS 图片地址，留空可移除头像。资料会同步到你的 FUJIOKY 账户。</p>
<button type="submit">保存资料</button></form>
<p><a href="/auth/account?section=security">账号与安全 ↗</a> · <a href="/auth/sessions">登录设备</a></p>"""
        response = page(cfg,"个人资料",body)
        response.status_code = status
        return response

    async def read_account(request, db):
        row = request.state.auth_session
        token = manager.decrypt(row.tokens)["access_token"]
        values = await manager.provider.account(token)
        if values.get("id") != row.sub:
            raise InvalidToken("Account identity changed")
        return token, values

    def account_login(request, db):
        row = request.state.auth_session
        manager.revoke_sessions(db,[row.id])
        db.commit()
        response = RedirectResponse("/auth/login?next=/auth/account",status_code=303,headers=NO_STORE)
        manager.clear_cookie(response)
        return response

    @router.get("/auth/account")
    async def account(request: Request, section: str = "profile", saved: bool = False,
                      db=Depends(get_db), user=Depends(manager.current_user)):
        if cfg.portal_url:
            destination = "/security" if section != "profile" else "/auth/account"
            return RedirectResponse(cfg.portal_url.rstrip("/")+destination,status_code=302,headers=NO_STORE)
        if cfg.standalone and section == "security":
            return RedirectResponse("/security",status_code=302,headers=NO_STORE)
        if section not in ("profile","security","email","password"):
            raise HTTPException(400)
        if not user:
            return RedirectResponse("/auth/login?"+urlencode({"next":"/auth/account?section="+section}),status_code=302,headers=NO_STORE)
        if section != "profile":
            if not cfg.account_center:
                raise HTTPException(503,{"error":"账号中心尚未配置"})
            url = cfg.account_center.rstrip("/")+"/"+section+"?"+urlencode({"redirect":cfg.base_url+"/auth/account/return"})
            return RedirectResponse(url,status_code=302,headers=NO_STORE)
        try:
            _, values = await read_account(request,db)
        except (InvalidToken,KeyError):
            return account_login(request,db)
        except (AccountDenied,ProviderUnavailable):
            return page(cfg,"个人资料",'<p>账户资料暂时无法读取，请稍后重试。</p><p><a href="/auth/account">重新加载</a></p>')
        if "name" in values:
            user.name = str(values.get("name") or "")[:120]
        if "avatar" in values:
            user.avatar = str(values.get("avatar") or "")[:600]
        db.commit()
        return profile_page(request,user,values,"资料已保存。" if saved else "")

    @router.post("/auth/account")
    async def save_account(request: Request, db=Depends(get_db), user=Depends(manager.require_user)):
        data = await form(request)
        check_csrf(request,"profile:"+str(user.id),data.get("csrf"),cfg.base_url)
        name, avatar = data.get("name", "").strip(), data.get("avatar", "").strip()
        valid_avatar = not avatar
        try:
            parsed = urlsplit(avatar)
            valid_avatar = valid_avatar or (parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password)
        except ValueError:
            pass
        values = {"name":name,"avatar":avatar}
        if (not name or len(name)>120 or len(avatar)>600 or not valid_avatar
                or any(ord(c)<32 for c in name+avatar)):
            return profile_page(request,user,values,"请填写姓名和有效的 HTTPS 图片地址。",400)
        try:
            token, _ = await read_account(request,db)
            await manager.provider.account(token,{"name":name,"avatar":avatar or None})
            # Re-read authoritative data instead of treating a submitted form as saved.
            _, updated = await read_account(request,db)
        except (InvalidToken,KeyError):
            return account_login(request,db)
        except AccountDenied:
            return profile_page(request,user,values,"暂时无法保存，请确认账户中心的姓名、头像权限为可编辑。",403)
        except ProviderUnavailable:
            return profile_page(request,user,values,"暂时无法确认保存结果，请重新加载资料后重试。",503)
        user.name = str(updated.get("name") or "")[:120]
        user.avatar = str(updated.get("avatar") or "")[:600]
        db.commit()
        return RedirectResponse("/auth/account?saved=1",status_code=303,headers=NO_STORE)

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
        return RedirectResponse("/",status_code=302,headers=NO_STORE)

    return router
