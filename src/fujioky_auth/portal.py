"""Standalone account center. Uses only end-user Account API credentials."""
import asyncio
import httpx
import html
import os
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import Boolean, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from .config import AuthConfig
from .manager import AuthManager, now, upsert_standard_user
from .provider import AccountDenied, InvalidToken, ProviderUnavailable
from .web import NO_STORE, check_csrf, csrf, form, hidden, page


def create_app(env=None):
    env = os.environ if env is None else env
    config = AuthConfig(app_name="FUJIOKY", base_url=env.get("BASE_URL", "http://localhost:8080").rstrip('/'),
        issuer=env.get("OIDC_ISSUER", ""),client_id=env.get("OIDC_CLIENT_ID", ""),
        client_secret=env.get("OIDC_CLIENT_SECRET", ""),session_secret=env.get("SESSION_SECRET", ""),
        cookie_name="fujioky_account",scopes="openid profile email identities urn:logto:scope:sessions offline_access",
        account_center=env.get("OIDC_ISSUER", "").removesuffix('/oidc')+'/account',standalone=True)
    if len(config.session_secret)<32: raise ValueError("SESSION_SECRET must contain at least 32 characters")
    class Base(DeclarativeBase): pass
    class User(Base):
        __tablename__="users"
        id: Mapped[int] = mapped_column(Integer,primary_key=True)
        sub: Mapped[str] = mapped_column(String,unique=True)
        email: Mapped[str] = mapped_column(String,unique=True)
        name: Mapped[str] = mapped_column(String,default="")
        avatar: Mapped[str] = mapped_column(String,default="")
        is_admin: Mapped[bool] = mapped_column(Boolean,default=False)
    class Verification(Base):
        __tablename__="account_verifications"
        id: Mapped[str] = mapped_column(String,primary_key=True)
        value: Mapped[str] = mapped_column(Text,default="")
        expires: Mapped[int] = mapped_column(Integer,default=0)
        sent: Mapped[int] = mapped_column(Integer,default=0)
        verified: Mapped[bool] = mapped_column(Boolean,default=False)
    engine=create_engine(env.get('DATABASE_URL','sqlite:///account.db'),connect_args={'check_same_thread':False})
    factory=sessionmaker(engine,expire_on_commit=False)
    def get_db():
        with factory() as db: yield db
    manager=AuthManager(config,base=Base,get_db=get_db,user_model=User,
        upsert_user=lambda db,c:upsert_standard_user(db,User,c,lambda _:False))
    Base.metadata.create_all(engine)
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    from pathlib import Path
    from fastapi.staticfiles import StaticFiles
    app.mount("/brand", StaticFiles(directory=Path(__file__).with_name("assets")), name="brand")
    app.state.manager=manager
    app.state.sessions=factory
    targets=[x.strip() for x in env.get('LOGOUT_TARGETS','').split(',') if x.strip()]
    from urllib.parse import urlsplit
    if any(urlsplit(x).scheme != 'https' or urlsplit(x).username or urlsplit(x).query or urlsplit(x).fragment or x == config.base_url+'/auth/backchannel-logout' for x in targets):
        raise ValueError('Logout targets must be fixed HTTPS application endpoints')
    async def relay_logout(logout_token):
        async with httpx.AsyncClient(timeout=10,follow_redirects=False) as client:
            results=await asyncio.gather(*(client.post(url,data={'logout_token':logout_token}) for url in targets),return_exceptions=True)
        if any(isinstance(r,Exception) or r.status_code != 200 for r in results):
            raise ProviderUnavailable()
    app.state.relay_logout=relay_logout
    app.add_middleware(SessionMiddleware,secret_key=config.session_secret,session_cookie='account_oidc',
        https_only=config.base_url.startswith('https'),same_site='lax',max_age=600)
    origins=[x.strip() for x in env.get('CORS_ORIGINS','').split(',') if x.strip()]
    if '*' in origins: raise ValueError('Explicit CORS origins required')
    app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=True,allow_methods=['GET'],allow_headers=[])
    esc=lambda x:html.escape(str(x or ''),quote=True)
    def back(path):return RedirectResponse(path,status_code=303,headers=NO_STORE)
    async def token(request,db):
        row=request.state.auth_session
        return manager.decrypt(row.tokens)['access_token']
    def verification(request,db):
        row=db.get(Verification,request.state.auth_session.id)
        return manager.decrypt(row.value) if row and row.verified and row.expires>now() else None
    destinations=('/sessions','/apps','/security/change/email','/security/change/password')
    async def verify_page(request,destination,error='',stage=None):
        row=request.state.auth_session
        account=await manager.provider.account(manager.decrypt(row.tokens)['access_token'])
        has_password=account.get('hasPassword', False)
        has_email=bool(account.get('primaryEmail'))
        stage=stage or request.query_params.get('method','email')
        if stage not in ('email','password','code'):stage='email'
        if not has_email and stage=='email' and has_password:stage='password'
        suffix=urlencode({'next':destination})
        email=account.get('primaryEmail') or getattr(getattr(request.state,'user',None),'email','')
        body='<section class="flow"><a class="back" href="/security">← 返回账户安全</a><div class="step">身份验证</div>'
        body+='<h2>'+('验证您的密码' if stage=='password' else '输入验证码' if stage=='code' else '验证您的邮箱')+'</h2>'
        body+='<p class="description">'+('请输入当前密码，以确认是您本人。' if stage=='password' else '验证码已发送至 '+esc(email)+'。请在有效期内输入，完成后继续。' if stage=='code' else '为保护账户安全，请确认是您本人。我们会向您的邮箱发送验证码。')+'</p>'
        if error:body+='<p class="feedback" role="status">'+esc(error)+'</p>'
        method={'email':'send','password':'password','code':'code'}[stage]
        body+='<form method="post" action="/verify">'+hidden('csrf',csrf(request,'verify'))+hidden('next',destination)+hidden('method',method)
        if stage=='password':body+='<label class="profile-field"><span class="field-label">当前密码</span><input name="password" type="password" autocomplete="current-password" required autofocus></label>'
        elif stage=='code':body+='<label class="profile-field"><span class="field-label">邮箱验证码</span><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="12" required autofocus></label>'
        else:body+='<label class="profile-field"><span class="field-label">邮箱地址</span><input type="email" value="'+esc(email)+'" readonly></label>'
        body+='<button type="submit">'+('发送验证码' if stage=='email' else '验证并继续')+'</button></form>'
        alternate='email' if stage=='password' else 'password'
        if (alternate=='email' and has_email) or (alternate=='password' and has_password):
            body+='<p class="alternative"><a href="/verify?'+suffix+'&method='+alternate+'">'+('使用邮箱验证码' if alternate=='email' else '使用密码验证')+'</a></p>'
        if stage=='code':body+='<p class="alternative"><a href="/verify?'+suffix+'&method=email">没有收到？重新发送</a></p>'
        return page(config,'验证身份',body+'</section>')
    @app.get('/verify')
    async def verification_start(request:Request,next:str='/sessions',user=Depends(manager.require_user)):
        if next not in destinations:raise HTTPException(400)
        return await verify_page(request,next)
    @app.get('/healthz')
    def health():return {'ok':True,'configured':config.ready}
    @app.get('/')
    def root():return back('/auth/account')
    @app.get('/security')
    async def security(request:Request,db=Depends(get_db),user=Depends(manager.current_user)):
        if not user:return back('/auth/login?next=/security')
        account=await manager.provider.account(await token(request,db))
        body='<p class="muted">管理你的登录方式。修改时会要求验证身份。</p>'
        for label,value,action in [('电子邮箱',account.get('primaryEmail') or user.email,'email'),('密码','已设置' if account.get('hasPassword') else '设置或更改密码','password')]:
            body+='<section class="account-card account-row"><div><h2>'+label+'</h2><p>'+esc(value)+'</p></div><a href="/security/change/'+action+'">管理 →</a></section>'
        return page(config,'账号与安全',body)
    def edit_page(request,action,error='',pending=None):
        title='设置新密码' if action=='password' else '验证新邮箱' if pending else '更改邮箱'
        body='<section class="flow"><a class="back" href="/security">← 返回账户安全</a><div class="step">'+('设置密码' if action=='password' else '更新联系方式')+'</div><h2>'+title+'</h2>'
        body+='<p class="description">'+('使用独立且难以猜测的密码来保护您的账户。' if action=='password' else '请输入发送至 '+esc(pending['email'])+' 的验证码。' if pending else '验证新的邮箱后，它将成为您的登录和联系邮箱。')+'</p>'
        if error:body+='<p class="feedback" role="status">'+esc(error)+'</p>'
        body+='<form method="post" action="/security/change/'+action+'">'+hidden('csrf',csrf(request,'change:'+action))
        if action=='password':
            body+='<label class="profile-field"><span class="field-label">新密码</span><input type="password" name="password" autocomplete="new-password" required maxlength="1024"></label><label class="profile-field"><span class="field-label">确认新密码</span><input type="password" name="confirmation" autocomplete="new-password" required maxlength="1024"></label>'
        elif pending:
            body+=hidden('step','confirm')+'<label class="profile-field"><span class="field-label">验证码</span><input name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="12" autofocus></label>'
        else:body+=hidden('step','send')+'<label class="profile-field"><span class="field-label">新邮箱地址</span><input name="email" type="email" autocomplete="email" required maxlength="254" autofocus></label>'
        body+='<button type="submit">'+('保存新密码' if action=='password' else '确认更改' if pending else '发送验证码')+'</button></form>'
        if pending:body+='<p class="alternative"><a href="/security/change/email">更换邮箱或重新发送</a></p>'
        return page(config,title,body+'</section>')
    @app.get('/security/change/{action}')
    async def change(action:str,request:Request,db=Depends(get_db),user=Depends(manager.current_user)):
        if action not in ('email','password'):raise HTTPException(404)
        if not user:return back('/auth/login?next=/security/change/'+action)
        if not verification(request,db):return await verify_page(request,'/security/change/'+action)
        return edit_page(request,action)
    @app.post('/security/change/{action}')
    async def save_change(action:str,request:Request,db=Depends(get_db),user=Depends(manager.require_user)):
        if action not in ('email','password'):raise HTTPException(404)
        data=await form(request);check_csrf(request,'change:'+action,data.get('csrf'),config.base_url)
        verified=verification(request,db)
        if not verified:return await verify_page(request,'/security/change/'+action,'验证已过期，请重新确认身份。')
        access=await token(request,db)
        pending=None
        binding_id='binding:'+request.state.auth_session.id
        row=db.get(Verification,binding_id)
        try:
            if action=='password':
                password=data.get('password','')
                if not password or len(password)>1024 or password!=data.get('confirmation'):
                    return edit_page(request,action,'两次输入的密码不一致，请重新填写。')
                await manager.provider.account_request(access,'POST','/api/my-account/password',{'password':password},verified['id'])
            elif data.get('step')=='send':
                email=data.get('email','').strip()
                if len(email)>254 or '@' not in email or any(c.isspace() for c in email):
                    return edit_page(request,action,'请填写有效的邮箱地址。')
                if row and row.sent>now()-60:return edit_page(request,action,'请稍等一分钟再发送。')
                result=await manager.provider.account_request(access,'POST','/api/verifications/verification-code',{'identifier':{'type':'email','value':email}})
                pending={'id':result['verificationRecordId'],'email':email}
                row=row or Verification(id=binding_id)
                row.value=manager.encrypt(pending);row.expires=now()+600;row.sent=now();db.add(row);db.commit()
                return edit_page(request,action,pending=pending)
            elif data.get('step')=='confirm':
                if not row or row.expires<=now():return edit_page(request,action,'验证码已过期，请重新发送。')
                pending=manager.decrypt(row.value)
                await manager.provider.account_request(access,'POST','/api/verifications/verification-code/verify',{'identifier':{'type':'email','value':pending['email']},'verificationId':pending['id'],'code':data.get('code','')})
                await manager.provider.account_request(access,'POST','/api/my-account/primary-email',{'email':pending['email'],'newIdentifierVerificationRecordId':pending['id']},verified['id'])
                db.delete(row)
            else:raise HTTPException(400)
            # A sensitive update consumes our short-lived local verification.
            verified_row=db.get(Verification,request.state.auth_session.id)
            if verified_row:db.delete(verified_row)
            db.commit()
            return page(config,'更新成功','<section class="flow"><div class="step">已完成</div><h2>'+('密码已更新' if action=='password' else '邮箱已更新')+'</h2><p class="description">您的更改已保存。</p><a class="back" href="/security">返回账户安全 →</a></section>')
        except AccountDenied:return edit_page(request,action,'操作未完成。请检查验证码、邮箱是否可用，或密码是否符合账户密码规则。',pending)
        except InvalidToken:return await verify_page(request,'/security/change/'+action,'验证已失效，请重新确认身份。')
    @app.post('/verify')
    async def verify(request:Request,db=Depends(get_db),user=Depends(manager.require_user)):
        data=await form(request);check_csrf(request,'verify',data.get('csrf'),config.base_url)
        destination=data.get('next') if data.get('next') in destinations else '/sessions'
        sid=request.state.auth_session.id
        row=db.get(Verification,sid)
        access=await token(request,db)
        method=data.get('method')
        try:
            if method=='password':
                password=data.get('password','')
                if not password or len(password)>1024:raise AccountDenied()
                result=await manager.provider.account_request(access,'POST','/api/verifications/password',{'password':password})
                record=result['verificationRecordId']
            elif method=='send':
                if row and row.sent>now()-60:return await verify_page(request,destination,'请稍等一分钟再发送。')
                # The recipient comes from Logto, never from the browser form.
                account=await manager.provider.account(access)
                email=account.get('primaryEmail')
                if not email:raise AccountDenied()
                result=await manager.provider.account_request(access,'POST','/api/verifications/verification-code',{'identifier':{'type':'email','value':email}})
                row=row or Verification(id=sid)
                row.value=manager.encrypt({'id':result['verificationRecordId'],'email':email})
                row.expires=now()+600;row.sent=now();row.verified=False;db.add(row);db.commit()
                return await verify_page(request,destination,stage='code')
            elif method=='code':
                if not row or row.verified or row.expires<=now():raise AccountDenied()
                pending=manager.decrypt(row.value)
                await manager.provider.account_request(access,'POST','/api/verifications/verification-code/verify',
                    {'identifier':{'type':'email','value':pending['email']},'verificationId':pending['id'],'code':data.get('code','')})
                record=pending['id']
            else:raise AccountDenied()
            row=row or Verification(id=sid)
            row.value=manager.encrypt({'id':record});row.expires=now()+540;row.verified=True
            db.add(row);db.commit()
            return back(destination)
        except (AccountDenied,InvalidToken,KeyError):return await verify_page(request,destination,'验证未通过，请检查后重试。',stage='code' if method=='code' else 'password' if method=='password' else 'email')
    def items(result,key):
        if not isinstance(result,dict) or not isinstance(result.get(key),list):raise ProviderUnavailable()
        return result[key]
    @app.get('/sessions')
    @app.get('/apps')
    async def listing(request:Request,db=Depends(get_db),user=Depends(manager.current_user)):
        section=request.url.path.strip('/')
        if not user:return back('/auth/login?next=/'+section)
        verified=verification(request,db)
        if not verified:return await verify_page(request,'/'+section)
        key='sessions' if section=='sessions' else 'grants'
        try:
            result=await manager.provider.account_request(await token(request,db),'GET','/api/my-account/'+key,verification=verified['id'])
        except (InvalidToken,AccountDenied):return await verify_page(request,'/'+section,'请重新验证身份，或重新登录以更新账户权限。')
        body=''
        for item in items(result,key):
            payload=item.get('payload',{})
            ident=payload.get('uid') if key=='sessions' else item.get('id')
            if not isinstance(ident,str):continue
            title=(item.get('application') or {}).get('name','应用') if key=='grants' else ('当前登录' if item.get('isCurrent') else '登录设备')
            created=payload.get('iat')
            date=datetime.fromtimestamp(created,timezone.utc).strftime('%Y-%m-%d %H:%M UTC') if isinstance(created,(int,float)) and 0<created<4102444800 else ''
            body+='<article><h2>'+esc(title)+'</h2><p class="muted">'+esc(date)+'</p><form method="post" action="/'+section+'/revoke">'+hidden('csrf',csrf(request,'revoke:'+section+':'+ident))+hidden('id',ident)+'<button>撤销'+('授权' if key=='grants' else '登录')+'</button></form></article>'
        if section=='apps':
            if env.get('BIDE_ACCOUNT_API'):
                result=await mcp_request(await token(request,db),'GET')
                for grant in items(result,'grants'):
                    ident=grant['id']
                    body+='<article><h2>'+esc(grant['name'])+'</h2><p class="muted">BIDE · AI 客户端</p><form method="post" action="/mcp-apps/revoke">'+hidden('csrf',csrf(request,'mcp:'+ident))+hidden('id',ident)+'<button>撤销授权</button></form></article>' 
        return page(config,'登录设备' if section=='sessions' else '已授权应用',body or '<p>暂无记录。</p>')
    async def mcp_request(access,method,ident=''):
        url=env.get('BIDE_ACCOUNT_API','').rstrip('/')
        if not url or urlsplit(url).scheme != 'https': raise ProviderUnavailable()
        if ident: url+='/'+quote(ident,safe='')
        try:
            async with httpx.AsyncClient(timeout=15,follow_redirects=False) as client:
                result=await client.request(method,url,headers={'Authorization':'Bearer '+access})
            result.raise_for_status()
            return result.json()
        except (httpx.HTTPError,ValueError):raise ProviderUnavailable() from None
    @app.post('/mcp-apps/revoke')
    async def revoke_mcp(request:Request,db=Depends(get_db),user=Depends(manager.require_user)):
        data=await form(request);ident=data.get('id','')
        check_csrf(request,'mcp:'+ident,data.get('csrf'),config.base_url)
        if not verification(request,db):return await verify_page(request,'/apps')
        if not ident or len(ident)>200:raise HTTPException(400)
        await mcp_request(await token(request,db),'DELETE',ident)
        return back('/apps')
    @app.post('/{section}/revoke')
    async def revoke(section:str,request:Request,db=Depends(get_db),user=Depends(manager.require_user)):
        if section not in ('sessions','apps'):raise HTTPException(404)
        data=await form(request);ident=data.get('id','')
        check_csrf(request,'revoke:'+section+':'+ident,data.get('csrf'),config.base_url)
        verified=verification(request,db)
        if not verified:return await verify_page(request,'/'+section)
        if not ident or len(ident)>200:raise HTTPException(400)
        key='sessions' if section=='sessions' else 'grants'
        path='/api/my-account/'+key+'/'+quote(ident,safe='')
        if section=='sessions':path+='?revokeGrantsTarget=all'
        await manager.provider.account_request(await token(request,db),'DELETE',path,verification=verified['id'])
        return back('/'+section)
    @app.exception_handler(ProviderUnavailable)
    async def unavailable(request,exc):
        response=page(config,'暂时无法加载','<p>服务暂时不可用，请稍后重试。</p>');response.status_code=503;return response
    @app.exception_handler(AccountDenied)
    async def denied(request,exc):
        response=page(config,'操作未完成','<p>权限不足或验证已过期，请重新打开页面。</p>');response.status_code=403;return response
    @app.exception_handler(InvalidToken)
    async def invalid(request,exc):return back('/auth/login')
    app.include_router(manager.router)
    return app
