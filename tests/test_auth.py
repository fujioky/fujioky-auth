import asyncio
import json
import re
import time
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest
from authlib.jose import JsonWebKey, jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import Boolean, Integer, String, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

from fujioky_auth import AuthConfig, AuthManager, upsert_standard_user
from fujioky_auth.manager import now
from fujioky_auth.provider import InvalidToken, ProviderUnavailable

ISSUER = "https://auth.test/oidc"
EVENT = "http://schemas.openid.net/event/backchannel-logout"
private = rsa.generate_private_key(public_exponent=65537,key_size=2048)
PRIV = private.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
JWK = JsonWebKey.import_key(private.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)).as_dict()
JWK.update(kid="test-key", use="sig", alg="RS256")


def signed(**over):
    payload = {"iss":ISSUER,"aud":"bide-client","iat":now(),"exp":now()+120,"jti":"logout-1",
               "sid":"sid-one","events":{EVENT:{}}}
    payload.update(over)
    payload = {k:v for k,v in payload.items() if v is not None}
    return jwt.encode({"alg":"RS256","kid":"test-key"},payload,PRIV).decode()


def build(path, name="bide", secret="test-secret", revoke=None):
    class Base(DeclarativeBase): pass
    class User(Base):
        __tablename__="users"
        id: Mapped[int] = mapped_column(Integer,primary_key=True)
        sub: Mapped[str | None] = mapped_column(String,unique=True,nullable=True)
        email: Mapped[str] = mapped_column(String,unique=True)
        name: Mapped[str] = mapped_column(String,default="")
        avatar: Mapped[str] = mapped_column(String,default="")
        is_admin: Mapped[bool] = mapped_column(Boolean,default=False)
        # The adapter only writes last_login; this harness need not persist it.
    config=AuthConfig(app_name=name,base_url=f"https://{name}.test",issuer=ISSUER,client_id=name+"-client",
                      client_secret="client-secret",session_secret=secret,cookie_name=name+"_session",
                      dev_login=True,account_center="https://auth.test/account")
    engine=create_engine("sqlite:///"+str(path),connect_args={"check_same_thread":False,"timeout":30})
    sessions=sessionmaker(engine,expire_on_commit=False)
    def get_db():
        with sessions() as db: yield db
    def upsert(db,claims):
        return upsert_standard_user(db,User,claims,lambda c: c.get("email_verified") is True and c.get("email")=="admin@test.com")
    manager=AuthManager(config,base=Base,get_db=get_db,user_model=User,upsert_user=upsert,on_revoke=revoke)
    Base.metadata.create_all(engine)
    app=FastAPI()
    app.add_middleware(SessionMiddleware,secret_key=secret,https_only=True)
    app.include_router(manager.router)
    async def keys(force=False): return {"keys":[JWK]}
    manager.provider.jwks=keys
    return manager,sessions,app


@pytest.fixture
def env(tmp_path):
    manager,db,app=build(tmp_path/"auth.db")
    with TestClient(app,base_url=manager.config.base_url) as client:
        yield manager,db,client


def seed(env,email="alice@test.com",sid="sid-one",expires=None,tokens=True):
    manager,sessions,client=env
    claims={"sub":email,"email":email,"email_verified":True,"sid":sid,"name":"Alice"}
    token={"access_token":"private-access", "refresh_token":"private-refresh", "id_token":"private-id-token", "expires_in":3600} if tokens else {}
    with sessions() as db:
        user,_=manager.upsert_user(db,claims)
        raw=manager.create_session(db,user,claims,token,"Test Browser")
        row=db.get(manager.Session,manager.session_id(raw))
        if expires is not None: row.token_expires=expires
        db.commit()
    client.cookies.set(manager.config.cookie_name,raw,domain=urlsplit(manager.config.base_url).hostname,path="/")
    return raw


def fields(r):
    return dict(re.findall(r'<input type="hidden" name="([^"]+)" value="([^"]*)">',r.text))


def test_server_cookie_encrypted_tokens_and_restart(env,tmp_path):
    manager,sessions,client=env
    raw=seed(env)
    assert client.get("/auth/whoami").json()["signedIn"] is True
    with sessions() as db:
        row=db.get(manager.Session,manager.session_id(raw))
        assert raw not in row.id and "private" not in row.tokens
        assert manager.decrypt(row.tokens)["refresh_token"]=="private-refresh"
    second,_,app=build(tmp_path/"auth.db")
    with TestClient(app,base_url=second.config.base_url) as c:
        c.cookies.set(second.config.cookie_name,raw)
        assert c.get("/auth/whoami").json()["signedIn"] is True
    rotated,_,app=build(tmp_path/"auth.db",secret="rotated")
    with TestClient(app,base_url=rotated.config.base_url) as c:
        c.cookies.set(rotated.config.cookie_name,raw)
        assert c.get("/auth/whoami").json()["signedIn"] is False


def test_old_signed_cookie_rejected(env):
    manager,_,client=env
    from itsdangerous import TimestampSigner
    client.cookies.set(manager.config.cookie_name,TimestampSigner("test-secret",salt="session-v1").sign("1").decode())
    assert client.get("/auth/whoami").json()["signedIn"] is False


def test_refresh_rotation_and_profile(env):
    manager,sessions,client=env
    raw=seed(env,expires=0)
    seen=[]
    async def refresh(value):
        seen.append(value)
        return {"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"token_type":"Bearer"}
    async def profile(value):
        assert value=="new-access"
        return {"sub":"alice@test.com","email":"alice@test.com","email_verified":True,"name":"Updated"}
    manager.provider.refresh=refresh
    manager.provider.userinfo=profile
    assert client.get("/auth/whoami").json()["name"]=="Updated"
    assert client.get("/auth/whoami").status_code==200 and seen==["private-refresh"]
    with sessions() as db:
        row=db.get(manager.Session,manager.session_id(raw))
        assert manager.decrypt(row.tokens)["refresh_token"]=="new-refresh"
        assert row.refresh_until==0


@pytest.mark.parametrize("failure",[InvalidToken,ProviderUnavailable])
def test_refresh_failure_policy(env,failure):
    manager,sessions,client=env
    raw=seed(env,expires=0)
    async def refresh(_): raise failure("test")
    manager.provider.refresh=refresh
    r=client.get("/auth/whoami")
    if failure==ProviderUnavailable: assert r.status_code==503
    else: assert r.json()["signedIn"] is False
    with sessions() as db:
        row=db.get(manager.Session,manager.session_id(raw))
        assert row.revoked==(failure==InvalidToken) and row.refresh_until==0


def test_refresh_no_rotation_keeps_old_and_no_userinfo_network_failure_loss(env):
    manager,sessions,client=env
    raw=seed(env,expires=0)
    async def refresh(_): return {"access_token":"new","expires_in":3600}
    async def profile(_): raise ProviderUnavailable("temporary")
    manager.provider.refresh,manager.provider.userinfo=refresh,profile
    assert client.get("/auth/whoami").json()["signedIn"] is True
    with sessions() as db:
        assert manager.decrypt(db.get(manager.Session,manager.session_id(raw)).tokens)["refresh_token"]=="private-refresh"


def test_subject_mismatch_revokes(env):
    manager,sessions,client=env
    seed(env,expires=0)
    async def refresh(_): return {"access_token":"new","expires_in":3600}
    async def profile(_): return {"sub":"another-user","email":"another@test.com","email_verified":True}
    manager.provider.refresh,manager.provider.userinfo=refresh,profile
    assert client.get("/auth/whoami").json()["signedIn"] is False


def test_concurrent_refresh_only_once(env):
    from concurrent.futures import ThreadPoolExecutor
    manager,sessions,client=env
    raw=seed(env,expires=0)
    calls=[]
    async def refresh(_):
        calls.append(1)
        await asyncio.sleep(.1)
        return {"access_token":"new","refresh_token":"rotated","expires_in":3600}
    async def profile(_): return {"sub":"alice@test.com","email":"alice@test.com","email_verified":True}
    manager.provider.refresh,manager.provider.userinfo=refresh,profile
    def get(_):
        with TestClient(client.app,base_url=manager.config.base_url) as other:
            other.cookies.set(manager.config.cookie_name,raw)
            return other.get("/auth/whoami")
    with ThreadPoolExecutor(max_workers=2) as pool: results=list(pool.map(get,range(2)))
    assert all(r.status_code==200 and r.json()["signedIn"] for r in results)
    assert len(calls)==1


@pytest.mark.parametrize("over",[
    {"iss":"https://other.test"},{"aud":"note-client"},{"iat":now()-600},{"iat":now()+100},
    {"exp":now()-100},{"nonce":"forbidden"},{"events":{}},{"events":{EVENT:"bad"}},
    {"sid":None,"sub":None},{"jti":None},{"sid":123},{"iat":True},
])
def test_invalid_backchannel_does_not_logout(env,over):
    _,_,client=env
    seed(env)
    r=client.post("/auth/backchannel-logout",data={"logout_token":signed(**over)})
    assert r.status_code==400,r.text
    assert client.get("/auth/whoami").json()["signedIn"] is True


def test_backchannel_sid_and_replay(env):
    manager,sessions,client=env
    first=seed(env)
    other=seed(env,sid="sid-two")
    event=signed()
    assert client.post("/auth/backchannel-logout",data={"logout_token":event}).status_code==200
    assert client.get("/auth/whoami").json()["signedIn"] is True
    with sessions() as db:
        assert db.get(manager.Session,manager.session_id(first)).revoked
        assert not db.get(manager.Session,manager.session_id(other)).revoked
    assert client.post("/auth/backchannel-logout",data={"logout_token":event}).status_code==200


def test_subject_logout_isolated_and_hook(env):
    manager,sessions,client=env
    calls=[]
    manager.on_revoke=lambda db,ids:calls.extend(ids)
    one=seed(env)
    two=seed(env,sid="sid-two")
    other=seed(env,email="other@test.com",sid="other")
    r=client.post("/auth/backchannel-logout",data={"logout_token":signed(sid=None,sub="alice@test.com")})
    assert r.status_code==200
    assert set(calls)=={manager.session_id(one),manager.session_id(two)}
    assert client.get("/auth/whoami").json()["email"]=="other@test.com"


def test_logout_form_csrf_provider_and_state(env):
    manager,sessions,client=env
    raw=seed(env)
    async def endpoint(key):
        assert key=="end_session_endpoint"
        return ISSUER+"/session/end"
    seen=[]
    async def revoke(token): seen.append(token)
    manager.provider.endpoint,manager.provider.revoke=endpoint,revoke
    r=client.get("/auth/logout?next=/dashboard")
    assert r.status_code==200 and client.get("/auth/whoami").json()["signedIn"]
    assert "form-action 'self' https://auth.test;" in r.headers['content-security-policy']
    data=fields(r)
    assert client.post("/auth/logout",data={**data,"csrf":"bad"}).status_code==403
    r=client.post("/auth/logout",data=data,follow_redirects=False)
    assert r.status_code==303 and r.headers["location"].startswith(ISSUER+"/session/end?")
    query=parse_qs(urlsplit(r.headers["location"]).query)
    assert query["post_logout_redirect_uri"]==[manager.config.base_url+"/auth/logged-out"]
    assert seen==["private-refresh"]
    client.cookies.set(manager.config.cookie_name,raw)
    assert not client.get("/auth/whoami").json()["signedIn"]
    # A valid state is required; successful redirect preserves only the safe local next.
    response=client.get("/auth/logged-out",params={"state":query["state"][0]},follow_redirects=False)
    assert response.headers["location"]=="/dashboard"
    assert client.get("/auth/logged-out",params={"state":query["state"][0]}).status_code==400


def test_logout_provider_outage_still_revokes_local(env):
    manager,_,client=env
    seed(env)
    async def unavailable(*_): raise ProviderUnavailable()
    manager.provider.endpoint=unavailable
    manager.provider.revoke=unavailable
    response=client.post("/auth/logout",data=fields(client.get("/auth/logout")),follow_redirects=False)
    assert response.status_code==303
    assert "local_only" in response.headers["location"]
    assert not client.get("/auth/whoami").json()["signedIn"]


def test_session_management_and_account_center(env):
    manager,sessions,client=env
    first=seed(env,tokens=False)
    second=seed(env,sid="two",tokens=False)
    page=client.get("/auth/sessions")
    assert "当前设备" in page.text and "其他设备" in page.text
    # Each form owns a CSRF token; use the first complete form.
    forms=re.findall(r'<form.*?</form>',page.text)
    class Html: text=forms[0]
    payload=fields(Html())
    assert client.post("/auth/sessions/revoke",data={**payload,"csrf":"bad"}).status_code==403
    assert client.post("/auth/sessions/revoke",data=payload,follow_redirects=False).status_code==303
    seed(env)
    r=client.get("/auth/account?section=security",follow_redirects=False)
    assert r.headers["location"].startswith("https://auth.test/account/security?")
    assert parse_qs(urlsplit(r.headers["location"]).query)["redirect"]==[manager.config.base_url+"/auth/account/return"]
    assert client.get("/auth/account?section=../evil").status_code==400


def test_account_updates_keep_local_id(env):
    manager,sessions,client=env
    raw=seed(env)
    async def info(_):return {"sub":"alice@test.com","email":"updated@test.com","email_verified":True,"name":"New"}
    manager.provider.userinfo=info
    with sessions() as db: before=db.get(manager.Session,manager.session_id(raw)).user_id
    assert client.get("/auth/account/return",follow_redirects=False).headers["location"]=="/"
    assert client.get("/auth/whoami").json()["email"]=="updated@test.com"
    with sessions() as db: assert db.get(manager.Session,manager.session_id(raw)).user_id==before


def test_apps_independent_and_no_host_cookie_sharing(tmp_path):
    one,db1,app1=build(tmp_path/"one.db",name="bide")
    two,db2,app2=build(tmp_path/"two.db",name="note")
    with TestClient(app1,base_url=one.config.base_url) as c1, TestClient(app2,base_url=two.config.base_url) as c2:
        raw=seed((one,db1,c1))
        c2.cookies.set(two.config.cookie_name,raw)
        assert not c2.get("/auth/whoami").json()["signedIn"]
        seed((two,db2,c2))
        assert c2.post("/auth/backchannel-logout",data={"logout_token":signed()}).status_code==400
        assert c2.get("/auth/whoami").json()["signedIn"]
        assert c1.get("/auth/whoami",headers={"host":"note.test"}).status_code==404


def test_login_callback_and_refresh_consent(env,monkeypatch):
    manager,sessions,client=env
    from fastapi.responses import RedirectResponse
    seen={}
    async def authorize(request,uri,**kwargs):
        seen.update(uri=uri,**kwargs)
        return RedirectResponse("https://auth.test/login")
    async def exchange(request):
        return {"id_token":"signed-by-provider", "access_token":"server-only-access", "refresh_token":"server-only-refresh",
                "expires_in":3600,"userinfo":{"sub":"owner","sid":"logto-session","email":"owner@test.com","email_verified":True}}
    monkeypatch.setattr(manager.provider.oauth.sso,"authorize_redirect",authorize)
    monkeypatch.setattr(manager.provider.oauth.sso,"authorize_access_token",exchange)
    client.get("/auth/login?next=/auth/sessions",follow_redirects=False)
    assert seen["prompt"]=="consent" and seen["uri"]==manager.config.callback
    r=client.get("/auth/callback",follow_redirects=False)
    assert r.headers["location"]=="/auth/sessions"
    assert "server-only" not in str(r.headers) and "signed-by-provider" not in str(r.headers)
    assert "HttpOnly" in r.headers["set-cookie"] and "Secure" in r.headers["set-cookie"]
    assert client.get("/auth/whoami").json()["email"]=="owner@test.com"
    client.get("/auth/login?next=//evil.test&reauthenticate=true",follow_redirects=False)
    assert seen["prompt"]=="login consent"
    assert client.get("/auth/callback",follow_redirects=False).headers["location"]=="/"


def test_callback_unverified_email_and_sub_mismatch_rejected(env,monkeypatch):
    manager,_,client=env
    async def exchange(request):
        return {"id_token":"id", "access_token":"access", "expires_in":3600,
                "userinfo":{"sub":"owner", "email":"owner@test.com", "email_verified":False}}
    monkeypatch.setattr(manager.provider.oauth.sso,"authorize_access_token",exchange)
    assert "autherr" in client.get("/auth/callback",follow_redirects=False).headers["location"]
    assert not client.get("/auth/whoami").json()["signedIn"]


def test_provider_http_requests_and_rotation_errors(env,monkeypatch):
    import httpx
    manager,_,_=env
    calls=[]
    def handler(request):
        calls.append(request)
        if request.url.path.endswith("openid-configuration"):
            return httpx.Response(200,json={"issuer":ISSUER,"token_endpoint":ISSUER+"/token","userinfo_endpoint":ISSUER+"/me","jwks_uri":ISSUER+"/jwks"})
        if request.url.path.endswith("/token"):
            if b"revoked" in request.content:return httpx.Response(400,json={"error":"invalid_grant"})
            return httpx.Response(200,json={"access_token":"new-access","refresh_token":"new-refresh","expires_in":3600,"token_type":"Bearer"})
        return httpx.Response(200,json={"sub":"owner"})
    original=httpx.AsyncClient
    monkeypatch.setattr(httpx,"AsyncClient",lambda **kw:original(transport=httpx.MockTransport(handler),**kw))
    async def check():
        value=await manager.provider.refresh("old-refresh")
        assert value["refresh_token"]=="new-refresh"
        assert await manager.provider.userinfo(value["access_token"])=={"sub":"owner"}
        with pytest.raises(InvalidToken):await manager.provider.refresh("revoked")
    asyncio.run(check())
    token_call=next(r for r in calls if r.url.path.endswith("/token"))
    assert token_call.headers["authorization"].startswith("Basic ")
    assert "client-secret" not in str(token_call.url)


def test_shared_ui_script_available_without_login(env):
    _, _, client = env
    r = client.get('/auth/ui.js')
    assert r.status_code == 200
    assert 'javascript' in r.headers['content-type']
    assert '/auth/account?section=profile' in r.text
    assert 'alice@test.com' not in r.text
    assert client.get('/auth/ui.js', headers={'host': 'untrusted.test'}).status_code == 404


def test_profile_links_are_local_and_available_only_when_signed_in(tmp_path):
    from fujioky_auth.web import build_router
    manager, sessions, app = build(tmp_path / 'links.db')
    manager.config = replace(manager.config, profile_links=(
        {'href': '/oauth/connections', 'label': 'Authorized clients'},
        {'href': '//evil.test', 'label': 'bad external'},
        {'href': '/\\evil.test', 'label': 'bad backslash'},
    ))
    app.router.routes = []
    app.include_router(build_router(manager))
    with TestClient(app, base_url=manager.config.base_url) as client:
        assert client.get('/auth/whoami').json()['profileLinks'] == []
        seed((manager, sessions, client))
        assert client.get('/auth/whoami').json()['profileLinks'] == [
            {'href': '/oauth/connections', 'label': 'Authorized clients'}]
        response = client.get('/auth/account?section=security', follow_redirects=False)
        assert response.headers['location'].startswith('https://auth.test/account/security?')


def test_form_pages_preserve_origin_and_disable_cdn_transforms(env):
    _, _, client = env
    seed(env)
    for path in ('/auth/sessions', '/auth/logout'):
        r = client.get(path)
        assert r.status_code == 200
        assert r.headers['referrer-policy'] == 'same-origin'
        assert 'no-store' in r.headers['cache-control']
        assert 'no-transform' in r.headers['cache-control']


def test_repeated_logout_returns_safely_without_reauthenticating(env):
    manager, _, client = env
    seed(env, tokens=False)
    data = fields(client.get('/auth/logout'))
    assert client.post('/auth/logout', data=data, follow_redirects=False).status_code == 303
    response = client.post('/auth/logout', data={**data, 'next':'https://evil.test'}, follow_redirects=False)
    assert response.status_code == 303 and response.headers['location'] == '/'
    assert not client.get('/auth/whoami').json()['signedIn']


def profile_provider(manager, *, denied=False):
    from fujioky_auth.provider import AccountDenied
    state={"id":"alice@test.com","name":"Alice","avatar":"https://images.test/old.png"}
    calls=[]
    async def account(token,changes=None):
        assert token == 'private-access'
        if changes is not None:
            if denied: raise AccountDenied('denied')
            calls.append(changes)
            state.update(changes)
        return dict(state)
    manager.provider.account=account
    return state,calls


def test_profile_save_uses_current_user_and_syncs(env):
    manager,sessions,c=env
    seed(env)
    state,calls=profile_provider(manager)
    page=c.get('/auth/account')
    assert page.status_code==200 and 'private-access' not in page.text
    data={**fields(page),'name':'New Name','avatar':'','sub':'victim','is_admin':'true'}
    r=c.post('/auth/account',data=data,headers={'origin':manager.config.base_url},follow_redirects=False)
    assert r.status_code==303
    assert calls==[{'name':'New Name','avatar':None}]
    with sessions() as db:
        user=db.scalar(select(manager.User)) if hasattr(manager,'User') else db.scalar(select(manager.user_model))
        assert user.name=='New Name' and user.avatar=='' and not user.is_admin


def test_profile_requires_login_and_csrf(env):
    manager,_,c=env
    assert c.get('/auth/account',follow_redirects=False).headers['location'].startswith('/auth/login?')
    seed(env)
    _,calls=profile_provider(manager)
    assert c.post('/auth/account',data={'name':'Bob'}).status_code==403
    data={**fields(c.get('/auth/account')),'name':'Bob','avatar':''}
    assert c.post('/auth/account',data=data,headers={'origin':'https://evil.test'}).status_code==403
    assert calls==[]


@pytest.mark.parametrize('avatar',['javascript:alert(1)','http://images.test/a','https://user:pass@images.test/a'])
def test_profile_rejects_unsafe_avatar(env,avatar):
    manager,_,c=env
    seed(env);_,calls=profile_provider(manager)
    r=c.post('/auth/account',data={**fields(c.get('/auth/account')),'name':'Bob','avatar':avatar})
    assert r.status_code==400 and calls==[]


def test_profile_denied_does_not_claim_success(env):
    manager,_,c=env
    seed(env);profile_provider(manager,denied=True)
    r=c.post('/auth/account',data={**fields(c.get('/auth/account')),'name':'Bob','avatar':''})
    assert r.status_code==403 and '资料已保存' not in r.text


def test_profile_rejects_different_account(env):
    manager,_,c=env
    seed(env);state,calls=profile_provider(manager);state['id']='victim'
    r=c.get('/auth/account',follow_redirects=False)
    assert r.status_code==303 and r.headers['location'].startswith('/auth/login?') and not calls


def test_account_api_transport_limits_fields_and_handles_errors(env,monkeypatch):
    import httpx
    from fujioky_auth.provider import LogtoProvider, AccountDenied
    manager,_,_=env
    seen=[]
    code=[200]
    def handler(request):
        seen.append(request)
        return httpx.Response(code[0],json={'id':'alice@test.com','name':'Alice'})
    original=httpx.AsyncClient
    monkeypatch.setattr(httpx,'AsyncClient',lambda **kw:original(transport=httpx.MockTransport(handler),**kw))
    provider=LogtoProvider(manager.config)
    async def exercise():
        assert (await provider.account('opaque'))['id']=='alice@test.com'
        await provider.account('opaque',{'name':'Bob','avatar':None,'roles':['admin'],'id':'victim'})
        code[0]=403
        with pytest.raises(AccountDenied): await provider.account('opaque',{'name':'Bob'})
        code[0]=401
        with pytest.raises(InvalidToken): await provider.account('opaque')
        code[0]=503
        with pytest.raises(ProviderUnavailable): await provider.account('opaque')
    asyncio.run(exercise())
    assert str(seen[0].url)=='https://auth.test/api/my-account'
    assert seen[0].headers['authorization']=='Bearer opaque'
    assert json.loads(seen[1].content)=={'name':'Bob','avatar':None}
