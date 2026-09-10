import re
from fastapi.testclient import TestClient
from fujioky_auth.portal import create_app
from fujioky_auth.provider import ProviderUnavailable
from test_auth import seed, signed, JWK


def test_portal_session_and_verification(tmp_path):
    app=create_app({'BASE_URL':'https://account.test','SESSION_SECRET':'s'*40,
        'OIDC_ISSUER':'https://auth.test/oidc','OIDC_CLIENT_ID':'bide-client','OIDC_CLIENT_SECRET':'secret',
        'DATABASE_URL':'sqlite:///'+str(tmp_path/'portal.db'),'CORS_ORIGINS':'https://home.test'})
    manager=app.state.manager
    async def account(token):return {'id':'alice@test.com','primaryEmail':'alice@test.com','name':'Alice','avatar':''}
    manager.provider.account=account
    calls=[]
    async def api(token,method,path,data=None,verification=''):
        calls.append((method,path,data,verification))
        if path=='/api/verifications/password':return {'verificationRecordId':'verified'}
        if method=='DELETE':return None
        return {'sessions':[{'payload':{'jti':'other-id','uid':'session-id'},'isCurrent':True}]}
    manager.provider.account_request=api
    with TestClient(app,base_url='https://account.test') as c:
        r=c.get('/auth/whoami',headers={'Origin':'https://home.test'})
        assert r.json()['signedIn'] is False
        assert r.headers['access-control-allow-origin']=='https://home.test'
        assert 'access-control-allow-origin' not in c.get('/auth/whoami',headers={'Origin':'https://evil.test'}).headers
        seed((manager,app.state.sessions,c))
        assert c.get('/auth/whoami').json()['accountBase']=='https://account.test'
        r=c.get('/security');assert r.status_code==200 and '/security/change/email' in r.text
        r=c.get('/sessions');assert '验证身份' in r.text and not calls
        assert c.post('/verify',data={'method':'password','password':'secret'}).status_code==403
        csrf=re.search(r'name="csrf" value="([^"]+)',r.text)[1]
        r=c.post('/verify',data={'csrf':csrf,'method':'password','password':'secret','next':'/sessions'},follow_redirects=False)
        assert r.status_code==303
        r=c.get('/sessions');assert '当前登录' in r.text
        assert calls[-1][-1]=='verified'
        csrf=re.search(r'name="csrf" value="([^"]+)',r.text)[1]
        r=c.post('/sessions/revoke',data={'csrf':csrf,'id':'session-id'},follow_redirects=False)
        assert r.status_code==303
        assert calls[-1][0:2]==('DELETE','/api/my-account/sessions/session-id?revokeGrantsTarget=all')


def test_logout_relay_validates_and_retries(env):
    manager,db,c=env
    seed(env)
    attempts=[]
    async def relay(token):
        attempts.append(token)
        if len(attempts)==1:raise ProviderUnavailable()
    c.app.state.relay_logout=relay
    assert c.post('/auth/backchannel-logout',data={'logout_token':'invalid'}).status_code==400
    assert not attempts
    raw=signed()
    assert c.post('/auth/backchannel-logout',data={'logout_token':raw}).status_code==503
    assert c.get('/auth/whoami').json()['signedIn'] is False
    assert c.post('/auth/backchannel-logout',data={'logout_token':raw}).status_code==200
    assert attempts==[raw,raw]

from test_auth import env


def test_native_changes_require_two_distinct_verifications(tmp_path):
    app=create_app({'BASE_URL':'https://account.test','SESSION_SECRET':'x'*40,
        'OIDC_ISSUER':'https://auth.test/oidc','OIDC_CLIENT_ID':'bide-client','OIDC_CLIENT_SECRET':'secret',
        'DATABASE_URL':'sqlite:///'+str(tmp_path/'changes.db')})
    m=app.state.manager
    calls=[]
    async def account(token):return {'id':'alice@test.com','primaryEmail':'alice@test.com'}
    m.provider.account=account
    async def api(token,method,path,data=None,verification=''):
        calls.append((path,data,verification))
        if path=='/api/verifications/password':return {'verificationRecordId':'identity-proof'}
        if path=='/api/verifications/verification-code':return {'verificationRecordId':'new-email-proof'}
        return None
    m.provider.account_request=api
    def csrf_of(response):return re.search(r'name="csrf" value="([^"]+)',response.text)[1]
    with TestClient(app,base_url='https://account.test') as c:
        seed((m,app.state.sessions,c))
        r=c.get('/security/change/email')
        assert r.status_code==200 and '发送验证码' in r.text
        assert r.text.count('<form ')==1 and 'name="password"' not in r.text
        assert 'auth.test/account' not in r.text
        r=c.post('/verify',data={'csrf':csrf_of(r),'method':'password','password':'existing','next':'/security/change/email'})
        assert 'name="email"' in r.text
        change_csrf=csrf_of(r)
        r=c.post('/security/change/email',data={'csrf':change_csrf,'step':'send','email':'new@example.com'})
        assert 'name="code"' in r.text and 'name="email"' not in r.text
        r=c.post('/security/change/email',data={'csrf':change_csrf,'step':'confirm','email':'forged@example.com','code':'123456'})
        assert '邮箱已更新' in r.text
        assert calls[-1]==('/api/my-account/primary-email',{'email':'new@example.com','newIdentifierVerificationRecordId':'new-email-proof'},'identity-proof')
        # The short-lived local proof is consumed after the update.
        r=c.get('/security/change/password')
        assert '发送验证码' in r.text
        r=c.post('/verify',data={'csrf':csrf_of(r),'method':'password','password':'existing','next':'/security/change/password'})
        n=len(calls)
        bad=c.post('/security/change/password',data={'csrf':csrf_of(r),'password':'long-password','confirmation':'different'})
        assert '不一致' in bad.text and len(calls)==n
        good=c.post('/security/change/password',data={'csrf':csrf_of(r),'password':'long-password','confirmation':'long-password'})
        assert '密码已更新' in good.text
        assert calls[-1]==('/api/my-account/password',{'password':'long-password'},'identity-proof')
