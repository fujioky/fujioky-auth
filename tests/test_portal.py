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
