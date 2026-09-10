"""Shared account styling and avatar navigation; applications supply optional links."""

CSS = '''
*{box-sizing:border-box}body{margin:0;background:#f5f4ef;color:#24251f;font:15px/1.7 Arial,"PingFang SC",sans-serif}a{color:inherit;text-decoration:none}a:hover{text-decoration:underline}header{max-width:980px;margin:auto;padding:28px 24px;border-bottom:1px solid #deded5;display:flex;justify-content:space-between;align-items:center}.brand{font-size:12px;font-weight:700;letter-spacing:3px}main{max-width:880px;margin:48px auto;padding:0 24px 64px}h1{font:400 36px/1.25 Georgia,serif;margin:0 0 30px}h2{font-size:17px;margin:0 0 4px}.muted{color:#77786f;overflow-wrap:anywhere}button{font:inherit;border:1px solid #deded5;background:#24251f;color:#f5f4ef;padding:10px 18px;cursor:pointer}button:focus-visible,a:focus-visible{outline:2px solid #c9784e;outline-offset:4px}article{padding:22px 0;border-top:1px solid #deded5}
'''

JS = r'''
(function(){
'use strict';
var slots=document.querySelectorAll('[data-lyra-auth]');if(!slots.length)return;
if(!document.getElementById('fujioky-account-style')){var style=document.createElement('style');style.id='fujioky-account-style';style.textContent=`
.fujioky-user{position:relative;display:inline-flex;align-items:center;font:14px/1.5 Arial,"PingFang SC",sans-serif;text-align:left;letter-spacing:normal}.fujioky-user .fujioky-avatar{display:grid;place-items:center;width:36px;height:36px;padding:0;border:1px solid #d8d9d3;border-radius:50%;overflow:hidden;background:#e7e6df;color:#24251f;text-decoration:none;flex-shrink:0;font-size:15px}.fujioky-avatar img{width:100%;height:100%;object-fit:cover}.fujioky-user .fujioky-menu{display:block;position:absolute;top:100%;right:-8px;padding-top:12px;z-index:2000;width:248px;visibility:hidden;opacity:0;transform:translateY(-4px);transition:opacity .14s,transform .14s,visibility .14s}.fujioky-user[data-open] .fujioky-menu{visibility:visible;opacity:1;transform:none}.fujioky-menu-inner{padding:12px;background:#f5f4ef;color:#24251f;border:1px solid #deded5;border-radius:12px;box-shadow:0 12px 35px #24251f18}.fujioky-menu-name{font-weight:600;padding:5px 10px 0;overflow-wrap:anywhere}.fujioky-menu-email{padding:3px 10px 12px;color:#77786f;font-size:12px;overflow-wrap:anywhere;border-bottom:1px solid #deded5;margin-bottom:8px}.fujioky-user .fujioky-menu a{display:block;color:#24251f!important;padding:9px 10px;border-radius:6px;text-decoration:none;font-size:14px}.fujioky-menu a:hover,.fujioky-menu a:focus-visible{background:#eae9e2}.fujioky-avatar:focus-visible{outline:2px solid #c9784e;outline-offset:4px}.fujioky-menu-toggle{display:none}@media(hover:none){.fujioky-menu-toggle{display:block;border:0;background:transparent;color:inherit;padding:8px;font:inherit;cursor:pointer}}@media(prefers-reduced-motion:reduce){.fujioky-menu{transition:none}}
`;document.head.appendChild(style);}
fetch('/auth/whoami',{credentials:'same-origin',cache:'no-store'}).then(function(r){if(!r.ok)throw Error();return r.json();}).then(function(d){
slots.forEach(function(slot){if(slot.dataset.accountMounted)return;slot.dataset.accountMounted='1';slot.textContent='';
function link(href,label){var a=document.createElement('a');a.href=href;a.textContent=label;return a;}
if(!d.signedIn){if(d.authReady)slot.appendChild(link('/auth/login?next='+encodeURIComponent(location.pathname+location.search),'登录'));return;}
var wrap=document.createElement('div');wrap.className='fujioky-user';
var avatar=link('/auth/account?section=profile',(d.name||'U').slice(0,1).toUpperCase());avatar.className='fujioky-avatar';avatar.setAttribute('aria-label','个人账户：'+(d.name||'用户'));avatar.setAttribute('aria-expanded','false');
if(d.avatar && /^https:\/\//i.test(d.avatar)){var im=document.createElement('img');im.src=d.avatar;im.alt='';im.referrerPolicy='no-referrer';im.onerror=function(){avatar.textContent=(d.name||'U').slice(0,1).toUpperCase();};avatar.textContent='';avatar.appendChild(im);}
var menu=document.createElement('nav');menu.className='fujioky-menu';menu.setAttribute('aria-label','账户快捷操作');
var inner=document.createElement('div');inner.className='fujioky-menu-inner';
var name=document.createElement('div');name.className='fujioky-menu-name';name.textContent=d.name||'用户';inner.appendChild(name);
var email=document.createElement('div');email.className='fujioky-menu-email';email.textContent=d.email||'';inner.appendChild(email);
inner.appendChild(link('/auth/account?section=profile','个人账户'));inner.appendChild(link('/auth/account?section=security','账号与安全'));inner.appendChild(link('/auth/sessions','登录设备'));
(d.profileLinks||[]).forEach(function(l){if(/^\/(?!\/)/.test(l.href)&&!/[\\\x00-\x1f]/.test(l.href))inner.appendChild(link(l.href,l.label));});
inner.appendChild(link('/auth/logout','退出登录'));menu.appendChild(inner);wrap.appendChild(avatar);wrap.appendChild(menu);slot.appendChild(wrap);
var toggle=document.createElement('button');toggle.type='button';toggle.className='fujioky-menu-toggle';toggle.textContent='⌄';toggle.setAttribute('aria-label','展开账户菜单');toggle.setAttribute('aria-expanded','false');wrap.insertBefore(toggle,menu);toggle.addEventListener('click',function(){if(wrap.hasAttribute('data-open'))hide();else show();});
function show(){toggle.setAttribute('aria-expanded','true');wrap.setAttribute('data-open','');avatar.setAttribute('aria-expanded','true');}
function hide(){toggle.setAttribute('aria-expanded','false');wrap.removeAttribute('data-open');avatar.setAttribute('aria-expanded','false');}
wrap.addEventListener('pointerenter',function(e){if(e.pointerType==='mouse'||e.pointerType==='pen')show();});wrap.addEventListener('pointerleave',function(){if(!wrap.contains(document.activeElement))hide();});
wrap.addEventListener('focusin',function(e){if(e.target!==toggle)show();});wrap.addEventListener('focusout',function(e){if(!wrap.contains(e.relatedTarget))hide();});
document.addEventListener('keydown',function(e){if(e.key==='Escape'&&wrap.hasAttribute('data-open')){e.preventDefault();avatar.focus();hide();}});
wrap.addEventListener('keydown',function(e){if(e.key==='ArrowDown'&&e.target===avatar){e.preventDefault();show();inner.querySelector('a').focus();}});
document.addEventListener('pointerdown',function(e){if(!wrap.contains(e.target))hide();});
});}).catch(function(){slots.forEach(function(s){if(s.children.length)return;var a=document.createElement('a');a.href='/auth/account?section=profile';a.textContent='个人账户';s.appendChild(a);});});
})();
'''
