#!/usr/bin/env python3
"""Single administrator, local-host Docker control plane. No third-party dependencies."""
import base64
import auth
import defaults
import minimal
import subscriptions
import system_status
import provision
import wdtt
import images
from transports import TRANSPORTS, client_config
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import sqlite3
import subprocess
import threading
import time
import zipfile
import uuid
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from catalog import PROTOCOLS, BY_ID
from engine import validate, bundle, credential, profile

ROOT=Path(__file__).resolve().parent
DATA=Path(os.environ.get('YPTUN_DATA',str(ROOT/'data'))).resolve()
LOCK=threading.RLock()


def init():
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    os.chmod(DATA,0o700)
    with db() as c:
        c.execute('CREATE TABLE IF NOT EXISTS objects (id TEXT PRIMARY KEY, kind TEXT NOT NULL, value TEXT NOT NULL)')
        c.execute('CREATE TABLE IF NOT EXISTS events (at INTEGER, message TEXT)')
        # Existing access tokens and keys remain valid; each legacy access becomes a person.
        for object_id,value in c.execute("SELECT id,value FROM objects WHERE kind='user'").fetchall():
            u=json.loads(value)
            if u.get('person_id'):continue
            person=dict(id='person_'+object_id,name=u['name'],token=u['token'],created=int(time.time()))
            c.execute('INSERT OR IGNORE INTO objects VALUES (?,?,?)',(person['id'],'person',json.dumps(person)))
            u['person_id']=person['id']
            c.execute('UPDATE objects SET value=? WHERE id=?',(json.dumps(u),object_id))
    return auth.initialize(DATA)


def db():return sqlite3.connect(str(DATA/'panel.sqlite3'))
def rows(kind):
    with db() as c:return [json.loads(r[0]) for r in c.execute('SELECT value FROM objects WHERE kind=? ORDER BY rowid DESC',(kind,))]
def get(id,kind):
    with db() as c:r=c.execute('SELECT value FROM objects WHERE id=? AND kind=?',(id,kind)).fetchone()
    if not r:raise ValueError('Объект не найден')
    return json.loads(r[0])
def put(kind,o):
    with db() as c:c.execute('INSERT OR REPLACE INTO objects VALUES (?,?,?)',(o['id'],kind,json.dumps(o)))
def remove(id):
    with db() as c:c.execute('DELETE FROM objects WHERE id=?',(id,))
def event(msg):
    with db() as c:
        c.execute('INSERT INTO events VALUES (?,?)',(int(time.time()),msg))
        c.execute('DELETE FROM events WHERE rowid NOT IN (SELECT rowid FROM events ORDER BY rowid DESC LIMIT 200)')
def members(id):return [u for u in rows('user') if u['service_id']==id]
def compose(s,args,timeout=30,input=None):
    if os.environ.get('YPTUN_ALLOW_DOCKER')!='1':raise ValueError('Запуск отключён. Установите YPTUN_ALLOW_DOCKER=1 на хосте панели')
    try:
        r=subprocess.run(['docker','compose','-p','yptun-'+s['id'],'-f',str(DATA/s['id']/'compose.json'),*args],capture_output=True,text=True,timeout=timeout,input=input)
    except (OSError,subprocess.TimeoutExpired):raise ValueError('Docker недоступен или превышено время ожидания')
    if r.returncode:raise ValueError('Ошибка Docker: '+r.stderr[-1500:])
    return r.stdout

def write_bundle(s):
    directory=DATA/s['id'];directory.mkdir(mode=0o700,exist_ok=True)
    if s.get('image_id')=='warp' or s['protocol']=='wdtt':(directory/'runtime').mkdir(mode=0o700,exist_ok=True)
    for name,body in bundle(s,members(s['id'])).items():
        target=directory/name;target.parent.mkdir(mode=0o700,parents=True,exist_ok=True);tmp=target.with_name(target.name+'.tmp');tmp.write_bytes(body) if isinstance(body,bytes) else tmp.write_text(body);os.chmod(tmp,0o600);tmp.replace(target)

def running(s,strict=False):
    try:
        out=compose(s,['ps',*(['--all'] if strict else []),'--format','json'],10)
        items=json.loads(out) if out.strip().startswith('[') else [json.loads(x) for x in out.splitlines() if x.strip()]
        return any(x.get('State') not in ('exited','dead','created') if strict else x.get('State')=='running' for x in items)
    except (ValueError,json.JSONDecodeError):
        if strict:raise ValueError('Не удалось проверить состояние контейнера')
        return False

def sync(s):
    write_bundle(s)
    if s.get('desired')=='running':
        if (BY_ID[s['protocol']]['mode']=='native' or s.get('provisioned')) and not any(u['enabled'] for u in members(s['id'])):
            # Empty Hysteria2 user lists must never become an unauthenticated live listener.
            compose(s,['down']);s['desired']='stopped';put('service',s)
        else:compose(s,['up','-d','--force-recreate'],120)



def rollback(s):
    """Restore both saved files and the actual bind mounts after a failed recreate."""
    write_bundle(s)
    if s.get('desired')=='running':
        try:compose(s,['up','-d','--force-recreate'],120)
        except ValueError:event('Не удалось восстановить контейнер после ошибки; проверьте службу: '+s['name'])


def https_status():
    path=Path(os.environ.get('YPTUN_HTTPS_STATUS','/etc/yptun-panel/https.json'))
    if path.exists():return json.loads(path.read_text())
    return dict(host='',mode='',trusted=False,self_sni_ready=False)



def certificate_helper(data):
    if os.environ.get('YPTUN_HTTPS_HELPER')!='1':raise ValueError('Выпуск сертификата доступен на установленном Linux-сервере')
    result=subprocess.run(['sudo','-n','/usr/local/sbin/yptun-https'],input=json.dumps(data),capture_output=True,text=True,timeout=300)
    if result.returncode:raise ValueError('Ошибка сертификата: '+result.stderr[-2000:])
    return json.loads(result.stdout)


def generate_certificate(data):
    result=certificate_helper(dict(action='service-certificate',host=data.get('host',''),mode=data.get('mode','domain')))
    event('Выпущен сертификат службы: '+result['host'])
    return result

def prepare_service(data):
    s=dict(data)
    if not s.get('image') and BY_ID.get(s.get('protocol'),{}).get('mode')=='custom':
        image=next(i for i in images.CATALOG if s['protocol'] in i['protocols'])
        s.update(image_id=image['id'],image=image['reference'],command=image.get('command',[]))
    if not s.get('port') or not s.get('name') or not s.get('host'):
        preset=service_defaults(s.get('protocol'))
        for key in ('port','name','host','transport','security','sni','path'):
            if s.get(key) in (None,''):s[key]=preset[key]
    if s.get('self_sni'):
        status=https_status()
        if not status.get('self_sni_ready'):raise ValueError('Сначала настройте HTTPS по домену в разделе HTTPS и доступ')
        s['self_sni_domain']=status['host']
    else:s.pop('self_sni_domain',None)
    if s.get('certificate_id') and (s.get('security')=='tls' or s['protocol']=='trusttunnel'):
        managed=certificate_helper(dict(action='read-service-certificate',certificate_id=s['certificate_id']))
        s.update(certificate=managed['certificate'],private_key=managed['private_key'])
    s=minimal.apply(s)
    s=validate(s)
    if os.environ.get('YPTUN_HTTPS_HELPER')=='1' and s['port'] in (22,80,443,8080,9443):raise ValueError('Порт зарезервирован для SSH, HTTPS или панели; используйте, например, 8443')
    return s


def configure_https(data):
    if os.environ.get('YPTUN_HTTPS_HELPER')!='1':raise ValueError('Настройка HTTPS доступна после установки на Linux-сервер')
    active=[s for s in rows('service') if s.get('self_sni')]
    if active and data.get('host')!=https_status().get('host'):raise ValueError('Сначала отключите self-SNI в существующих службах перед сменой домена')
    if active and data.get('mode')=='ip':raise ValueError('Сначала отключите self-SNI в службах')
    result=subprocess.run(['sudo','-n','/usr/local/sbin/yptun-https'],input=json.dumps(data),capture_output=True,text=True,timeout=300)
    if result.returncode:raise ValueError('Не удалось настроить HTTPS: '+result.stderr[-2000:])
    status=json.loads(result.stdout);event('Обновлён HTTPS: '+status['host']);return status

def service_defaults(protocol,exclude_port=None):
    reserved=set().union(*(bound_ports(s) for s in rows('service')))
    if exclude_port is not None:
        port=int(exclude_port)
        if not 1<=port<=65535:raise ValueError('Некорректный порт')
        reserved.add(port)
    return defaults.setup(protocol,https_status().get('host',''),reserved)

def bound_ports(s):return {s['port']}|({s['admin_port']} if s['protocol']=='wdtt' and s.get('admin_port') else set())

def turn_request(s,path='',data=None):
    try:return wdtt.request(s,path,data)
    except wdtt.CoreUnavailable:
        if running(s,strict=True):raise ValueError('TURN работает, но его API недоступен. Проверьте журнал туннеля.')
    # No read/modify/write of the core database while a container is running.
    target=DATA/s['id']/'runtime'/'passwords.json'
    try:database=json.loads(target.read_text()) if target.exists() else dict(passwords={},devices={})
    except PermissionError:
        output=compose(s,['run','--rm','--no-deps','-T','--entrypoint','/bin/sh','tunnel','-c','if [ -f /etc/wdtt/passwords.json ]; then cat /etc/wdtt/passwords.json; else printf \'{"passwords":{},"devices":{}}\'; fi'],60)
        database=json.loads(output)
    view=wdtt.offline_change(database,path,data)
    if data is not None:
        body=json.dumps(database)
        try:
            target.parent.mkdir(mode=0o700,exist_ok=True)
            tmp=target.with_name('passwords.panel.tmp');tmp.write_text(body);os.chmod(tmp,0o600)
            if target.exists():shutil.copyfile(target,target.with_suffix('.previous'));os.chmod(target.with_suffix('.previous'),0o600)
            tmp.replace(target)
        except PermissionError:
            compose(s,['run','--rm','--no-deps','-T','--entrypoint','/bin/sh','tunnel','-c','umask 077; cat > /etc/wdtt/passwords.panel.tmp && { [ ! -f /etc/wdtt/passwords.json ] || cp /etc/wdtt/passwords.json /etc/wdtt/passwords.previous; } && mv /etc/wdtt/passwords.panel.tmp /etc/wdtt/passwords.json'],60,input=body)
    return view


def person_name(data):
    name=str(data.get('name','')).strip()
    if not 1<=len(name)<=100:raise ValueError('Имя пользователя: от 1 до 100 символов')
    return name


def save_access(u,person_id=None):
    # The connection and its owner are attached in one SQLite transaction.
    person=get(person_id,'person') if person_id else dict(id='person_'+u['id'],name=u['name'],token=u['token'],created=int(time.time()))
    u['person_id']=person['id']
    with db() as c:
        c.execute('INSERT OR REPLACE INTO objects VALUES (?,?,?)',(person['id'],'person',json.dumps(person)))
        c.execute('INSERT OR REPLACE INTO objects VALUES (?,?,?)',(u['id'],'user',json.dumps(u)))


def turn_capacity(s):
    count=sum(not u.get('expires_at') or u['expires_at']>time.time() for u in members(s['id']))
    unavailable=False
    if os.environ.get('YPTUN_ALLOW_DOCKER')=='1' or s.get('desired')=='running':
        try:
            view=turn_request(s)
            values=view if isinstance(view,list) else view.get('passwords')
            if isinstance(values,(dict,list)):count=len(values)
        except ValueError:unavailable=True
    return dict(used=count,limit=10,free=max(0,10-count),unavailable=unavailable)


def require_turn_slot(s):
    cap=turn_capacity(s)
    if cap['free']<=0:raise ValueError('Лимит TURN-подписок достигнут: '+str(cap['used'])+'/10. Удалите ненужную подписку или создайте другой TURN-туннель. Отключённые подписки тоже занимают место.')


def mutate(path,data):
    parts=path.strip('/').split('/');kind=parts[1];id=parts[2] if len(parts)>2 else None;action=parts[3] if len(parts)>3 else None
    if kind=='service-defaults':return service_defaults(data.get('protocol'),data.get('exclude_port'))
    if kind=='turn-hashes':
        values=wdtt.hashes(data.get('hashes','')).split(',')
        for value in values:put('turnhash',dict(id='turnhash:'+value,value=value))
        return dict(hashes=[x['value'] for x in rows('turnhash')])
    if kind=='images':return images.start_job(id,action,DATA)
    if kind=='certificates':return generate_certificate(data)
    if kind=='https':return configure_https(data)
    if kind=='people':
        if not id:
            person=dict(id=secrets.token_hex(8),name=person_name(data),token=secrets.token_urlsafe(32),created=int(time.time()))
            put('person',person);event('Создан пользователь: '+person['name']);return person
        person=get(id,'person')
        if action=='edit':person['name']=person_name(data);put('person',person);return person
        if action=='rotate':person['token']=secrets.token_urlsafe(32);put('person',person);return person
        if action=='grant':return mutate('/api/users',dict(data,person_id=id,name=data.get('name') or person['name']))
        if action=='delete':
            if any(u.get('person_id')==id for u in rows('user')):raise ValueError('Сначала удалите подключения пользователя')
            remove(id);return {}
        raise ValueError('Неизвестное действие пользователя')
    if kind=='services':
        if not id:
            s=prepare_service(data);s.update(id=secrets.token_hex(8),desired='stopped',created=int(time.time()))
            # Same host here: every managed service binds on this machine.
            if any(bound_ports(s)&bound_ports(x) for x in rows('service')):raise ValueError('Этот порт уже занят другой службой панели')
            write_bundle(s);put('service',s);event('Создана служба: '+s['name']);return s
        s=get(id,'service')
        if action=='edit':
            updated=dict(s);updated.update(data);updated['id']=s['id'];updated['protocol']=s['protocol'];updated['desired']=s['desired']
            updated=prepare_service(updated)
            if any(x['id']!=id and bound_ports(updated)&bound_ports(x) for x in rows('service')):raise ValueError('Порт занят другой службой')
            bundle(updated,members(id))
            put('service',updated)
            try:sync(updated)
            except Exception:put('service',s);rollback(s);raise
            event('Изменена служба: '+s['name']);return {}
        if action in ('start','restart','stop'):
            if action=='stop':compose(s,['down']);s['desired']='stopped'
            else:
                if (BY_ID[s['protocol']]['mode']=='native' or s.get('provisioned')) and not any(u['enabled'] for u in members(id)):raise ValueError('Сначала добавьте активного пользователя')
                write_bundle(s);compose(s,['up','-d'] if action=='start' else ['up','-d','--force-recreate'],120);s['desired']='running'
            put('service',s);event(s['name']+': '+action);return dict(running=running(s))
        if action=='delete':
            if s.get('desired')=='running' or running(s):raise ValueError('Сначала остановите службу')
            for u in members(id):remove(u['id'])
            remove(id);shutil.rmtree(DATA/id,ignore_errors=True);event('Удалена служба: '+s['name']);return {}
        raise ValueError('Неизвестное действие')
    if kind=='users':
        if not id:
            if data.get('person_id'):get(data['person_id'],'person')
            s=get(data.get('service_id',''),'service')
            if s['protocol']=='wdtt':
                require_turn_slot(s)
                view=turn_request(s,data=wdtt.user_fields(s,data))
                u=wdtt.apply_view(dict(id=secrets.token_hex(8),name=data['name'],service_id=s['id'],token=secrets.token_urlsafe(32)),view)
                try:save_access(u,data.get('person_id'))
                except Exception:turn_request(s,'/delete',dict(password=u['password']));raise
                event('Выдан доступ TURN: '+u['name']);return u
            if not str(data.get('name','')).strip() or len(data['name'])>100:raise ValueError('Укажите имя пользователя до 100 символов')
            if s['protocol']=='shadowsocks' and members(s['id']):raise ValueError('Shadowsocks: создайте отдельную службу для второго пользователя')
            u=dict(id=secrets.token_hex(8),name=data['name'],service_id=s['id'],enabled=True,token=secrets.token_urlsafe(32),profile=data.get('profile',''),**credential())
            if s.get('provisioned'):
                u['vk_hash']=data.get('vk_hash','')
                u=provision.user(s,u,members(s['id']))
            if s['protocol'] in ('vless','vmess','warp') and data.get('uuid'):
                try:u['uuid']=str(uuid.UUID(data['uuid']))
                except ValueError:raise ValueError('Некорректный UUID')
                if any(other['uuid']==u['uuid'] for other in members(s['id'])):raise ValueError('UUID уже используется в этой службе')
            if s['protocol'] in ('trojan','shadowsocks','hysteria2','trusttunnel') and data.get('password'):
                if not 8<=len(data['password'])<=255:raise ValueError('Пароль доступа: от 8 до 255 символов')
                u['password']=data['password']
                if any(other['password']==u['password'] for other in members(s['id'])):raise ValueError('Пароль уже используется в этой службе')
            if BY_ID[s['protocol']]['mode']=='custom' and not s.get('provisioned') and not u['profile'].strip():raise ValueError('Для своего движка нужен готовый клиентский конфиг или URI')
            try:subscriptions.link(s,u)
            except ValueError:
                if BY_ID[s['protocol']]['mode']=='custom':raise
            save_access(u,data.get('person_id'))
            try:sync(s)
            except Exception:
                remove(u['id'])
                if not data.get('person_id'):remove(u['person_id'])
                rollback(s);raise
            event('Выдан доступ: '+u['name']);return u
        u=get(id,'user');s=get(u['service_id'],'service')
        if s['protocol']=='wdtt':
            if action=='rotate':u['token']=secrets.token_urlsafe(32);put('user',u);return {}
            if action=='delete':
                try:turn_request(s,'/delete',dict(password=u['password']))
                except wdtt.CoreNotFound:pass
                remove(id)
            elif action in ('toggle','edit'):
                fields=dict(password=u['password'])
                if action=='edit':
                    fields.update(wdtt.user_fields(s,data));path='/update'
                    if not data.get('days') and (not u.get('expires_at') or u['expires_at']>time.time()):fields.pop('days',None)
                else:path='/deactivate' if u['enabled'] else '/activate'
                if action=='edit' and u.get('expires_at',0) and u['expires_at']<=time.time():
                    fields.pop('password',None);view=turn_request(s,data=fields)
                else:view=turn_request(s,path,fields)
                u=wdtt.apply_view(u,view);put('user',u)
            else:raise ValueError('Неизвестное действие TURN')
            event('Доступ TURN '+u['name']+': '+action);return {}
        if action=='edit':
            old=dict(u);u['name']=person_name(data)
            if data.get('uuid'):
                if s['protocol'] not in ('vless','vmess','warp'):raise ValueError('UUID доступен для VLESS и VMess')
                try:u['uuid']=str(uuid.UUID(data['uuid']))
                except ValueError:raise ValueError('Некорректный UUID')
                if any(x['id']!=id and x.get('uuid')==u['uuid'] for x in members(s['id'])):raise ValueError('UUID уже используется')
            if data.get('password'):
                if s['protocol'] not in ('trojan','shadowsocks','hysteria2','trusttunnel'):raise ValueError('Пароль здесь не используется')
                if not 8<=len(data['password'])<=255:raise ValueError('Пароль: от 8 до 255 символов')
                u['password']=data['password']
                if any(x['id']!=id and x.get('password')==u['password'] for x in members(s['id'])):raise ValueError('Пароль уже используется')
            if BY_ID[s['protocol']]['mode']=='custom' and not s.get('provisioned') and 'profile' in data:u['profile']=data['profile']
            if s.get('provisioned') and s['protocol']=='vkturn' and data.get('vk_hash'):u['vk_hash']=wdtt.hashes(data['vk_hash'])
            if s.get('provisioned') and s['protocol'] in ('wireguard','amneziawg','vkturn') and data.get('rotate_key'):
                keys=provision.user(s,dict(u),[x for x in members(s['id']) if x['id']!=id])
                for k in ('wg_private','wg_public','wg_psk'):u[k]=keys[k]
            subscriptions.link(s,u)
            put('user',u)
            try:sync(s)
            except Exception:put('user',old);rollback(s);raise
            event('Изменено подключение: '+u['name']);return {}
        if action=='toggle' and BY_ID[s['protocol']]['mode']=='custom' and not s.get('provisioned'):raise ValueError('Свой движок: отзовите доступ в его конфигурации; выключение подписки не отзывает VPN-ключ')
        if action=='toggle':
            old=dict(u);u['enabled']=not u['enabled'];put('user',u)
            try:sync(s)
            except Exception:put('user',old);rollback(s);raise
        elif action=='rotate':u['token']=secrets.token_urlsafe(32);put('user',u)
        elif action=='delete':
            if BY_ID[s['protocol']]['mode']=='custom' and not s.get('provisioned') and s.get('desired')=='running':raise ValueError('Сначала остановите свой движок и удалите ключ из его конфигурации; автоматический отзыв недоступен')
            remove(id)
            try:sync(s)
            except Exception:put('user',u);rollback(s);raise
        else:raise ValueError('Неизвестное действие')
        event('Доступ '+u['name']+': '+action);return {}
    raise ValueError('Неизвестный API')


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args):pass
    def send(self,status,body,ctype='application/json; charset=utf-8',headers=None):
        if not isinstance(body,bytes):body=(json.dumps(body,ensure_ascii=False) if ctype.startswith('application/json') else body).encode()
        self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(body)));self.send_header('Cache-Control','no-store');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','no-referrer');self.send_header('X-Frame-Options','DENY')
        self.send_header('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'")
        for k,v in (headers or {}).items():self.send_header(k,v)
        self.end_headers();self.wfile.write(body)
    def session_token(self):
        cookie=SimpleCookie()
        try:cookie.load(self.headers.get('Cookie',''))
        except Exception:return ''
        actual=cookie.get('yptun_session')
        return actual.value if actual else ''
    def auth(self):return auth.authenticated(self.session_token())
    def route(self):
        path=urlsplit(self.path).path
        prefix=auth.CONFIG['base_path']
        if __import__('re').fullmatch(r'/(?:turn-sub|subscription)/[A-Za-z0-9_-]{43}',path):return path
        if path==prefix:
            self.send(308,'','text/plain',{'Location':prefix+'/'})
            return None
        if not path.startswith(prefix+'/'):
            self.send(404,'Not found','text/plain')
            return None
        return path[len(prefix):]
    def cookie(self,token,age=43200):
        return 'yptun_session='+token+'; Max-Age='+str(age)+'; HttpOnly; SameSite=Strict; Path='+auth.CONFIG['base_path']+'/'+('; Secure' if os.environ.get('YPTUN_HTTPS')=='1' else '')
    def do_GET(self):
        path=self.route()
        if path is None:return
        try:
            if path.startswith('/subscription/'):
                token=path.rsplit('/',1)[-1]
                with LOCK:
                    person=next((p for p in rows('person') if hmac.compare_digest(p['token'],token)),None)
                    if not person:return self.send(404,dict(error='Подписка недоступна'))
                    body=subscriptions.feed(person,rows('user'),rows('service'),wdtt.available)
                return self.send(200,body,headers={'Profile-Update-Interval':'1'})
            if path.startswith('/turn-sub/'):

                token=path.rsplit('/',1)[-1];u=next((u for u in rows('user') if hmac.compare_digest(u['token'],token)),None)
                if not u or not wdtt.available(u):return self.send(404,dict(error='Подписка недоступна'))
                s=get(u['service_id'],'service')
                if s['protocol']!='wdtt':return self.send(404,{})
                if not subscriptions.service_available(s):return self.send(404,dict(error='Подписка недоступна'))
                return self.send(200,wdtt.subscription(s,u))
            if path=='/health':return self.send(200,dict(status='ok'))
            if path.startswith('/sub/'):
                token=path.rsplit('/',1)[-1]
                u=next((u for u in rows('user') if hmac.compare_digest(u['token'],token)),None)
                if not u or not wdtt.available(u):return self.send(404,'Подписка недоступна','text/plain; charset=utf-8')
                s=get(u['service_id'],'service')
                if not subscriptions.service_available(s):return self.send(404,'Подписка недоступна','text/plain; charset=utf-8')
                if s['protocol']=='wdtt':return self.send(200,wdtt.subscription(s,u))
                body=profile(s,u)
                if BY_ID[s['protocol']]['mode']=='native' and not body.lstrip().startswith('{'):body=base64.b64encode(body.encode()).decode()
                return self.send(200,body,'text/plain; charset=utf-8')
            if path.startswith('/api/'):
                if not self.auth():return self.send(401,dict(error='Требуется вход'))
                if path=='/api/system':return self.send(200,system_status.status())
                with LOCK:
                    if path=='/api/turn-hashes':return self.send(200,dict(hashes=[x['value'] for x in rows('turnhash')]))
                    if path=='/api/images':return self.send(200,images.image_list())
                    if path=='/api/https':return self.send(200,https_status())
                    if path=='/api/state':
                        services=rows('service')
                        for s in services:
                            if s['protocol']=='wdtt':s['capacity']=turn_capacity(s)
                            s['running']=running(s) if s.get('desired')=='running' else False
                            for k in ('private_key','certificate','reality_private','raw_config','admin_token','owner_password','admin_cert','admin_key','server_private','engine_key'):s.pop(k,None)
                        with db() as c:events=[dict(at=r[0],message=r[1]) for r in c.execute('SELECT at,message FROM events ORDER BY rowid DESC LIMIT 30')]
                        users=rows('user')
                        for u in users:
                            for k in ('password','uuid','profile','wg_private','wg_psk'):u.pop(k,None)
                        return self.send(200,dict(protocols=PROTOCOLS,transports=TRANSPORTS,image_catalog=images.CATALOG,services=services,users=users,people=rows('person'),events=events,docker_enabled=os.environ.get('YPTUN_ALLOW_DOCKER')=='1',https=https_status(),base_path=auth.CONFIG['base_path'],username=auth.CONFIG['username']))
                    parts=path.strip('/').split('/')
                    if len(parts)==4 and parts[1]=='users' and parts[3]=='settings':return self.send(200,get(parts[2],'user'))
                    if len(parts)==4 and parts[1]=='users' and parts[3]=='config':
                        u=get(parts[2],'user');s=get(u['service_id'],'service')
                        if s['protocol'] not in ('vless','vmess','trojan'):raise ValueError('Полный Xray JSON доступен для VLESS, VMess и Trojan')
                        return self.send(200,dict(content=json.dumps(client_config(s,u),indent=2,ensure_ascii=False)))
                    if len(parts)==4 and parts[1]=='users' and parts[3]=='profile':
                        u=get(parts[2],'user');return self.send(200,dict(content=profile(get(u['service_id'],'service'),u)))
                    if len(parts)==4 and parts[1]=='services':
                        s=get(parts[2],'service')
                        if parts[3]=='settings':return self.send(200,s)
                        if parts[3]=='logs':return self.send(200,dict(content=compose(s,['logs','--tail','100','--no-color']) or 'Журнал пуст'))
                        if parts[3]=='export':
                            files=bundle(s,members(s['id']));out=io.BytesIO()
                            with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED) as z:
                                for name,body in files.items():z.writestr(name,body)
                                for u in members(s['id']):
                                    if u['enabled']:z.writestr('clients/'+u['id']+'.txt',profile(s,u))
                            return self.send(200,out.getvalue(),'application/zip',{'Content-Disposition':'attachment; filename="yptun-'+s['id']+'.zip"'})
                    return self.send(404,dict(error='API не найден'))
            asset={'/':'index.html','/app.js':'app.js','/qrcode.js':'qrcode.js','/style.css':'style.css'}.get(path)
            if not asset:return self.send(404,'Не найдено','text/plain')
            return self.send(200,(ROOT/'static'/asset).read_bytes(),{'index.html':'text/html; charset=utf-8','app.js':'text/javascript; charset=utf-8','qrcode.js':'text/javascript; charset=utf-8','style.css':'text/css; charset=utf-8'}[asset])
        except (ValueError,KeyError) as e:self.send(400,dict(error=str(e)))
        except Exception:self.send(500,dict(error='Внутренняя ошибка; проверьте доступность хранилища и Docker'))
    def do_POST(self):
        path=self.route()
        if path is None:return
        # Browser requests must originate from this host; also require a non-simple JSON content type.
        if self.headers.get('Content-Type','').split(';')[0]!='application/json':return self.send(415,dict(error='Нужен application/json'))
        origin=self.headers.get('Origin')
        if origin and urlsplit(origin).netloc!=self.headers.get('Host'):return self.send(403,dict(error='Недопустимый источник'))
        try:
            size=int(self.headers.get('Content-Length','0'))
            if not 0<size<=16_000_000:raise ValueError('Недопустимый размер запроса')
            data=json.loads(self.rfile.read(size))
            if not isinstance(data,dict):raise ValueError('Нужен JSON-объект')
            if path=='/api/login':
                ip=self.client_address[0]
                if ip in ('127.0.0.1','::1'):ip=self.headers.get('X-Real-IP',ip)
                with LOCK:session=auth.login(data.get('username',''),data.get('password',''),ip)
                if not session:return self.send(401,dict(error='Неверный логин или пароль'))
                return self.send(200,{},headers={'Set-Cookie':self.cookie(session)})
            if path=='/api/logout':
                auth.logout(self.session_token())
                return self.send(200,{},headers={'Set-Cookie':self.cookie('',0)})
            if not self.auth():return self.send(401,dict(error='Требуется вход'))
            with LOCK:result=mutate(path,data)
            self.send(200,result)
        except (ValueError,KeyError,TypeError,subprocess.SubprocessError) as e:self.send(400,dict(error=str(e)))
        except Exception:self.send(500,dict(error='Не удалось выполнить операцию; проверьте хранилище и Docker'))

if __name__=='__main__':
    os.umask(0o077);created=init()
    host=os.environ.get('YPTUN_HOST','127.0.0.1');port=int(os.environ.get('YPTUN_PORT','8080'))
    print(f"panel for YPtun: http://{host}:{port}{auth.CONFIG['base_path']}/",flush=True)
    if created:print('Создан администратор: '+created['username']+' / '+created['password'],flush=True)
    ThreadingHTTPServer((host,port),Handler).serve_forever()
