"""Persistent per-access byte counters and a shared per-person traffic allowance."""
import datetime
import hashlib
import http.client
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time

INTERVAL=10


def kind(s):
    p=s['protocol']
    if p=='wdtt':return 'wdtt'
    if p=='webproxy':return 'webproxy'
    if p in ('vless','vmess','trojan','shadowsocks') or p=='warp' and s.get('provisioned'):return 'xray'
    if p in ('wireguard','amneziawg','vkturn') and s.get('provisioned'):return 'wireguard'
    return None


def init(c):
    c.execute('''CREATE TABLE IF NOT EXISTS traffic (
        user_id TEXT PRIMARY KEY,person_id TEXT NOT NULL,service_id TEXT NOT NULL,
        upload INTEGER NOT NULL DEFAULT 0,download INTEGER NOT NULL DEFAULT 0,
        epoch TEXT NOT NULL,last_upload INTEGER NOT NULL,last_download INTEGER NOT NULL,
        sampled_at INTEGER NOT NULL)''')
    c.execute('CREATE INDEX IF NOT EXISTS traffic_person ON traffic(person_id)')
    columns={row[1] for row in c.execute('PRAGMA table_info(traffic)')}
    for name,definition in [('lifetime_upload','INTEGER NOT NULL DEFAULT 0'),('lifetime_download','INTEGER NOT NULL DEFAULT 0'),('day','TEXT NOT NULL DEFAULT ""'),('day_upload','INTEGER NOT NULL DEFAULT 0'),('day_download','INTEGER NOT NULL DEFAULT 0')]:
        if name not in columns:
            c.execute('ALTER TABLE traffic ADD COLUMN '+name+' '+definition)
            if name in ('lifetime_upload','lifetime_download'):c.execute('UPDATE traffic SET '+name+'='+name[len('lifetime_'):])



def configure(s,files):
    """Instrument generated configs; never modify an imported raw config."""
    core=kind(s)
    if core=='webproxy':
        files['relay.toml']+='\n[admin]\nlisten = "/run/yptun/metrics.sock"\n'
        compose=json.loads(files['compose.json'])
        compose['services']['tunnel']['volumes'].append('./runtime:/run/yptun')
        files['compose.json']=json.dumps(compose,indent=2)
    elif core=='xray':
        config=json.loads(files['config.json'])
        config['stats']={}
        config['policy']=dict(levels={'0':dict(statsUserUplink=True,statsUserDownlink=True)},system=dict(statsInboundUplink=True,statsInboundDownlink=True))
        config['api']=dict(tag='traffic-api',listen='127.0.0.1:'+str(s.get('stats_port',10085 if s['port']!=10085 else 10086)),services=['StatsService'])
        files['config.json']=json.dumps(config,indent=2)
    return files


def xray_counters(text,users,shadowsocks=False):
    result={u['id']:[0,0] for u in users}
    payload=json.loads(text)
    for stat in payload.get('stat',[]):
        parts=stat['name'].split('>>>')
        if len(parts)!=4 or parts[2]!='traffic' or parts[3] not in ('uplink','downlink'):continue
        id=parts[1] if parts[0]=='user' else next(iter(result),None) if shadowsocks and parts[:2]==['inbound','in'] else None
        if id in result:result[id][parts[3]=='downlink']+=int(stat.get('value',0))
    return result


def webproxy_counters(text,users):
    result={u['id']:[0,0] for u in users}
    for line in text.splitlines():
        match=re.fullmatch(r'tgwp_bytes_(up|down)_total\{([^}]+)\}\s+(\d+)',line)
        if not match:continue
        label=re.search(r'(?:^|,)label="([a-zA-Z0-9_-]+)"(?:,|$)',match[2])
        if label and label[1] in result:result[label[1]][match[1]=='down']+=int(match[3])
    return result


class UnixHTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.host)


def collect(panel,s):
    """Snapshot cumulative counters and the container generation without resetting either."""
    core=kind(s)
    if not core:return
    users=panel.members(s['id'])
    if core=='wdtt':
        import wdtt
        counters=wdtt.counters(panel.turn_request(s),users)
        # The core persists these counters in passwords.json across restarts.
        epochs={u['id']:'wdtt:'+hashlib.sha256(u['password'].encode()).hexdigest() for u in users}
        record(panel,s,users,counters,epochs,persistent=True)
        return
    container_service='backend' if s['protocol']=='vkturn' else 'tunnel'
    container=panel.compose(s,['ps','-q',container_service],10).strip()
    if not container:raise ValueError('Контейнер со счётчиками остановлен')
    inspect_args=['docker','inspect','--format','{{.Id}}:{{.State.StartedAt}}',container]
    inspected=subprocess.run(inspect_args,capture_output=True,text=True,timeout=10)
    if inspected.returncode:raise ValueError('Не удалось получить поколение контейнера')
    epoch=inspected.stdout.strip()
    if not epoch:raise ValueError('Пустое поколение контейнера')
    if core=='xray':
        text=panel.compose(s,['exec','-T','tunnel','xray','api','statsquery','--server=127.0.0.1:'+str(s.get('stats_port',10085))],10)
        counters=xray_counters(text,users,s['protocol']=='shadowsocks')
    elif core=='webproxy':
        conn=UnixHTTPConnection(str(panel.DATA/s['id']/'runtime'/'metrics.sock'),timeout=5)
        try:
            conn.request('GET','/metrics');response=conn.getresponse()
            if response.status!=200:raise ValueError('WebProxy metrics недоступны')
            counters=webproxy_counters(response.read(4_000_000).decode(),users)
        finally:conn.close()
    else:
        command='awg' if s['protocol']=='amneziawg' else 'wg'
        text=panel.compose(s,['exec','-T',container_service,command,'show','wg0','transfer'],10)
        by_key={u.get('wg_public'):u['id'] for u in users};counters={u['id']:[0,0] for u in users}
        for line in text.splitlines():
            key,up,down=line.split()
            if key in by_key:counters[by_key[key]]=[int(up),int(down)]
    # A restart during the read invalidates the snapshot; retry on the next poll.
    check=subprocess.run(inspect_args,capture_output=True,text=True,timeout=10)
    if check.returncode or check.stdout.strip()!=epoch:raise ValueError('Контейнер перезапустился во время чтения счётчиков')
    record(panel,s,users,counters,epoch)


def day_key(now=None):
    return datetime.datetime.fromtimestamp(time.time() if now is None else now).date().isoformat()


def record(panel,s,users,counters,epoch,persistent=False):
    now=int(time.time());today=day_key(now)
    with panel.db() as c:
        for u in users:
            if u['id'] not in counters:continue
            up,down=counters[u['id']]
            if up<0 or down<0:raise ValueError('Отрицательный счётчик трафика')
            generation=epoch[u['id']] if isinstance(epoch,dict) else epoch
            old=c.execute('SELECT epoch,last_upload,last_download,day,day_upload,day_download FROM traffic WHERE user_id=?',(u['id'],)).fetchone()
            delta_up=up-old[1] if old and old[0]==generation and up>=old[1] else up
            delta_down=down-old[2] if old and old[0]==generation and down>=old[2] else down
            # Historical WDTT bytes on the first import have no known date.
            today_up=0 if old is None and persistent else delta_up
            today_down=0 if old is None and persistent else delta_down
            if old and old[3]==today:today_up+=old[4];today_down+=old[5]
            c.execute('''INSERT INTO traffic
                (user_id,person_id,service_id,upload,download,epoch,last_upload,last_download,sampled_at,lifetime_upload,lifetime_download,day,day_upload,day_download)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET
                upload=upload+excluded.upload,download=download+excluded.download,
                lifetime_upload=lifetime_upload+excluded.lifetime_upload,lifetime_download=lifetime_download+excluded.lifetime_download,
                epoch=excluded.epoch,last_upload=excluded.last_upload,last_download=excluded.last_download,sampled_at=excluded.sampled_at,
                day=excluded.day,day_upload=excluded.day_upload,day_download=excluded.day_download''',
                (u['id'],u['person_id'],s['id'],delta_up,delta_down,generation,up,down,now,delta_up,delta_down,today,today_up,today_down))


def summary(panel,person):
    users=[u for u in panel.rows('user') if u.get('person_id')==person['id']]
    services={s['id']:s for s in panel.rows('service')}
    unsupported=[services[u['service_id']]['name'] for u in users if u['service_id'] in services and not kind(services[u['service_id']])]
    errors={s['id']:[message for message in (s.get('traffic_error'),s.get('quota_sync_error')) if message] for s in services.values()}
    with panel.db() as c:
        up,down,at=c.execute('SELECT coalesce(sum(upload),0),coalesce(sum(download),0),max(sampled_at) FROM traffic WHERE person_id=?',(person['id'],)).fetchone()
    with panel.db() as c:
        lifetime_up,lifetime_down,today_up,today_down=c.execute('SELECT coalesce(sum(lifetime_upload),0),coalesce(sum(lifetime_download),0),coalesce(sum(CASE WHEN day=? THEN day_upload ELSE 0 END),0),coalesce(sum(CASE WHEN day=? THEN day_download ELSE 0 END),0) FROM traffic WHERE person_id=?',(day_key(),day_key(),person['id'])).fetchone()
        current={row[0]:row[1:] for row in c.execute('SELECT user_id,last_upload,last_download FROM traffic WHERE person_id=?',(person['id'],))}
    current_up=sum(current.get(u['id'],(0,0))[0] for u in users);current_down=sum(current.get(u['id'],(0,0))[1] for u in users)
    return dict(lifetime_upload=lifetime_up,lifetime_download=lifetime_down,lifetime_total=lifetime_up+lifetime_down,today_upload=today_up,today_download=today_down,today_total=today_up+today_down,current_upload=current_up,current_download=current_down,current_total=current_up+current_down,day=day_key(),upload=up,download=down,total=up+down,limit=person.get('traffic_limit',0),blocked=bool(person.get('quota_exceeded')),updated_at=at,unsupported=sorted(set(unsupported)),pending=any(services.get(u['service_id'],{}).get('quota_sync_pending') for u in users),errors=sorted({message for u in users for message in errors.get(u['service_id'],[])}))


def access_summary(panel,u):
    with panel.db() as c:
        row=c.execute('SELECT last_upload,last_download,day,day_upload,day_download,lifetime_upload,lifetime_download,sampled_at FROM traffic WHERE user_id=?',(u['id'],)).fetchone()
    if row is None:return dict(updated_at=None)
    up,down,day,today_up,today_down,lifetime_up,lifetime_down,at=row
    if day!=day_key():today_up=today_down=0
    return dict(current_upload=up,current_download=down,current_total=up+down,today_upload=today_up,today_download=today_down,today_total=today_up+today_down,lifetime_upload=lifetime_up,lifetime_download=lifetime_down,lifetime_total=lifetime_up+lifetime_down,updated_at=at)


def validate_limit(panel,person,value):
    if isinstance(value,bool) or not (isinstance(value,int) or isinstance(value,str) and re.fullmatch(r'[0-9]+',value)):
        raise ValueError('Лимит трафика: укажите целое число байт, 0 — без лимита')
    limit=int(value)
    if not 0<=limit<=1_000_000*1024**3:raise ValueError('Лимит трафика: от 0 до 1000000 ГиБ')
    if limit and summary(panel,person)['unsupported']:raise ValueError('Лимит недоступен: у пользователя есть подключения без учёта трафика')
    return limit


def enforce(panel):
    """Persist blocks first; retry failed core updates on every polling cycle."""
    changed=set()
    for person in panel.rows('person'):
        data=summary(panel,person)
        blocked=bool(data['limit'] and data['total']>=data['limit'])
        if bool(person.get('quota_exceeded'))!=blocked:
            person['quota_exceeded']=blocked;panel.put('person',person)
            panel.event(('Достигнут лимит трафика: ' if blocked else 'Снят лимит трафика: ')+person['name'])
        for u in panel.rows('user'):
            if u.get('person_id')==person['id'] and bool(u.get('quota_blocked'))!=blocked:
                u['quota_blocked']=blocked;panel.put('user',u);changed.add(u['service_id'])
    for s in panel.rows('service'):
        if s['id'] in changed or s.get('quota_sync_pending'):
            if s.get('quota_stopped') and any(u.get('enabled',True) and not u.get('quota_blocked') for u in panel.members(s['id'])):
                s['desired']='running';s.pop('quota_stopped',None)
            s['quota_sync_pending']=True;panel.put('service',s)
            try:
                if s['protocol']=='wdtt':
                    import wdtt
                    wdtt.sync_limits(panel,s)
                else:panel.sync(s)
                s=panel.get(s['id'],'service');s.pop('quota_sync_pending',None);s.pop('quota_sync_error',None);panel.put('service',s)
            except (ValueError,OSError,subprocess.SubprocessError):
                s['quota_sync_error']='Не удалось применить лимит к службе; повторная попытка через 10 секунд';panel.put('service',s)


def snapshot(panel,s):
    if kind(s) and s.get('traffic_enabled') and s.get('desired')=='running' and os.environ.get('YPTUN_ALLOW_DOCKER')=='1':
        try:collect(panel,s)
        except (ValueError,OSError,KeyError,subprocess.SubprocessError,http.client.HTTPException):pass


def poll(panel):
    with panel.LOCK:
        for s in panel.rows('service'):
            if not kind(s) or s.get('desired')!='running':continue
            try:
                if not s.get('traffic_enabled'):
                    panel.telemetry_defaults(s)
                    if kind(s)!='wdtt':panel.sync(s)
                    s['traffic_enabled']=True;panel.put('service',s)
                collect(panel,s)
                if s.pop('traffic_error',None):panel.put('service',s)
            except (ValueError,OSError,KeyError,subprocess.SubprocessError,http.client.HTTPException):
                s['traffic_error']='Нет свежей статистики; проверьте журнал службы';panel.put('service',s)
        enforce(panel)


def start(panel):
    if os.environ.get('YPTUN_ALLOW_DOCKER')!='1':return
    def work():
        while True:
            try:poll(panel)
            except Exception:
                # Keep the quota worker alive after temporary storage / Docker failures.
                logging.exception('Ошибка учёта трафика')
            time.sleep(INTERVAL)
    threading.Thread(target=work,name='traffic-accounting',daemon=True).start()
