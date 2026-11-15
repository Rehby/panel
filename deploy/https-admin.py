#!/usr/bin/python3
"""Root-owned, fixed-purpose nginx/certbot helper. Accepts one JSON object on stdin."""
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

CONFIG=Path('/etc/yptun-panel')
NGINX=Path('/etc/nginx/conf.d/yptun-panel.conf')
WEBROOT=Path('/var/lib/yptun-acme')
CERTS=CONFIG/'certificates'


def run(args,**kw):
    p=subprocess.run(args,capture_output=True,text=True,timeout=240,**kw)
    if p.returncode:raise ValueError((p.stderr or p.stdout)[-2500:])
    return p.stdout


def hostname(value):
    try:return str(ipaddress.ip_address(value)),True
    except ValueError:
        if not re.fullmatch(r'(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}',value):raise ValueError('Укажите публичный домен или IP без схемы и порта')
        return value.lower(),False


def nginx_config(host,prefix,cert=None,key=None):
    urlhost='['+host+']' if ':' in host else host
    http=f'''server {{
    listen 80;
    listen [::]:80;
    server_name {host};
    location ^~ /.well-known/acme-challenge/ {{ root {WEBROOT}; }}
    location / {{ return 308 https://{urlhost}$request_uri; }}
}}
'''
    if not cert:return http
    tls=f'''ssl_certificate {cert};
    ssl_certificate_key {key};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    http2 on;
'''
    return http+f'''server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {host};
    {tls}
    client_max_body_size 16m;
    location ^~ /subscription/ {{
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
    location ^~ /turn-sub/ {{
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
    }}
    location = {prefix} {{ return 308 {prefix}/; }}
    location ^~ {prefix}/ {{
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;
    }}
    location / {{ root /var/www/yptun-cover; try_files $uri $uri/ =404; }}
}}
server {{
    listen 127.0.0.1:9443 ssl;
    server_name {host};
    {tls}
    root /var/www/yptun-cover;
    location / {{ try_files $uri $uri/ =404; }}
}}
'''


def reload_nginx(text):
    old=NGINX.read_text() if NGINX.exists() else None
    NGINX.write_text(text)
    try:run(['nginx','-t']);run(['systemctl','reload','nginx'])
    except Exception:
        if old is None:NGINX.unlink(missing_ok=True)
        else:NGINX.write_text(old)
        raise


def apply(data):
    host,is_ip=hostname(str(data.get('host','')))
    mode=data.get('mode')
    if mode not in ('domain','ip','upload'):raise ValueError('Неизвестный способ HTTPS')
    if mode=='domain' and is_ip:raise ValueError('Для Let’s Encrypt в этом режиме нужен домен; для IP выберите IP или свой сертификат')
    if mode=='ip' and not is_ip:raise ValueError('Для IP-сертификата укажите IP')
    deploy=json.loads((CONFIG/'deploy.json').read_text());prefix=deploy['base_path']
    if not re.fullmatch(r'/[A-Za-z0-9_-]{16,100}',prefix):raise ValueError('Некорректный путь панели')
    WEBROOT.mkdir(parents=True,exist_ok=True);CERTS.mkdir(mode=0o700,exist_ok=True)
    old=NGINX.read_text() if NGINX.exists() else None
    try:
        if mode=='domain':
            if not old:reload_nginx(nginx_config(host,prefix))
            else:
                # Keep the old HTTPS site reachable while adding the new HTTP challenge host.
                challenge=nginx_config(host,prefix)
                if host not in old:reload_nginx(old+challenge)
            run(['certbot','certonly','--webroot','-w',str(WEBROOT),'--non-interactive','--agree-tos','--register-unsafely-without-email','--cert-name','yptun-panel','--expand','-d',host])
            cert=Path('/etc/letsencrypt/live/yptun-panel/fullchain.pem');key=Path('/etc/letsencrypt/live/yptun-panel/privkey.pem')
        else:
            # New immutable generation avoids replacing files in use until nginx validates.
            directory=Path(tempfile.mkdtemp(prefix='tls-',dir=CERTS));os.chmod(directory,0o700)
            cert=directory/'fullchain.pem';key=directory/'privkey.pem'
            if mode=='ip':
                run(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','365','-keyout',str(key),'-out',str(cert),'-subj','/CN='+host,'-addext','subjectAltName=IP:'+host])
            else:
                cert.write_text(str(data.get('certificate','')));key.write_text(str(data.get('private_key','')))
                run(['openssl','x509','-in',str(cert),'-noout','-checkend','0'])
                match=run(['openssl','x509','-in',str(cert),'-noout','-checkip' if is_ip else '-checkhost',host])
                if 'does NOT match' in match:raise ValueError('Сертификат не соответствует домену/IP')
                pub=run(['openssl','x509','-in',str(cert),'-noout','-pubkey'])
                if pub!=run(['openssl','pkey','-in',str(key),'-pubout']):raise ValueError('Сертификат и приватный ключ не совпадают')
            os.chmod(cert,0o600);os.chmod(key,0o600)
        reload_nginx(nginx_config(host,prefix,cert,key))
        trusted=mode=='domain'
        if mode=='upload':
            try:run(['openssl','verify','-untrusted',str(cert),str(cert)]);trusted=True
            except ValueError:trusted=False
        result=dict(host=host,mode=mode,trusted=trusted,self_sni_ready=not is_ip and trusted,base_path=prefix,certificate=str(cert),updated=__import__('time').time())
        tmp=CONFIG/'https.json.tmp';tmp.write_text(json.dumps(result));os.chmod(tmp,0o644);tmp.replace(CONFIG/'https.json')
        return result
    except Exception:
        if old is not None:reload_nginx(old)
        elif NGINX.exists():NGINX.unlink();run(['systemctl','reload','nginx'])
        raise


def certificate_registry():
    path=CONFIG/'service-certificates.json'
    return json.loads(path.read_text()) if path.exists() else {}


def read_service_certificate(id):
    if not re.fullmatch(r'[a-f0-9]{24}',str(id)):raise ValueError('Некорректный ID сертификата')
    entry=certificate_registry().get(id)
    if not entry:raise ValueError('Сертификат не найден')
    return dict(certificate_id=id,host=entry['host'],mode=entry['mode'],certificate=Path(entry['cert']).read_text(),private_key=Path(entry['key']).read_text(),expires=run(['openssl','x509','-in',entry['cert'],'-noout','-enddate']).strip())


def service_certificate(data):
    import hashlib
    import socket
    host,is_ip=hostname(str(data.get('host','')));mode=data.get('mode','domain')
    if mode not in ('domain','ip'):raise ValueError('Выберите домен или IP')
    if (mode=='ip')!=is_ip:raise ValueError('Способ выпуска не соответствует домену/IP')
    id=hashlib.sha256((mode+':'+host).encode()).hexdigest()[:24]
    if mode=='domain':
        ips={x[4][0] for x in socket.getaddrinfo(host,80,type=socket.SOCK_STREAM)}
        addresses=json.loads(run(['ip','-j','address','show']))
        local={a['local'] for iface in addresses for a in iface.get('addr_info',[]) if a.get('scope')=='global'}
        if not ips.intersection(local):raise ValueError('DNS домена должен указывать на IP этого сервера')
        WEBROOT.mkdir(parents=True,exist_ok=True)
        panel=json.loads((CONFIG/'https.json').read_text()) if (CONFIG/'https.json').exists() else {}
        if panel.get('host')!=host:
            challenge=Path('/etc/nginx/conf.d/yptun-acme-'+id+'.conf')
            challenge.write_text(f'server {{ listen 80; listen [::]:80; server_name {host}; location ^~ /.well-known/acme-challenge/ {{ root {WEBROOT}; }} location / {{ return 404; }} }}')
            run(['nginx','-t']);run(['systemctl','reload','nginx'])
        name='yptun-service-'+id
        run(['certbot','certonly','--webroot','-w',str(WEBROOT),'--non-interactive','--agree-tos','--register-unsafely-without-email','--cert-name',name,'-d',host])
        cert=Path('/etc/letsencrypt/live')/name/'fullchain.pem';key=cert.parent/'privkey.pem'
    else:
        directory=CONFIG/'service-certs'/id;directory.mkdir(mode=0o700,parents=True,exist_ok=True)
        cert=directory/'fullchain.pem';key=directory/'privkey.pem'
        renew=not cert.exists() or subprocess.run(['openssl','x509','-in',str(cert),'-noout','-checkend','2592000'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode!=0
        if renew:
            run(['openssl','req','-x509','-newkey','rsa:3072','-sha256','-nodes','-days','365','-keyout',str(key),'-out',str(cert),'-subj','/CN='+host,'-addext','subjectAltName=IP:'+host])
        os.chmod(key,0o600)
    registry=certificate_registry();registry[id]=dict(host=host,mode=mode,cert=str(cert),key=str(key))
    temp=CONFIG/'service-certificates.tmp';temp.write_text(json.dumps(registry));os.chmod(temp,0o600);temp.replace(CONFIG/'service-certificates.json')
    return read_service_certificate(id)

if __name__=='__main__':
    try:
        if os.geteuid()!=0:raise ValueError('Helper требует root')
        raw=sys.stdin.read(2_000_001)
        if len(raw)>2_000_000:raise ValueError('Слишком большой запрос')
        data=json.loads(raw);action=data.get('action','https')
        if action=='service-certificate':result=service_certificate(data)
        elif action=='read-service-certificate':result=read_service_certificate(data.get('certificate_id'))
        elif action=='https':result=apply(data)
        else:raise ValueError('Неизвестная операция helper')
        print(json.dumps(result))
    except Exception as e:
        print(json.dumps(dict(error=str(e))),file=sys.stderr);sys.exit(1)
