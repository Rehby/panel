#!/usr/bin/python3
"""Renewal hook: refresh services bound to managed VPN or panel certificates."""
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess

DATA=Path('/var/lib/yptun-panel')
REGISTRY=Path('/etc/yptun-panel/service-certificates.json')
PANEL=Path('/etc/yptun-panel/https.json')

def sync_certificates():
    if (DATA/'panel.sqlite3').exists():
        registry=json.loads(REGISTRY.read_text()) if REGISTRY.exists() else {}
        if PANEL.exists():
            panel=json.loads(PANEL.read_text());cert=Path(panel['certificate'])
            registry['panel']=dict(cert=str(cert),key=str(cert.parent/'privkey.pem'))
        with sqlite3.connect(DATA/'panel.sqlite3') as db:
            for id,body in db.execute("SELECT id,value FROM objects WHERE kind='service'").fetchall():
                service=json.loads(body);cert=registry.get(service.get('certificate_id'))
                if not cert or service.get('security')!='tls' or not re.fullmatch('[a-f0-9]{16}',id):continue
                newcert=Path(cert['cert']).read_text();newkey=Path(cert['key']).read_text()
                if service.get('certificate')==newcert and service.get('private_key')==newkey:continue
                directory=DATA/id
                if not directory.is_dir() or directory.is_symlink():continue
                stat=directory.stat()
                names=[('cert.pem',newcert),('key.pem',newkey)]
                if service.get('provisioned') and service.get('protocol')=='trusttunnel':names=[('runtime/cert.pem',newcert),('runtime/key.pem',newkey)]
                for name,text in names:
                    target=directory/name
                    if target.is_symlink():raise RuntimeError('Refusing symlink certificate target')
                    target.write_text(text);os.chmod(target,0o600);os.chown(target,stat.st_uid,stat.st_gid)
                service.update(certificate=newcert,private_key=newkey)
                db.execute('UPDATE objects SET value=? WHERE id=?',(json.dumps(service),id))
                if service.get('desired')=='running':
                    subprocess.run(['docker','compose','-p','yptun-'+id,'-f',str(directory/'compose.json'),'up','-d','--force-recreate'],check=True,timeout=120)
                print('Renewed service certificate:',id)

if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('root required')
    sync_certificates()
