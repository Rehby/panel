#!/usr/bin/python3
"""Install a checked-out panel on a fresh Linux VPS; run as root after installing dependencies."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT=Path('/opt/yptun-panel')

def run(args,**kwargs):return subprocess.run(args,check=True,text=True,**kwargs)

def install():
    if os.geteuid()!=0:raise SystemExit('Run as root')
    if not (ROOT/'server.py').exists():raise SystemExit('Copy the source to /opt/yptun-panel first')
    if subprocess.run(['id','yptun'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode:
        run(['useradd','--system','--home-dir','/var/lib/yptun-panel','--create-home','--shell','/usr/sbin/nologin','yptun'])
    run(['usermod','-aG','docker','yptun'])
    data=Path('/var/lib/yptun-panel');data.mkdir(mode=0o700,exist_ok=True);shutil.chown(data,user='yptun',group='yptun');os.chmod(data,0o700)
    config=Path('/etc/yptun-panel');config.mkdir(mode=0o755,exist_ok=True)
    script="import sys,json;sys.path.insert(0,'/opt/yptun-panel');import server;created=server.init();print(json.dumps(dict(created=created,base_path=server.auth.CONFIG['base_path'],username=server.auth.CONFIG['username'])))"
    result=run(['runuser','-u','yptun','--','env','YPTUN_DATA='+str(data),'python3','-B','-c',script],capture_output=True)
    info=json.loads(result.stdout)
    (config/'deploy.json').write_text(json.dumps(dict(base_path=info['base_path'])));os.chmod(config/'deploy.json',0o644)
    env=Path('/etc/yptun-panel.env');env.write_text('YPTUN_DATA=/var/lib/yptun-panel\nYPTUN_ALLOW_DOCKER=1\nYPTUN_HTTPS=1\nYPTUN_HTTPS_HELPER=1\nYPTUN_HOST=127.0.0.1\nYPTUN_PORT=8080\n');os.chmod(env,0o600)
    helper=Path('/usr/local/sbin/yptun-https');shutil.copyfile(ROOT/'deploy'/'https-admin.py',helper);os.chmod(helper,0o755)
    sync=Path('/usr/local/sbin/yptun-cert-sync');shutil.copyfile(ROOT/'deploy'/'cert-sync.py',sync);os.chmod(sync,0o755)
    sudoers=Path('/etc/sudoers.d/yptun-https');sudoers.write_text('yptun ALL=(root) NOPASSWD: /usr/local/sbin/yptun-https ""\n');os.chmod(sudoers,0o440);run(['visudo','-cf',str(sudoers)])
    shutil.copyfile(ROOT/'deploy'/'yptun-panel.service','/etc/systemd/system/yptun-panel.service')
    cover=Path('/var/www/yptun-cover');cover.mkdir(parents=True,exist_ok=True)
    (cover/'index.html').write_text('<!doctype html><html lang="en"><meta name="viewport" content="width=device-width"><title>Network services</title><style>body{font:17px system-ui;max-width:640px;margin:15vh auto;padding:24px;color:#263c32;background:#f4f6f1}h1{font-weight:500;font-size:40px}p{line-height:1.8;color:#6d8070}</style><h1>Network services</h1><p>Private infrastructure. Reliable connections.</p></html>')
    hook=Path('/etc/letsencrypt/renewal-hooks/deploy/yptun-nginx');hook.parent.mkdir(parents=True,exist_ok=True);hook.write_text('#!/bin/sh\n/usr/sbin/nginx -t && /usr/bin/systemctl reload nginx\n/usr/local/sbin/yptun-cert-sync\n');os.chmod(hook,0o755)
    run(['systemctl','daemon-reload']);run(['systemctl','enable','--now','docker','nginx','certbot.timer']);run(['systemctl','enable','yptun-panel']);run(['systemctl','restart','yptun-panel'])
    print(json.dumps(info))

if __name__=='__main__':install()
