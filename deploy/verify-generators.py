#!/usr/bin/env python3
"""Disposable Docker smoke tests; use a separate DATA directory, never production data.

Run as the panel user with YPTUN_ALLOW_DOCKER=1. No production certificates
are read; a disposable self-signed certificate is generated for TrustTunnel.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server,subscriptions

if os.environ.get('YPTUN_ALLOW_DOCKER')!='1':raise SystemExit('Requires YPTUN_ALLOW_DOCKER=1')
if not os.environ.get('YPTUN_VERIFY_DATA'):raise SystemExit('Set a separate YPTUN_VERIFY_DATA directory')
server.DATA=Path(os.environ['YPTUN_VERIFY_DATA']).resolve()
if (server.DATA/'panel.sqlite3').exists():raise SystemExit('Verification directory must be empty')
os.umask(0o077);server.init()
protocols=sys.argv[1:] or ['wireguard','amneziawg','snolc','masterdns','trusttunnel','vkturn','warp']
failed=[]
with tempfile.TemporaryDirectory() as tmp:
    cert=Path(tmp)/'cert';key=Path(tmp)/'key'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=verify.example.invalid','-addext','subjectAltName=DNS:verify.example.invalid','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
    person=server.mutate('/api/people',dict(name='Disposable verification'))
    for p in protocols:
        service=None
        try:
            data=dict(protocol=p,name='Disposable '+p,host='127.0.0.1',simple_engine=True)
            if p=='masterdns':data['dns_domain']='verify.example.invalid'
            if p=='trusttunnel':data.update(certificate=cert.read_text(),private_key=key.read_text(),sni='verify.example.invalid')
            service=server.mutate('/api/services',data)
            user=server.mutate('/api/people/'+person['id']+'/grant',dict(service_id=service['id'],vk_hash='verification_hash'))
            # Ensure public subscription can serialize the generated profile.
            assert subscriptions.link(service,user)
            server.mutate('/api/services/'+service['id']+'/start',{})
            time.sleep(4)
            state=server.compose(service,['ps','--all','--format','json'])
            items=json.loads(state) if state.strip().startswith('[') else [json.loads(line) for line in state.splitlines() if line.strip()]
            if not items or not all(x.get('State')=='running' for x in items):raise ValueError('A container failed to stay running')
            # A running status alone does not prove configs were loaded: wait and detect restarts.
            ids=server.compose(service,['ps','-q']).split()
            inspected=json.loads(subprocess.run(['docker','inspect',*ids],check=True,capture_output=True,text=True).stdout)
            if any(x.get('RestartCount') for x in inspected):raise ValueError('Container is restarting')
            if p in ('wireguard','amneziawg','vkturn'):
                target='backend' if p=='vkturn' else 'tunnel'
                tool='awg' if p=='amneziawg' else 'wg'
                peers=server.compose(service,['exec','-T',target,tool,'show','wg0','peers']).strip()
                if user['wg_public'] not in peers:raise ValueError('Generated peer not loaded by WireGuard')
            if p=='trusttunnel':
                import socket,ssl
                context=ssl.create_default_context(cadata=cert.read_text());context.check_hostname=False
                with socket.create_connection(('127.0.0.1',service['port']),timeout=10) as sock:
                    with context.wrap_socket(sock,server_hostname='verify.example.invalid') as tls:assert tls.version()
            print(p+': container/config/profile OK',flush=True)
            server.mutate('/api/users/'+user['id']+'/toggle',{})
            if server.running(service):raise ValueError('Last-access revocation left listener running')
            print(p+': last-access revocation OK',flush=True)
        except Exception as error:
            failed.append(p)
            # Error details/logs stay in the private verification directory; never print keys.
            if service:
                try:
                    log=server.compose(service,['logs','--no-color','--tail','100'])
                    (server.DATA/(p+'-failure.log')).write_text(str(error)+'\n'+log)
                except Exception:pass
            print(p+': FAILED; inspect private '+str(server.DATA/(p+'-failure.log')),flush=True)
        finally:
            if service:
                try:server.compose(service,['down','-v'],90)
                except Exception:print(p+': cleanup requires attention',flush=True)
if failed:raise SystemExit('Failed: '+', '.join(failed))
