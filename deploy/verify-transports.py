#!/usr/bin/env python3
"""Parse generated server and client configs with the actual image. Uses ephemeral test keys only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import engine
from transports import TRANSPORTS,client_config

image='ghcr.io/xtls/xray-core:26.9.30'
failures=0
with tempfile.TemporaryDirectory(prefix='yptun-transport-check-') as tmp:
    root=Path(tmp)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-keyout',str(root/'key.pem'),'-out',str(root/'cert.pem'),'-subj','/CN=transport-test.invalid','-addext','subjectAltName=DNS:transport-test.invalid'],check=True,capture_output=True)
    for n,t in enumerate(TRANSPORTS):
        if 'vless' not in t.get('protocols',['vless']):continue
        for security in t['security']:
            s=dict(protocol='vless',name='Validation',host='transport-test.invalid',sni='transport-test.invalid',port=19443+n,transport=t['id'],security=security,certificate=(root/'cert.pem').read_text(),private_key=(root/'key.pem').read_text())
            if t['id']=='xdrive':s['transport_settings']=dict(service='local',remoteFolder='/tmp/xdrive-test')
            s=engine.validate(s);u=dict(id='validation',name='validation',**engine.credential())
            files=engine.bundle(s,[u])
            for name,body in files.items():(root/name).write_text(body)
            (root/'client.json').write_text(json.dumps(client_config(s,u)))
            for side in ('config','client'):
                result=subprocess.run(['docker','run','--rm','--user',str(os.getuid())+':'+str(os.getgid()),'-v',str(root)+':/etc/yptun:ro',image,'run','-test','-config','/etc/yptun/'+side+'.json'],capture_output=True,text=True,timeout=30)
                if result.returncode:failures+=1
                print(t['id'],security,side,'OK' if result.returncode==0 else (result.stdout+result.stderr)[-1500:],flush=True)
print('Failures:',failures)
sys.exit(bool(failures))
