import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('https_admin',Path(__file__).resolve().parents[1]/'deploy'/'https-admin.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
spec=importlib.util.spec_from_file_location('cert_sync',Path(__file__).resolve().parents[1]/'deploy'/'cert-sync.py')
sync=importlib.util.module_from_spec(spec);spec.loader.exec_module(sync)

class HTTPSTest(unittest.TestCase):
    def test_host_validation(self):
        self.assertEqual(helper.hostname('vpn.example.com'),('vpn.example.com',False))
        self.assertEqual(helper.hostname('2.56.119.128'),('2.56.119.128',True))
        for host in ['x; return 200;', 'https://x.com','x.com\nssl_verify off;', '../foo','']:
            with self.assertRaises(ValueError):helper.hostname(host)
    def test_hidden_proxy_and_local_decoy(self):
        config=helper.nginx_config('vpn.example.com','/random-secret-path','/cert.pem','/key.pem')
        self.assertIn('location ^~ /random-secret-path/',config)
        self.assertIn('listen 127.0.0.1:9443 ssl http2;',config)
        self.assertIn('listen 443 ssl http2;',config)
        self.assertIn('listen [::]:443 ssl http2;',config)
        self.assertNotIn('listen 9443',config)
        self.assertIn('location / { root /var/www/yptun-cover;',config)
    def test_panel_certificate_can_be_read_and_renewed_for_bound_services(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);data=root/'data';data.mkdir()
            cert=root/'fullchain.pem';cert.write_text('renewed certificate')
            key=root/'privkey.pem';key.write_text('renewed key')
            status=root/'https.json';status.write_text(json.dumps(dict(host='panel.example.com',mode='domain',certificate=str(cert))))
            with patch.object(helper,'CONFIG',root):
                result=helper.read_panel_certificate()
                self.assertEqual(result['private_key'],'renewed key')
                self.assertEqual(result['host'],'panel.example.com')
            service=dict(certificate_id='panel',security='tls',certificate='old',private_key='old',desired='running')
            service_id='a'*16;(data/service_id).mkdir()
            with sqlite3.connect(data/'panel.sqlite3') as db:
                db.execute('CREATE TABLE objects (id TEXT,kind TEXT,value TEXT)')
                db.execute('INSERT INTO objects VALUES (?,?,?)',(service_id,'service',json.dumps(service)))
            with patch.object(sync,'DATA',data),patch.object(sync,'PANEL',status),patch.object(sync,'REGISTRY',root/'missing.json'),patch.object(sync.os,'chown'),patch.object(sync.subprocess,'run') as restart:
                sync.sync_certificates()
                restart.assert_called_once()
            self.assertEqual((data/service_id/'cert.pem').read_text(),'renewed certificate')
            self.assertEqual((data/service_id/'key.pem').read_text(),'renewed key')
            with sqlite3.connect(data/'panel.sqlite3') as db:
                saved=json.loads(db.execute('SELECT value FROM objects').fetchone()[0])
            self.assertEqual(saved['certificate'],'renewed certificate')

if __name__=='__main__':unittest.main()
