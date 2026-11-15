import importlib.util
from pathlib import Path
import unittest
spec=importlib.util.spec_from_file_location('https_admin',Path(__file__).resolve().parents[1]/'deploy'/'https-admin.py')
helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)

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

if __name__=='__main__':unittest.main()
