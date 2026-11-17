"""Regression checks for production SQLite FD exhaustion and Unix HTTP Host."""
from http.server import BaseHTTPRequestHandler
from pathlib import Path
import socketserver
import sqlite3
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import server,traffic


class DatabaseAndMetricsTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='yptun-metrics-',dir='/tmp')
        self.old=server.DATA;server.DATA=Path(self.tmp.name);server.init()
        self.addCleanup(self.tmp.cleanup);self.addCleanup(setattr,server,'DATA',self.old)

    def test_database_connections_close_and_failed_transactions_roll_back(self):
        with server.db() as connection:connection.execute('SELECT 1')
        with self.assertRaises(sqlite3.ProgrammingError):connection.execute('SELECT 1')
        with self.assertRaises(ValueError):
            with server.db() as failed:
                failed.execute("INSERT INTO events VALUES (1,'rollback')")
                raise ValueError('abort')
        with self.assertRaises(sqlite3.ProgrammingError):failed.execute('SELECT 1')
        with server.db() as check:self.assertEqual(check.execute('SELECT count(*) FROM events').fetchone()[0],0)

    def test_webproxy_collection_sends_a_valid_http_host_over_unix_socket(self):
        observed=[]
        class MetricsHandler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_GET(self):
                observed.append(self.headers.get('Host'))
                if self.headers.get('Host')!='localhost':self.send_error(400);return
                body=b'tgwp_bytes_up_total{domain="tg.example.com",label="access"} 12\ntgwp_bytes_down_total{domain="tg.example.com",label="access"} 34\n'
                self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        s=dict(id='web',protocol='webproxy',name='WEB',host='tg.example.com',port=23456)
        server.put('service',s);server.put('person',dict(id='owner',name='Owner'))
        server.put('user',dict(id='access',person_id='owner',service_id=s['id'],enabled=True))
        directory=server.DATA/s['id']/'runtime';directory.mkdir(parents=True)
        listener=socketserver.UnixStreamServer(str(directory/'metrics.sock'),MetricsHandler)
        thread=threading.Thread(target=listener.serve_forever,daemon=True);thread.start()
        try:
            with patch.object(server,'compose',return_value='container-id'),patch.object(traffic.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout='container:started')):
                traffic.collect(server,s)
            self.assertEqual(observed,['localhost'])
            summary=traffic.summary(server,dict(id='owner'))
            self.assertEqual((summary['upload'],summary['download']),(12,34))
        finally:listener.shutdown();listener.server_close();thread.join()

if __name__=='__main__':unittest.main()
