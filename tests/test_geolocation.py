import gzip
import ipaddress
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import geolocation


class GeolocationTest(unittest.TestCase):
    def test_local_ipv4_ipv6_lookup_and_mixed_countries(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'countries.gz'
            with gzip.open(path,'wt') as out:
                out.write('8.8.8.0,8.8.8.255,US\n1.1.1.0,1.1.1.255,AU\n2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,US\n')
            self.assertEqual(geolocation.lookup(str(path),(ipaddress.ip_address('8.8.8.8'),ipaddress.ip_address('2001:4860:4860::8888'))),'US')
            with self.assertRaisesRegex(ValueError,'разных странах'):
                geolocation.lookup(str(path),(ipaddress.ip_address('8.8.8.8'),ipaddress.ip_address('1.1.1.1')))
            with self.assertRaisesRegex(ValueError,'не найдена'):
                geolocation.lookup(str(path),(ipaddress.ip_address('9.9.9.9'),))

    def test_resolution_rejects_private_addresses(self):
        result=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1',0))]
        with patch.object(socket,'getaddrinfo',return_value=result):
            with self.assertRaisesRegex(ValueError,'нет публичного IP'):geolocation.addresses('localhost')

    def test_download_errors_are_explicit(self):
        with tempfile.TemporaryDirectory() as tmp, patch('urllib.request.urlopen',side_effect=OSError('offline')):
            with self.assertRaisesRegex(ValueError,'загрузить базу'):geolocation.database(tmp)
