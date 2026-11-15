import socket
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import defaults,server

class RandomPortTest(unittest.TestCase):
 def test_crypto_shuffle_is_used(self):
  with patch.object(defaults.secrets,'SystemRandom') as rng:
   rng.return_value.shuffle.side_effect=lambda candidates:candidates.__setitem__(slice(None),[21549])
   self.assertEqual(defaults.free_port('vless',set()),21549)
   rng.return_value.shuffle.assert_called_once()
 def test_tcp_udp_and_reserved_ports_are_skipped(self):
  with socket.socket(type=socket.SOCK_STREAM) as tcp,socket.socket(type=socket.SOCK_DGRAM) as udp:
   tcp.bind(('0.0.0.0',0));udp.bind(('0.0.0.0',0));ports=[tcp.getsockname()[1],udp.getsockname()[1],24004]
   with patch.object(defaults.secrets,'SystemRandom') as rng:
    rng.return_value.shuffle.side_effect=lambda candidates:candidates.__setitem__(slice(None),ports)
    self.assertEqual(defaults.free_port('wdtt',set()),24004)
  with patch.object(defaults.secrets,'SystemRandom') as rng:
   def order(candidates):
    self.assertNotIn(24004,candidates);candidates[:]=[24005]
   rng.return_value.shuffle.side_effect=order
   self.assertEqual(defaults.free_port('vless',{24004}),24005)
 def test_dns_direct_resolver_uses_random_port(self):
  with patch.object(defaults.secrets,'SystemRandom') as rng:
   rng.return_value.shuffle.side_effect=lambda candidates:candidates.__setitem__(slice(None),[29453])
   self.assertEqual(defaults.free_port('masterdns',set()),29453)
   rng.return_value.shuffle.assert_called_once()
 def test_random_ports_are_in_high_range(self):
  for protocol in ('vless','vmess','trojan','shadowsocks','hysteria2','wdtt','wireguard','amneziawg','vkturn','masterdns','openflux','snolc','warp','raw'):
   port=defaults.free_port(protocol,set());self.assertTrue(10000<=port<=65535)

if __name__=='__main__':unittest.main()
