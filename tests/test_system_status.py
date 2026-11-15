import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import system_status


class SystemStatusTest(unittest.TestCase):
    def test_cpu_uses_delta_and_memory_available(self):
        with tempfile.TemporaryDirectory() as directory:
            proc=Path(directory)
            (proc/'stat').write_text('cpu 100 0 50 850 0 0 0 0\n')
            (proc/'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 600 kB\n')
            with patch.object(system_status,'PROC',proc), patch.object(system_status,'_last_cpu',None):
                self.assertIsNone(system_status.cpu_usage())
                (proc/'stat').write_text('cpu 120 0 60 920 0 0 0 0\n')
                self.assertEqual(system_status.cpu_usage(),30.0)
                self.assertEqual(system_status.memory_usage(),dict(total=1024000,used=409600))

    def test_missing_proc_is_reported(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(system_status,'PROC',Path(directory)):
            result=system_status.status()
        self.assertIsNone(result['memory'])
        self.assertIn('memory',result['errors'])


if __name__=='__main__':unittest.main()
