import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import images


class ImageCleanupTest(unittest.TestCase):
    def run_job(self,prepare_error=None,cleanup_error=None):
        def thread(*,target,**kwargs):
            return SimpleNamespace(start=target)
        with patch.dict(os.environ,YPTUN_ALLOW_DOCKER='1'),patch.dict(images.JOBS,{},clear=True),patch.object(images.threading,'Thread',side_effect=thread),patch.object(images,'prepare_image',side_effect=prepare_error),patch.object(images,'command',side_effect=cleanup_error) as command:
            result=images.start_job('mieru','build',Path('/unused'))
        return result,command

    def test_successful_build_runs_cleanup(self):
        result,command=self.run_job()
        self.assertEqual(result['status'],'succeeded')
        self.assertEqual(command.call_args.args[0],['/bin/sh',str(images.ROOT/'deploy'/'cleanup-images.sh')])

    def test_failed_build_does_not_clean_recovery_images(self):
        result,command=self.run_job(prepare_error=ValueError('build failed'))
        self.assertEqual(result['status'],'failed')
        command.assert_not_called()

    def test_cleanup_failure_does_not_fail_successful_build(self):
        result,_=self.run_job(cleanup_error=ValueError('cleanup failed'))
        self.assertEqual(result['status'],'succeeded')
        self.assertEqual(result['cleanup_error'],'cleanup failed')


if __name__=='__main__':unittest.main()
