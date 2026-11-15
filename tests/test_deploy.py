import importlib.util
import io
import os
from pathlib import Path
import sqlite3
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch


def module(name):
    path=Path(__file__).resolve().parents[1]/'deploy'/(name+'.py')
    spec=importlib.util.spec_from_file_location(name,path)
    result=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


bootstrap=module('bootstrap')
updater=module('update')


class ArchiveTest(unittest.TestCase):
    def archive(self, name, content=b'test', kind=tarfile.REGTYPE):
        output=io.BytesIO()
        with tarfile.open(fileobj=output,mode='w:gz') as archive:
            member=tarfile.TarInfo(name)
            member.type=kind
            member.size=len(content) if kind==tarfile.REGTYPE else 0
            archive.addfile(member,io.BytesIO(content) if member.size else None)
        return output.getvalue()

    def test_extract_and_reject_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            bootstrap.extract(self.archive('panel/file.txt'),root)
            self.assertEqual((root/'file.txt').read_text(),'test')
            for archive in (self.archive('panel/../outside'),self.archive('panel/link',kind=tarfile.SYMTYPE)):
                with self.assertRaises(ValueError):
                    bootstrap.extract(archive,root)


class InstallShellTest(unittest.TestCase):
    def test_bootstrap_cleanup_and_download_failure(self):
        script=Path(__file__).resolve().parents[1]/'deploy'/'install.sh'
        for fail in (False,True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                binpath=root/'bin';binpath.mkdir()
                curl=binpath/'curl'
                curl.write_text('#!/bin/sh\n[ "$FAIL_CURL" = 1 ] && exit 22\nfor arg do last="$arg"; done\nprintf bootstrap > "$last"\n')
                python=binpath/'python3'
                python.write_text('#!/bin/sh\nprintf "%s" "$1" > "$MARKER"\n')
                curl.chmod(0o755);python.chmod(0o755)
                marker=root/'called'
                env=dict(os.environ,PATH=str(binpath)+':'+os.defpath,TMPDIR=str(root),
                         FAIL_CURL='1' if fail else '0',MARKER=str(marker))
                result=subprocess.run(['/bin/bash',str(script)],env=env,capture_output=True)
                self.assertEqual(result.returncode,22 if fail else 0)
                self.assertEqual(marker.exists(),not fail)
                self.assertEqual(list(root.glob('yptun-bootstrap.*')),[])


class UpdateTest(unittest.TestCase):
    def test_proxy_migration_preserves_existing_location(self):
        old='server {\n    location ^~ /turn-sub/ {\n        proxy_pass http://127.0.0.1:8080;\n    }\n}\n'
        result=updater.subscription_proxy_config(old)
        self.assertIn('location ^~ /subscription/',result)
        self.assertIn('location ^~ /turn-sub/',result)
        self.assertIsNone(updater.subscription_proxy_config(result))
        self.assertIn('location ^~ /subscription/',updater.subscription_proxy_config(old.replace(':8080;',':8081;')))
        with self.assertRaises(ValueError):
            updater.subscription_proxy_config(old.replace('127.0.0.1','other.example'))
        with self.assertRaises(ValueError):
            updater.subscription_proxy_config(old.replace(':8080;',':8080/turn-sub/;'))

    def test_fresh_install_runs_installer_and_checks_health(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            source=root/'source';(source/'deploy').mkdir(parents=True)
            (source/'server.py').write_text('new')
            (source/'VERSION').write_text('0.1.0')
            installed=root/'opt'/'yptun-panel'
            data=root/'data';env=root/'panel.env'
            calls=[]
            def run(args,**kwargs):
                calls.append(args)
                env.write_text('YPTUN_DATA='+str(data)+'\n')
            with patch.multiple(updater,SOURCE=source,ROOT=installed,DATA=data,ENV=env,
                                NGINX=root/'nginx.conf',
                                check_dependencies=lambda:None,run=run,
                                health=lambda values:calls.append(values)), \
                 patch.object(updater.os,'geteuid',return_value=0):
                updater.update('b'*40)
            self.assertEqual(calls[0][1],str(installed/'deploy'/'install.py'))
            self.assertEqual(calls[1]['YPTUN_DATA'],str(data))
            self.assertEqual((installed/'.revision').read_text().strip(),'b'*40)

    def test_update_and_rollback_preserve_data(self):
        for fail in (False,True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                source=root/'source';(source/'deploy').mkdir(parents=True)
                (source/'server.py').write_text('new')
                (source/'VERSION').write_text('0.1.0')
                (source/'deploy'/'https-admin.py').write_text('new helper')
                installed=root/'opt'/'yptun-panel';installed.mkdir(parents=True)
                (installed/'server.py').write_text('old')
                data=root/'data';data.mkdir()
                database=data/'panel.sqlite3'
                with sqlite3.connect(database) as db:
                    db.execute('create table items (value text)')
                    db.execute("insert into items values ('original')")
                env=root/'panel.env';env.write_text('YPTUN_DATA='+str(data)+'\n')
                helper=root/'helper';helper.write_text('old helper')
                nginx=root/'nginx.conf'
                old_nginx='server {\n    location ^~ /turn-sub/ {\n        proxy_pass http://127.0.0.1:8080;\n    }\n}\n'
                nginx.write_text(old_nginx)
                calls=[]
                def run(args,**kwargs):
                    calls.append(args)
                def health(values):
                    if fail and (installed/'server.py').read_text()=='new':
                        with sqlite3.connect(database) as db:
                            db.execute("update items set value='changed'")
                        raise RuntimeError('health failed')
                with patch.multiple(updater,SOURCE=source,ROOT=installed,DATA=data,ENV=env,
                                    BACKUPS=root/'backups',NGINX=nginx,HELPERS=(('https-admin.py',str(helper)),),
                                    check_dependencies=lambda:None,run=run,health=health), \
                     patch.object(updater.os,'geteuid',return_value=0):
                    if fail:
                        with self.assertRaisesRegex(RuntimeError,'health failed'):
                            updater.update('a'*40)
                    else:
                        updater.update('a'*40)
                self.assertEqual((installed/'server.py').read_text(),'old' if fail else 'new')
                self.assertEqual(helper.read_text(),'old helper' if fail else 'new helper')
                if fail:
                    self.assertEqual(nginx.read_text(),old_nginx)
                else:
                    self.assertIn('location ^~ /subscription/',nginx.read_text())
                if not fail:
                    self.assertEqual(installed.stat().st_mode & 0o777,0o755)
                with sqlite3.connect(database) as db:
                    self.assertEqual(db.execute('select value from items').fetchone()[0],'original')
                self.assertIn(['systemctl','stop','yptun-panel'],calls)
                if not fail:
                    self.assertEqual((installed/'.revision').read_text().strip(),'a'*40)


if __name__=='__main__':unittest.main()
