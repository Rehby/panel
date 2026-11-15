import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import select
import signal
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
from unittest.mock import call,patch


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
    def run_installer(self,root,**options):
        script=Path(__file__).resolve().parents[1]/'deploy'/'install.sh'
        binpath=root/'bin';binpath.mkdir()
        def fake(name,body):
            target=binpath/name;target.write_text('#!/bin/sh\n'+body+'\n');target.chmod(0o755)
        fake('id','echo 0')
        fake('uname','[ "$1" = -m ] && echo x86_64 || echo Linux')
        fake('systemctl','[ "$FAIL_SYSTEMD" != 1 ]')
        fake('nginx','echo "configure arguments: --with-http_v2_module" >&2')
        fake('docker','[ "$COMPOSE_MISSING" != 1 ] || [ -f "$COMPOSE_READY" ]')
        fake('python3','[ "$1" = -c ] && exit 0\nprintf "%s" "$1" > "$MARKER"')
        fake('curl','printf "%s\\n" "$*" >> "$CALLS"\n[ "$FAIL_CURL" = 1 ] && exit 22\nfor arg do last="$arg"; done\nprintf bootstrap > "$last"')
        fake('apt-get','printf "apt-get %s\\n" "$*" >> "$CALLS"\n[ "$FAIL_APT" = 1 ] && exit 1\n[ "$1" != install ] || /bin/cp "$FAKE_BIN/certbot-template" "$FAKE_BIN/certbot"')
        fake('sha256sum','/bin/cat >/dev/null\n[ "$FAIL_CHECKSUM" != 1 ]')
        fake('install','printf "install %s\\n" "$*" >> "$CALLS"\n[ "$1" = -d ] || /usr/bin/touch "$COMPOSE_READY"')
        for name in ('sudo','visudo','useradd','usermod','runuser','openssl','git','ip','update-ca-certificates','certbot-template'):
            fake(name,'exit 0')
        if not options.get('missing_certbot'):fake('certbot','exit 0')
        for name,target in (('mktemp','/usr/bin/mktemp'),('rm','/bin/rm'),('grep','/usr/bin/grep')):
            (binpath/name).symlink_to(target)
        env=dict(os.environ,PATH=str(binpath),TMPDIR=str(root),MARKER=str(root/'called'),
                 FAKE_BIN=str(binpath),CALLS=str(root/'calls'),COMPOSE_READY=str(root/'compose-ready'),
                 FAIL_CURL=str(int(options.get('fail_curl',False))),FAIL_APT=str(int(options.get('fail_apt',False))),
                 FAIL_CHECKSUM=str(int(options.get('fail_checksum',False))),FAIL_SYSTEMD=str(int(options.get('fail_systemd',False))),
                 COMPOSE_MISSING=str(int(options.get('compose_missing',False))))
        return subprocess.run(['/bin/bash',str(script)],env=env,capture_output=True,text=True)

    def test_bootstrap_cleanup_and_download_failure(self):
        for fail in (False,True):
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                result=self.run_installer(root,fail_curl=fail)
                self.assertEqual(result.returncode,22 if fail else 0)
                self.assertEqual((root/'called').exists(),not fail)
                self.assertEqual(list(root.glob('yptun-bootstrap.*')),[])
                self.assertNotIn('apt-get', (root/'calls').read_text())

    def test_installs_only_missing_packages_and_stops_on_apt_failure(self):
        for fail in (False,True):
            with self.subTest(fail=fail),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);result=self.run_installer(root,missing_certbot=True,fail_apt=fail)
                self.assertEqual(result.returncode,1 if fail else 0,result.stderr)
                calls=(root/'calls').read_text()
                self.assertIn('apt-get update',calls)
                self.assertEqual((root/'called').exists(),not fail)
                if not fail:self.assertIn('apt-get install -y --no-install-recommends certbot',calls)

    def test_compose_checksum_failure_prevents_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);result=self.run_installer(root,compose_missing=True,fail_checksum=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('docker-compose-linux-x86_64',(root/'calls').read_text())
            self.assertFalse((root/'compose-ready').exists())
            self.assertFalse((root/'called').exists())
            self.assertEqual(list(root.glob('yptun-compose.*')),[])

    def test_installs_compose_plugin_after_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);result=self.run_installer(root,compose_missing=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertTrue((root/'compose-ready').exists())
            self.assertTrue((root/'called').exists())
            self.assertIn('docker-compose-linux-x86_64',(root/'calls').read_text())
            self.assertEqual(list(root.glob('yptun-compose.*')),[])

    def test_fails_without_systemd_before_installing(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);result=self.run_installer(root,fail_systemd=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('systemd',result.stderr)
            self.assertFalse((root/'calls').exists())


class InstallProgressTest(unittest.TestCase):
    def test_command_output_is_live_and_captured_credentials_remain_private(self):
        script=("import sys; sys.path.insert(0,sys.argv[1]); import install; "
                "install.run([sys.executable,'-u','-c',sys.argv[2]]); "
                "result=install.run([sys.executable,'-c',sys.argv[3]],capture_output=True); "
                "print(result.stdout,end='')")
        worker="import sys; print('service progress',flush=True); sys.stdin.readline()"
        credentials="print('{\"created\":\"test-secret\"}')"
        deploy=str(Path(__file__).resolve().parents[1]/'deploy')
        process=subprocess.Popen([sys.executable,'-c',script,deploy,worker,credentials],
                                 stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            self.assertTrue(select.select([process.stderr],[],[],10)[0], 'Нет вывода во время работы команды')
            progress=os.read(process.stderr.fileno(),4096)
            self.assertIn(b'service progress',progress)
            self.assertIsNone(process.poll())
            output,remaining=process.communicate(input=b'\n',timeout=10)
            self.assertEqual(process.returncode,0,remaining.decode(errors='replace'))
            self.assertEqual(json.loads(output),{'created':'test-secret'})
            self.assertNotIn(b'test-secret',progress+remaining)
        finally:
            if process.poll() is None:
                process.kill();process.wait()
            for stream in (process.stdin,process.stdout,process.stderr):
                if stream and not stream.closed:stream.close()


class UpdateTest(unittest.TestCase):
    def test_address_prompt_uses_tty_and_validates_domain_and_ip(self):
        class TTY:
            def __init__(self,lines):self.lines=iter(lines);self.output=''
            def __enter__(self):return self
            def __exit__(self,*args):pass
            def readline(self):return next(self.lines,'')
            def write(self,text):self.output+=text
            def flush(self):pass
        tty_in=TTY(['bad/url\n','VPN.Example.com\n']);tty_out=TTY([])
        with patch('builtins.open',side_effect=[tty_in,tty_out]) as opened:
            self.assertEqual(updater.prompt_address(),dict(host='vpn.example.com',mode='domain'))
        self.assertEqual(opened.call_args_list,[call('/dev/tty','r'),call('/dev/tty','w')])
        self.assertIn('нажмите Enter',tty_out.output)
        self.assertIn('Укажите публичный',tty_out.output)
        with patch('builtins.open',side_effect=[TTY(['2001:db8::1\n']),TTY([])]):
            self.assertEqual(updater.prompt_address(),dict(host='2001:db8::1',mode='ip'))
        with patch('builtins.open',side_effect=OSError('no tty')):
            with self.assertRaisesRegex(RuntimeError,'терминал'):updater.prompt_address()
        with patch('builtins.open',side_effect=[TTY([]),OSError('no tty')]):
            with self.assertRaisesRegex(RuntimeError,'терминал'):updater.prompt_address()

    def test_address_prompt_with_piped_stdin_and_controlling_terminal(self):
        script="import sys; sys.path.insert(0,sys.argv[1]); import update,json; print(json.dumps(update.prompt_address()))"
        pid,master=pty.fork()
        if pid==0:
            read_fd,write_fd=os.pipe();os.close(write_fd)
            os.dup2(read_fd,0);os.close(read_fd)
            os.execv(sys.executable,[sys.executable,'-c',script,str(Path(__file__).resolve().parents[1]/'deploy')])
        output=b'';sent=False;status=None
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                if select.select([master],[],[],0.1)[0]:
                    try:chunk=os.read(master,4096)
                    except OSError:chunk=b''
                    output+=chunk
                    if not sent and 'Домен или публичный IP панели: '.encode() in output:
                        os.write(master,b'bad/url\nVPN.Example.com\n');sent=True
                done,result=os.waitpid(pid,os.WNOHANG)
                if done:
                    status=result
                    while select.select([master],[],[],0)[0]:
                        try:chunk=os.read(master,4096)
                        except OSError:break
                        if not chunk:break
                        output+=chunk
                    break
            else:self.fail('Запрос адреса в терминале не завершился')
        finally:
            if status is None:
                os.kill(pid,signal.SIGKILL);os.waitpid(pid,0)
            os.close(master)
        self.assertEqual(os.waitstatus_to_exitcode(status),0,output.decode(errors='replace'))
        self.assertIn('нажмите Enter'.encode(),output)
        self.assertIn(b'"host": "vpn.example.com"',output)
        self.assertIn(b'"mode": "domain"',output)

    def test_https_helper_error_is_reported(self):
        result=subprocess.CompletedProcess([],1,'','{"error":"certificate failed"}')
        with patch.object(updater.subprocess,'run',return_value=result):
            with self.assertRaisesRegex(RuntimeError,'certificate failed'):updater.configure_initial_https(dict(host='vpn.example.com',mode='domain'))
        with patch.object(updater.subprocess,'run',side_effect=subprocess.TimeoutExpired('helper',300)):
            with self.assertRaisesRegex(RuntimeError,'не завершилась за 5 минут'):updater.configure_initial_https(dict(host='vpn.example.com',mode='domain'))

    def test_ip_url_includes_brackets_and_certificate_warning(self):
        output=io.StringIO()
        with patch('sys.stdout',output):
            updater.print_access(dict(host='2001:db8::1',mode='ip'),dict(base_path='/abcdefghijklmnop'))
        self.assertIn('https://[2001:db8::1]/abcdefghijklmnop/',output.getvalue())
        self.assertIn('самоподписанный',output.getvalue())

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
                self.assertIn('Адрес принят.',output.getvalue())
                self.assertIn('Подготовка установки панели',output.getvalue())
                calls.append(args)
                env.write_text('YPTUN_DATA='+str(data)+'\n')
                return subprocess.CompletedProcess(args,0,'systemctl output\n'+json.dumps(dict(base_path='/abcdefghijklmnop',created=dict(username='admin',password='test-password')))+'\n')
            output=io.StringIO()
            def health(values):
                self.assertIn('Проверка запуска панели',output.getvalue())
                calls.append(values)
            def configure(address):
                self.assertIn('Настройка HTTPS и выпуск сертификата',output.getvalue())
                return dict(host=address['host'],mode=address['mode'])
            with patch.multiple(updater,SOURCE=source,ROOT=installed,DATA=data,ENV=env,
                                NGINX=root/'nginx.conf',
                                check_dependencies=lambda:None,run=run,
                                health=health,
                                prompt_address=lambda:dict(host='vpn.example.com',mode='domain'),
                                configure_initial_https=configure), \
                 patch.object(updater.os,'geteuid',return_value=0),patch('sys.stdout',output):
                updater.update('b'*40)
            self.assertEqual(calls[0][1],str(installed/'deploy'/'install.py'))
            self.assertEqual(calls[1]['YPTUN_DATA'],str(data))
            self.assertEqual((installed/'.revision').read_text().strip(),'b'*40)
            self.assertIn('URL панели: https://vpn.example.com/abcdefghijklmnop/',output.getvalue())
            self.assertIn('Логин панели: admin',output.getvalue())
            self.assertIn('Пароль панели: test-password',output.getvalue())
            self.assertNotIn('"created"',output.getvalue())

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
                https=root/'https.json';https.write_text(json.dumps(dict(host='vpn.example.com',mode='domain')))
                deploy=root/'deploy.json';deploy.write_text(json.dumps(dict(base_path='/abcdefghijklmnop')))
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
                                    BACKUPS=root/'backups',NGINX=nginx,HTTPS_STATUS=https,DEPLOY_CONFIG=deploy,HELPERS=(('https-admin.py',str(helper)),),
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
