#!/usr/bin/env python3
"""Install or update the panel while retaining its separate state directory."""
import json
import fcntl
import importlib.util
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit
import urllib.request

SOURCE = Path(__file__).resolve().parent.parent
ROOT = Path('/opt/yptun-panel')
DATA = Path('/var/lib/yptun-panel')
ENV = Path('/etc/yptun-panel.env')
BACKUPS = Path('/var/backups/yptun-panel')
NGINX = Path('/etc/nginx/conf.d/yptun-panel.conf')
HTTPS_STATUS = Path('/etc/yptun-panel/https.json')
DEPLOY_CONFIG = Path('/etc/yptun-panel/deploy.json')
HTTPS_HELPER = '/usr/local/sbin/yptun-https'
HELPERS = (('https-admin.py', '/usr/local/sbin/yptun-https'),
           ('cert-sync.py', '/usr/local/sbin/yptun-cert-sync'))


def run(args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def environment():
    values = {}
    for line in ENV.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        key, separator, value = line.partition('=')
        if not separator:
            raise ValueError('Некорректный файл ' + str(ENV))
        parts = shlex.split(value, comments=True)
        values[key] = parts[0] if parts else ''
        if len(parts) > 1:
            raise ValueError('Некорректное значение в ' + str(ENV))
    return values


def health(values):
    config = json.loads(Path('/etc/yptun-panel/deploy.json').read_text())
    prefix = config['base_path']
    if not re.fullmatch(r'/[A-Za-z0-9_-]{16,100}', prefix):
        raise ValueError('Некорректный путь панели')
    host = values.get('YPTUN_HOST', '127.0.0.1')
    if host in ('0.0.0.0', '::', '[::]'):
        host = '127.0.0.1'
    if ':' in host and not host.startswith('['):
        host = '[' + host + ']'
    port = int(values.get('YPTUN_PORT', '8080'))
    url = 'http://' + host + ':' + str(port) + prefix + '/health'
    for attempt in range(20):
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200 and json.load(response).get('status') == 'ok':
                    return
        except (OSError, ValueError):
            pass
        time.sleep(1)
    raise RuntimeError('Панель не прошла проверку доступности после запуска')


def check_dependencies():
    for command in ('curl', 'python3', 'systemctl', 'docker', 'nginx', 'certbot',
                    'visudo', 'sudo', 'useradd', 'usermod', 'runuser', 'openssl'):
        if not shutil.which(command):
            raise RuntimeError('Не найдена зависимость: ' + command)
    run(['docker', 'compose', 'version'], stdout=subprocess.DEVNULL)

def prompt_address():
    spec = importlib.util.spec_from_file_location('yptun_https_admin', Path(__file__).with_name('https-admin.py'))
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    try:
        tty = open('/dev/tty', 'r+')
    except OSError as error:
        raise RuntimeError('Для ввода домена или IP нужен интерактивный терминал') from error
    with tty:
        while True:
            tty.write('Домен или публичный IP панели: ')
            tty.flush()
            value = tty.readline()
            if not value:
                raise RuntimeError('Адрес панели не указан')
            try:
                host, is_ip = helper.hostname(value.strip())
                return dict(host=host, mode='ip' if is_ip else 'domain')
            except ValueError as error:
                tty.write(str(error) + '\n')


def configure_initial_https(address):
    result = subprocess.run([HTTPS_HELPER], input=json.dumps(address), capture_output=True, text=True, timeout=300)
    if result.returncode:
        try:
            error = json.loads(result.stderr).get('error')
        except (json.JSONDecodeError, AttributeError):
            error = result.stderr.strip()
        raise RuntimeError('Не удалось настроить HTTPS: ' + (error or 'ошибка helper') +
                           '. Исправьте причину и повторите установку.')
    return json.loads(result.stdout)


def print_access(status, info):
    host = status['host']
    if ':' in host:
        host = '[' + host + ']'
    prefix = info['base_path']
    if not re.fullmatch(r'/[A-Za-z0-9_-]{16,100}', prefix):
        raise ValueError('Некорректный путь панели')
    print('URL панели: https://' + host + prefix + '/', flush=True)
    if status.get('mode') == 'ip':
        print('Сертификат самоподписанный: необходимо добавить его в доверенные.', flush=True)


def subscription_proxy_config(text):
    if re.search(r'(?m)^[ \t]*location\s+(?:\^~\s+)?/subscription/\s*\{', text):
        return None
    blocks = list(re.finditer(r'(?m)^[ \t]*location\s+\^~\s+/turn-sub/\s*\{([^{}]*)\}', text))
    if len(blocks) != 1:
        raise ValueError('Не найден единственный маршрут /turn-sub/; настройте /subscription/ в nginx вручную')
    block = blocks[0]
    directives = [item.strip() for item in block.group(1).split(';') if item.strip()]
    proxy = [item.split(None, 1)[1] for item in directives if re.match(r'^proxy_pass\s+\S+$', item)]
    allowed = re.compile(r'^proxy_set_header\s+(?:Host|X-Real-IP|X-Forwarded-Proto)\s+\S+$')
    if len(proxy) != 1 or any(not re.fullmatch(r'proxy_pass\s+\S+', item) and not allowed.fullmatch(item) for item in directives):
        raise ValueError('Нестандартный маршрут /turn-sub/; настройте /subscription/ в nginx вручную')
    target = urlsplit(proxy[0])
    if (target.scheme != 'http' or target.hostname not in ('127.0.0.1', 'localhost', '::1')
            or target.path or target.query or target.fragment
            or target.username is not None or target.password is not None):
        raise ValueError('Нестандартный proxy_pass; настройте /subscription/ в nginx вручную')
    new_block = block.group(0).replace('/turn-sub/', '/subscription/', 1)
    return text[:block.start()] + new_block + '\n' + text[block.start():]


def write_nginx(text):
    stat = NGINX.stat()
    fd, name = tempfile.mkstemp(prefix='.yptun-nginx-', dir=str(NGINX.parent))
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
        os.chmod(name, stat.st_mode & 0o777)
        os.chown(name, stat.st_uid, stat.st_gid)
        os.replace(name, NGINX)
    finally:
        Path(name).unlink(missing_ok=True)


def update(revision):
    if os.geteuid() != 0:
        raise SystemExit('Запустите установщик от root')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Некорректная ревизия')
    check_dependencies()
    if ROOT.is_symlink() or (ROOT / 'data').exists():
        raise RuntimeError('Источник панели содержит данные или является ссылкой; автоматическое обновление невозможно')
    if ROOT.exists() and not (ROOT / 'server.py').is_file():
        raise RuntimeError('Каталог установки занят посторонними файлами')
    if not ROOT.exists() and (DATA.exists() or ENV.exists()):
        raise RuntimeError('Обнаружена существующая конфигурация без исходников; установка остановлена')
    updating = ROOT.exists()
    values = environment() if updating else {}
    if updating and Path(values.get('YPTUN_DATA', '')) != DATA:
        raise RuntimeError('Нестандартный YPTUN_DATA: автоматическое обновление остановлено')
    if updating:
        run(['systemctl', 'is-active', '--quiet', 'yptun-panel'])
    address = prompt_address() if not updating or not HTTPS_STATUS.exists() else None

    ROOT.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.yptun-stage-', dir=str(ROOT.parent)))
    old = None
    backup = None
    stopped = False
    swapped = False
    nginx_changed = False
    try:
        shutil.copytree(SOURCE, stage, dirs_exist_ok=True)
        (stage / '.revision').write_text(revision + '\n')
        os.chmod(stage, 0o755)
        if updating:
            BACKUPS.mkdir(mode=0o700, parents=True, exist_ok=True)
            os.chmod(BACKUPS, 0o700)
            backup = Path(tempfile.mkdtemp(prefix='update-', dir=str(BACKUPS)))
            for _, target in HELPERS:
                path = Path(target)
                if not path.is_file() or path.is_symlink():
                    raise RuntimeError('Не найден штатный helper: ' + target)
                shutil.copy2(path, backup / path.name)
            nginx_update = None
            if NGINX.exists():
                if NGINX.is_symlink():
                    raise RuntimeError('Конфигурация nginx является ссылкой; настройте /subscription/ вручную')
                nginx_update = subscription_proxy_config(NGINX.read_text())
                if nginx_update is not None:
                    shutil.copy2(NGINX, backup / 'nginx.conf')
            dbpath = DATA / 'panel.sqlite3'
            if not dbpath.is_file():
                raise RuntimeError('Не найдена база данных панели')
            run(['systemctl', 'stop', 'yptun-panel'])
            stopped = True
            with sqlite3.connect('file:' + str(dbpath) + '?mode=ro', uri=True) as db, sqlite3.connect(backup / 'panel.sqlite3') as copy:
                db.backup(copy)
            old = ROOT.parent / ('.yptun-previous-' + backup.name)
            ROOT.rename(old)
        stage.rename(ROOT)
        swapped = True
        if updating:
            for name, target in HELPERS:
                shutil.copyfile(ROOT / 'deploy' / name, target)
                os.chmod(target, 0o755)
            if nginx_update is not None:
                nginx_changed = True
                write_nginx(nginx_update)
                run(['nginx', '-t'])
                run(['systemctl', 'reload', 'nginx'])
            run(['systemctl', 'start', 'yptun-panel'])
            health(values)
        else:
            result = run([sys.executable, str(ROOT / 'deploy' / 'install.py')], stdout=subprocess.PIPE, text=True)
            lines = result.stdout.splitlines()
            if not lines:
                raise RuntimeError('Установщик не вернул данные доступа панели')
            if len(lines) > 1:
                print('\n'.join(lines[:-1]), flush=True)
            info = json.loads(lines[-1])
            created = info.get('created')
            if created:
                print('Логин панели: ' + created['username'], flush=True)
                print('Пароль панели: ' + created['password'], flush=True)
                print('Сохраните пароль: повторно показать его нельзя.', flush=True)
            health(environment())
    except Exception:
        if updating and stopped:
            try:
                if swapped:
                    run(['systemctl', 'stop', 'yptun-panel'])
                    failed = ROOT.parent / ('.yptun-failed-' + backup.name)
                    ROOT.rename(failed)
                if old and old.exists():
                    old.rename(ROOT)
                if nginx_changed:
                    write_nginx((backup / 'nginx.conf').read_text())
                    run(['nginx', '-t'])
                    run(['systemctl', 'reload', 'nginx'])
                for _, target in HELPERS:
                    saved = backup / Path(target).name
                    if saved.exists():
                        shutil.copy2(saved, target)
                saved_db = backup / 'panel.sqlite3'
                if swapped and saved_db.exists():
                    dbpath = DATA / 'panel.sqlite3'
                    owner = dbpath.stat()
                    for suffix in ('-wal', '-shm'):
                        Path(str(dbpath) + suffix).unlink(missing_ok=True)
                    shutil.copyfile(saved_db, dbpath)
                    os.chown(dbpath, owner.st_uid, owner.st_gid)
                run(['systemctl', 'start', 'yptun-panel'])
                health(values)
            except Exception as rollback_error:
                print('Не удалось восстановить панель: ' + str(rollback_error), file=sys.stderr)
            print('Обновление не удалось; резервная копия: ' + str(backup), file=sys.stderr)
        raise
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    status = configure_initial_https(address) if address else json.loads(HTTPS_STATUS.read_text())
    print('Установлена версия ' + (ROOT / 'VERSION').read_text().strip() + ', ревизия ' + revision)
    if backup:
        print('Резервная копия базы: ' + str(backup) + '; предыдущая версия: ' + str(old))
    if updating:
        info = json.loads(DEPLOY_CONFIG.read_text())
        print('Логин и пароль панели остались прежними.', flush=True)
    print_access(status, info)


if __name__ == '__main__':
    if os.geteuid() != 0:
        raise SystemExit('Запустите установщик от root')
    lock_fd = os.open('/run/lock/yptun-panel-update.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(lock_fd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit('Установка или обновление уже выполняется')
        update(sys.argv[1])
