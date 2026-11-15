#!/usr/bin/env python3
"""Install or update the panel while retaining its separate state directory."""
import json
import fcntl
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
import urllib.request

SOURCE = Path(__file__).resolve().parent.parent
ROOT = Path('/opt/yptun-panel')
DATA = Path('/var/lib/yptun-panel')
ENV = Path('/etc/yptun-panel.env')
BACKUPS = Path('/var/backups/yptun-panel')
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

    ROOT.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix='.yptun-stage-', dir=str(ROOT.parent)))
    old = None
    backup = None
    stopped = False
    swapped = False
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
            run(['systemctl', 'start', 'yptun-panel'])
            health(values)
        else:
            run([sys.executable, str(ROOT / 'deploy' / 'install.py')])
            health(environment())
        print('Установлена версия ' + (ROOT / 'VERSION').read_text().strip() + ', ревизия ' + revision)
        if backup:
            print('Резервная копия базы: ' + str(backup) + '; предыдущая версия: ' + str(old))
    except Exception:
        if updating and stopped:
            try:
                if swapped:
                    run(['systemctl', 'stop', 'yptun-panel'])
                    failed = ROOT.parent / ('.yptun-failed-' + backup.name)
                    ROOT.rename(failed)
                if old and old.exists():
                    old.rename(ROOT)
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
