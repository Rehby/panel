#!/usr/bin/env python3
"""Download a specific main-branch revision and run its installer."""
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

API = 'https://api.github.com/repos/Rehby/panel/commits/main'
ARCHIVE = 'https://codeload.github.com/Rehby/panel/tar.gz/'


def download(url):
    return subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location',
                           '--connect-timeout', '15', '--max-time', '180', url],
                          check=True, stdout=subprocess.PIPE).stdout


def extract(archive, destination):
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as tar:
        members = tar.getmembers()
        if sum(member.size for member in members) > 100 * 1024 * 1024:
            raise ValueError('Архив слишком велик')
        roots = {PurePosixPath(member.name).parts[0] for member in members if PurePosixPath(member.name).parts}
        if len(roots) != 1:
            raise ValueError('Некорректный архив')
        for member in members:
            parts = PurePosixPath(member.name).parts
            if not parts or any(part in ('..', '.') for part in parts) or member.name.startswith('/'):
                raise ValueError('Некорректный путь в архиве')
            if not (member.isdir() or member.isfile()):
                raise ValueError('Ссылки и специальные файлы в архиве запрещены')
            target = destination.joinpath(*parts[1:])
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError('Не удалось прочитать файл архива')
                with source, target.open('wb') as output:
                    shutil.copyfileobj(source, output)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Запустите установщик от root')
    revision = json.loads(download(API))['sha']
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError('Некорректная ревизия GitHub')
    with tempfile.TemporaryDirectory(prefix='yptun-download-') as directory:
        source = Path(directory)
        extract(download(ARCHIVE + revision), source)
        subprocess.run([sys.executable, str(source / 'deploy' / 'update.py'), revision], check=True)


if __name__ == '__main__':
    main()
