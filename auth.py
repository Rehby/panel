"""Persistent PBKDF2 credentials, random panel route, expiring revocable sessions."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import time

ITERATIONS = 600_000
SESSIONS = {}
ATTEMPTS = {}
CONFIG = {}


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),ITERATIONS).hex()


def initialize(directory):
    global CONFIG
    path=Path(directory)/'auth.json';created=None
    if path.exists():CONFIG=json.loads(path.read_text())
    else:
        password=os.environ.get('YPTUN_ADMIN_PASSWORD') or secrets.token_urlsafe(24)
        salt=secrets.token_hex(32)
        CONFIG=dict(username=os.environ.get('YPTUN_ADMIN_USER','admin'),salt=salt,password_hash=password_hash(password,salt),base_path='/'+secrets.token_urlsafe(24))
        created=dict(username=CONFIG['username'],password=password)
        temp=path.with_suffix('.tmp');temp.write_text(json.dumps(CONFIG));os.chmod(temp,0o600);temp.replace(path)
    if not re.fullmatch(r'/[a-zA-Z0-9_-]{16,100}',CONFIG['base_path']):raise ValueError('Некорректный путь панели в auth.json')
    SESSIONS.clear();ATTEMPTS.clear()
    return created


def login(username,password,ip):
    now=time.time()
    attempts=[t for t in ATTEMPTS.get(ip,[]) if t>now-900]
    if len(attempts)>=10:raise ValueError('Слишком много попыток. Повторите через 15 минут')
    valid=hmac.compare_digest(str(username),CONFIG['username'])
    valid=hmac.compare_digest(password_hash(str(password),CONFIG['salt']),CONFIG['password_hash']) and valid
    if not valid:
        ATTEMPTS[ip]=attempts+[now]
        return None
    ATTEMPTS.pop(ip,None)
    # Store only a digest of each session token; cookies expire after twelve hours.
    for key,expiry in list(SESSIONS.items()):
        if expiry<=now:SESSIONS.pop(key,None)
    token=secrets.token_urlsafe(32);SESSIONS[hashlib.sha256(token.encode()).hexdigest()]=now+43200
    return token


def authenticated(token):
    key=hashlib.sha256(token.encode()).hexdigest()
    return SESSIONS.get(key,0)>time.time()


def logout(token):SESSIONS.pop(hashlib.sha256(token.encode()).hexdigest(),None)
