"""Persistent PBKDF2 credentials, random panel route, expiring revocable sessions."""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import time

ITERATIONS = 600_000
SESSIONS = {}
ATTEMPTS = {}
CONFIG = {}
DB_PATH = None


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),ITERATIONS).hex()


@contextmanager
def _db():
    connection=sqlite3.connect(str(DB_PATH))
    connection.execute('CREATE TABLE IF NOT EXISTS auth_config (username TEXT NOT NULL, salt TEXT NOT NULL, password_hash TEXT NOT NULL, base_path TEXT NOT NULL)')
    connection.execute('CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, expires_at REAL NOT NULL)')
    try:
        with connection:yield connection
    finally:connection.close()


def initialize(directory):
    global CONFIG,DB_PATH
    directory=Path(directory);DB_PATH=directory/'panel.sqlite3';created=None
    with _db() as connection:
        row=connection.execute('SELECT username,salt,password_hash,base_path FROM auth_config').fetchone()
        if row:
            CONFIG=dict(username=row[0],salt=row[1],password_hash=row[2],base_path=row[3])
        else:
            legacy=directory/'auth.json'
            if legacy.exists():
                CONFIG=json.loads(legacy.read_text())
            else:
                password=os.environ.get('YPTUN_ADMIN_PASSWORD') or secrets.token_urlsafe(24)
                salt=secrets.token_hex(32)
                CONFIG=dict(username=os.environ.get('YPTUN_ADMIN_USER','admin'),salt=salt,password_hash=password_hash(password,salt),base_path='/'+secrets.token_urlsafe(24))
                created=dict(username=CONFIG['username'],password=password)
            connection.execute('INSERT INTO auth_config VALUES (?,?,?,?)',(CONFIG['username'],CONFIG['salt'],CONFIG['password_hash'],CONFIG['base_path']))
            legacy.unlink(missing_ok=True)
        if not re.fullmatch(r'/[a-zA-Z0-9_-]{16,100}',CONFIG['base_path']):raise ValueError('Некорректный путь панели в базе данных')
        SESSIONS.clear();ATTEMPTS.clear()
        now=time.time()
        # One-time import of sessions created before the database migration; digests and expiry only, never plaintext tokens.
        legacy_sessions=directory/'sessions.json'
        if legacy_sessions.exists():
            try:
                stored=json.loads(legacy_sessions.read_text())
                for key,expiry in stored.items():
                    if isinstance(expiry,(int,float)) and expiry>now:
                        connection.execute('INSERT OR REPLACE INTO sessions VALUES (?,?)',(key,expiry))
            except (OSError,ValueError,AttributeError):pass
            legacy_sessions.unlink(missing_ok=True)
        connection.execute('DELETE FROM sessions WHERE expires_at<=?',(now,))
        SESSIONS.update(dict(connection.execute('SELECT token_hash,expires_at FROM sessions')))
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
    # Store only a digest of each session token in the database; cookies expire after twelve hours and survive a panel restart.
    token=secrets.token_urlsafe(32);key=hashlib.sha256(token.encode()).hexdigest();expiry=now+43200
    with _db() as connection:
        connection.execute('DELETE FROM sessions WHERE expires_at<=?',(now,))
        connection.execute('INSERT OR REPLACE INTO sessions VALUES (?,?)',(key,expiry))
    for stale in [k for k,e in SESSIONS.items() if e<=now]:SESSIONS.pop(stale,None)
    SESSIONS[key]=expiry
    return token


def authenticated(token):
    key=hashlib.sha256(token.encode()).hexdigest()
    return SESSIONS.get(key,0)>time.time()


def logout(token):
    key=hashlib.sha256(token.encode()).hexdigest()
    if SESSIONS.pop(key,None) is not None:
        with _db() as connection:connection.execute('DELETE FROM sessions WHERE token_hash=?',(key,))
