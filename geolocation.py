"""Country lookup against a locally cached DB-IP Lite database."""
import csv
import datetime
import functools
import gzip
import ipaddress
import re
import socket
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


def addresses(host):
    host=str(host or '').strip().strip('[]')
    if not host or len(host)>253:raise ValueError('Укажите публичный IP или домен службы')
    try:
        results=socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError('Не удалось определить IP адреса службы') from error
    ips=[]
    for result in results:
        ip=ipaddress.ip_address(result[4][0].split('%')[0])
        if ip.is_global and ip not in ips:ips.append(ip)
    if not ips:raise ValueError('У адреса службы нет публичного IP')
    if len(ips)>16:raise ValueError('У домена слишком много IP для определения страны')
    return tuple(ips)


def database(directory):
    month=datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m')
    target=Path(directory)/('dbip-country-lite-'+month+'.csv.gz')
    if target.is_file():return target
    target.parent.mkdir(parents=True,exist_ok=True)
    url='https://download.db-ip.com/free/'+target.name
    try:
        request=urllib.request.Request(url,headers={'User-Agent':'Mozilla/5.0'})
        with urllib.request.urlopen(request,timeout=30) as response, tempfile.NamedTemporaryFile(dir=target.parent,delete=False) as tmp:
            temporary=Path(tmp.name)
            try:
                total=0
                while True:
                    chunk=response.read(65536)
                    if not chunk:break
                    total+=len(chunk)
                    if total>20_000_000:raise ValueError('База стран превышает допустимый размер')
                    tmp.write(chunk)
                if total==0:raise ValueError('Загружена пустая база стран')
                tmp.flush()
                with gzip.open(temporary,'rt',encoding='utf-8',newline='') as source:
                    if len(next(csv.reader(source)))!=3:raise ValueError('Некорректная база стран')
                temporary.replace(target)
            finally:
                temporary.unlink(missing_ok=True)
    except (OSError,urllib.error.URLError,EOFError,StopIteration) as error:
        raise ValueError('Не удалось загрузить базу стран DB-IP') from error
    return target


@functools.lru_cache(maxsize=256)
def lookup(path,ips):
    remaining=set(ips);countries=set()
    try:
        with gzip.open(path,'rt',encoding='utf-8',newline='') as source:
            for start,end,country in csv.reader(source):
                version=6 if ':' in start else 4
                candidates=[ip for ip in remaining if ip.version==version]
                if not candidates:continue
                first,last=ipaddress.ip_address(start),ipaddress.ip_address(end)
                for ip in candidates:
                    if first<=ip<=last:
                        if not re.fullmatch(r'[A-Z]{2}',country):raise ValueError('Для адреса неизвестна страна')
                        countries.add(country);remaining.remove(ip)
                if not remaining:break
    except (OSError,EOFError,csv.Error) as error:
        raise ValueError('Не удалось прочитать базу стран DB-IP') from error
    if remaining:raise ValueError('Страна адреса не найдена в базе DB-IP')
    if len(countries)!=1:raise ValueError('IP домена находятся в разных странах; укажите страну вручную')
    return countries.pop()


def country(host,directory):
    ips=addresses(host)
    return lookup(str(database(directory)),ips)
