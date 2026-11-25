"""Audited registry references and pinned source build recipes. No arbitrary build URLs."""
import copy
import image_updates
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parent
AUDIT='2026-11-15'
CATALOG=[
 dict(id='webproxy',name='Telegram WebProxy',protocols=['webproxy'],reference='yptun/webproxy:44aa88ac176e',source='https://github.com/kesevone/tgwebproxy',revision='44aa88ac176ee89a9bf8cdf1b76227d8c653f2a1',recipe='webproxy.Dockerfile',command=['-config','/etc/yptun/relay.toml'],note='WEB-прокси Telegram с отдельными секретами. Нужен отдельный домен и HTTPS nginx панели.'),
 dict(id='wdtt',name='qWDTT 1.4.3 · TURN',protocols=['wdtt'],reference='yptun/wdtt:1.4.3',source='https://github.com/SpaceNeuroX/proxy-turn-vk-android',revision='fae121efc3ef57b633516601d3c0d6b1be1fde7c',recipe='wdtt.Dockerfile',sparse='server',command=[],note='Изолированный TURN-туннель с штатным API управления, до 10 пользователей. Нужен /dev/net/tun.'),
 dict(id='xray',name='Xray',protocols=['vless','vmess','trojan','shadowsocks','raw'],reference='ghcr.io/xtls/xray-core:26.9.30',source='https://github.com/XTLS/Xray-core',command=['run','-config','/etc/yptun/config.conf']),
 dict(id='singbox',name='sing-box',protocols=['hysteria2','raw'],reference='ghcr.io/sagernet/sing-box:v1.12.0',source='https://github.com/SagerNet/sing-box',command=['run','-c','/etc/yptun/config.conf']),
 dict(id='wireguard',name='WireGuard · LinuxServer',protocols=['wireguard'],reference='lscr.io/linuxserver/wireguard:latest',source='https://docs.linuxserver.io/images/docker-wireguard/',command=[],config_path='/config/wg_confs/wg0.conf',note='Конфиг сервера и отдельные пиры создаются автоматически. Нужен WireGuard в ядре хоста; модули хоста не загружаются.'),
 dict(id='amneziawg',name='AmneziaWG · AYastrebov',protocols=['amneziawg'],reference='ghcr.io/ayastrebov/docker-amneziawg:latest',source='https://github.com/AYastrebov/docker-amneziawg',command=[],config_path='/config/wg_confs/wg0.conf',note='Сторонний образ с userspace fallback; версия AWG должна соответствовать клиенту.'),
 dict(id='masterdns',name='MasterDnsVPN',protocols=['masterdns'],reference='ghcr.io/masterking32/masterdnsvpn:latest',source='https://github.com/masterking32/MasterDnsVPN',command=['-nowait'],config_path='/data/server_config.toml',note='Панель генерирует TOML и ключ AES-256-GCM. Для прямого резолвера используется случайный порт; DNS-делегация требует доступного UDP 53.'),
 dict(id='trusttunnel',name='TrustTunnel endpoint',protocols=['trusttunnel'],reference='trusttunnel/trusttunnel-endpoint:latest',source='https://github.com/TrustTunnel/TrustTunnel',command=[],note='Панель создаёт конфигурации и отдельные учётные записи. Сертификат службы выпускается кнопкой.'),
 dict(id='warp',name='WARP · caomingjun',protocols=['warp'],reference='caomingjun/warp:latest',source='https://github.com/cmj2002/warp-docker',command=[],note='Вход VLESS + Reality, выход через WARP. SOCKS5 остаётся внутри приватной Docker-сети.'),
 dict(id='freeturn',name='Free TURN · arisudesu',protocols=['vkturn'],reference='ghcr.io/arisudesu/free-turn-proxy:latest',source='https://github.com/arisudesu/free-turn-proxy',command=[],note='Панель создаёт WireGuard-backend, ключи и ссылку FreeTURN. Ссылку на VK-звонок укажите при выдаче доступа.'),
 dict(id='olcrtc',name='olcRTC · ghostlane',protocols=['olcrtc'],reference='yptun/olcrtc:a6cd0ab2a362',source='https://github.com/ghostlane-project/olcrtc',revision='a6cd0ab2a362837acda10d50dfdf230af8db91d2',recipe='olcrtc.Dockerfile',command=['/etc/yptun/config.conf'],note='Закреплённая сборка OLC2. Панель генерирует YAML и ключ; укажите сервис звонков и комнату.'),
 dict(id='openflux',name='OpenFlux · exit L4',protocols=['openflux'],reference='yptun/openflux:f12e981629a1',source='https://github.com/p1neappleXpress/OpenFlux',revision='f12e981629a18c8c01007d59ac002254c02972bb',recipe='openflux.Dockerfile',command=['--role=exit','--mode=l4','--transport=yandex'],note='OpenFlux 0.7.3. Формат cups.online определяется по ссылке комнат. Панель создаёт комнаты автоматически.'),
 dict(id='snolc',name='snolc · YPtun builtin 0.0.4',protocols=['snolc'],reference='yptun/snolc:yptun-2a8f9517fa9a',source='https://github.com/yanisplugg/yptun',revision='2a8f9517fa9a62fa2f50dcf1e57b41cec8c6d0cc',recipe='snolc.Dockerfile',sparse='snolc',command=['run','/etc/yptun/snolc.toml'],note='Совместимый бинарник YPtun со встроенными модулями. Конфиги и Noise-ключи генерируются панелью.'),
 dict(id='mieru',name='Mieru (mita)',protocols=['mieru'],reference='yptun/mieru:3.39.0',source='https://github.com/enfein/mieru',revision='bcd14b88d0fb7e7707bb80e5d7f6c33675d26c06',recipe='mieru.Dockerfile',command=[],note='Закреплённая сборка mita (mieru) из исходников. Диапазон TCP/UDP-портов и пользователи задаются панелью; состояние mita хранится в отдельном volume.'),
]
BY_IMAGE={i['id']:i for i in CATALOG}
JOBS={}
LOCK=threading.Lock()


def image_list():
    local=set()
    if os.environ.get('YPTUN_ALLOW_DOCKER')=='1':
        try:
            r=subprocess.run(['docker','image','ls','--format','{{.Repository}}:{{.Tag}}'],capture_output=True,text=True,timeout=10)
            if r.returncode==0:local=set(r.stdout.splitlines())
        except (OSError,subprocess.TimeoutExpired):pass
    with LOCK:
        return [dict(image_updates.current(i),update=image_updates.snapshot(i['id']),kind='build' if i.get('recipe') else 'registry',verified_at=None if i.get('recipe') else AUDIT,local=image_updates.current(i)['reference'] in local,job=copy.deepcopy(JOBS.get(i['id']))) for i in CATALOG]


def command(args,job,cwd=None,timeout=1200):
    # Persist neither credentials nor environment; only known public repository URLs are used.
    if job.get('stream'):
        result=subprocess.run(args,cwd=cwd,stdout=sys.stderr,stderr=subprocess.STDOUT,text=True,timeout=timeout)
        if result.returncode:raise ValueError('Команда завершилась с кодом '+str(result.returncode))
        return ''
    with tempfile.TemporaryFile(mode='w+') as log:
        try:
            r=subprocess.run(args,cwd=cwd,stdout=log,stderr=subprocess.STDOUT,text=True,timeout=timeout)
        finally:
            log.seek(0);output=log.read()[-12000:]
            with LOCK:job['log']=(job.get('log','')+'\n'+output)[-16000:]
        if r.returncode:raise ValueError('Команда завершилась с кодом '+str(r.returncode))
        return output


def start_job(id,action,data_dir,force=True,restart_services=None):
    if os.environ.get('YPTUN_ALLOW_DOCKER')!='1':raise ValueError('Управление Docker отключено')
    if not isinstance(force,bool):raise ValueError('force должен быть логическим значением')
    if action=='check-updates' and id=='all':
        threading.Thread(target=image_updates.check_all,args=(CATALOG,force),daemon=True).start()
        return dict(status='running')
    image=BY_IMAGE.get(id)
    if not image:raise ValueError('Неизвестный образ')
    if action not in ('check','pull','build','check-updates','update'):raise ValueError('Неизвестная операция с образом')
    if action=='pull' and image.get('recipe'):raise ValueError('У этого движка нет найденного готового образа; выберите сборку')
    if action=='build' and not image.get('recipe'):raise ValueError('Для этого движка есть готовый образ; выберите скачивание')
    with LOCK:
        if any(j['status']=='running' for j in JOBS.values()):raise ValueError('Дождитесь завершения текущей операции с образами')
        job=dict(action=action,status='running',started=time.time(),log='');JOBS[id]=job
    def work():
        try:
            if action=='check-updates':
                result=image_updates.check_one(image,force=force)
                if result.get('error'):raise ValueError(result['error'])
            elif action=='update':
                selected=image_updates.apply_update(image,data_dir,job,prepare_image,command,restart_services=restart_services)
                with LOCK:job['reference']=selected['reference']
            else:prepare_image(image_updates.current(image),action,data_dir,job)
            if action in ('build','update'):
                try:command(['/bin/sh',str(ROOT/'deploy'/'cleanup-images.sh')],job,timeout=600)
                except Exception as error:
                    with LOCK:job['cleanup_error']=str(error)
            with LOCK:job.update(status='succeeded',finished=time.time())
        except Exception as e:
            with LOCK:job.update(status='failed',finished=time.time(),error=str(e))
    threading.Thread(target=work,daemon=True).start()
    return copy.deepcopy(job)


def prepare_image(image,action,data_dir,job=None):
    """Shared synchronous operation for the installer and background UI jobs."""
    job=job if job is not None else dict(log='')
    if action=='check':
        args=['docker','image','inspect',image['reference']] if image.get('recipe') else ['docker','manifest','inspect',image['reference']]
        command(args,job,timeout=60)
    elif action=='pull':command(['docker','pull',image['reference']],job,timeout=600)
    else:
        builds=Path(data_dir)/'image-builds';builds.mkdir(mode=0o700,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=builds) as tmp:
            context=Path(tmp)/'source'
            command(['git','init',str(context)],job)
            command(['git','remote','add','origin',image['source']+'.git'],job,cwd=context)
            command(['git','fetch','--filter=blob:none','--no-tags','--depth','1','origin',image['revision']],job,cwd=context,timeout=180)
            if image.get('sparse'):command(['git','sparse-checkout','set',image['sparse']],job,cwd=context)
            command(['git','checkout','--detach','FETCH_HEAD'],job,cwd=context)
            dockerfile=Path(tmp)/'Dockerfile';shutil.copyfile(ROOT/'images'/image['recipe'],dockerfile)
            command(['docker','build','--label','org.opencontainers.image.revision='+image['revision'],'-f',str(dockerfile),'-t',image['reference'],str(context)],job,timeout=1800)

