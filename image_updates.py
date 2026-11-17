"""Cached discovery of catalog image updates; checks never pull or run containers."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import threading
import time
import urllib.request

INTERVAL=24*3600
LOCK=threading.RLock()
CHECK_LOCK=threading.Lock()
DATA=None
SELECTED={}
CHECKS={}
CHECKING=False
RELEASES={'xray':False,'singbox':True}
DIGEST=re.compile(r'sha256:[a-f0-9]{64}')
REVISION=re.compile(r'[a-f0-9]{40}')


def repository(reference):return reference.rsplit(':',1)[0]


def valid_selection(image,value):
    reference=value.get('reference','')
    prefix=repository(image['reference'])+':'
    if not isinstance(reference,str) or not reference.startswith(prefix) or not re.fullmatch(r'[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}',reference[len(prefix):]):return False
    return not image.get('recipe') or bool(REVISION.fullmatch(value.get('revision','')))


def configure(data_dir,catalog):
    global DATA,SELECTED,CHECKS
    with LOCK:
        DATA=Path(data_dir);SELECTED={};CHECKS={}
        try:
            saved=json.loads((DATA/'image-updates.json').read_text())
            for image in catalog:
                value=saved.get('selected',{}).get(image['id'])
                if isinstance(value,dict) and value.get('base_reference')==image['reference'] and value.get('base_revision')==image.get('revision') and valid_selection(image,value):
                    SELECTED[image['id']]={key:value[key] for key in ('reference','revision','digest','image_id','base_reference','base_revision') if key in value}
                check=saved.get('checks',{}).get(image['id'])
                if isinstance(check,dict) and isinstance(check.get('checked_at'),(int,float)) and check.get('current_reference')==current(image)['reference']:
                    CHECKS[image['id']]=check
        except (OSError,ValueError,TypeError,AttributeError):pass


def save_locked():
    if DATA is None:return
    DATA.mkdir(mode=0o700,parents=True,exist_ok=True)
    target=DATA/'image-updates.json';tmp=target.with_suffix('.tmp')
    tmp.write_text(json.dumps(dict(selected=SELECTED,checks=CHECKS),ensure_ascii=False))
    os.chmod(tmp,0o600);tmp.replace(target)


def current(image):
    with LOCK:return dict(image,**copy.deepcopy(SELECTED.get(image.get('id'),{})))


def snapshot(id):
    with LOCK:return copy.deepcopy(CHECKS.get(id,{}))


def summary():
    with LOCK:
        available=[id for id,value in CHECKS.items() if value.get('available')]
        return dict(count=len(available),available=available,checking=CHECKING,checked_at=max((v.get('checked_at',0) for v in CHECKS.values()),default=None))


def output(args,timeout=45):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout)
    if result.returncode:raise ValueError(result.stderr[-1000:] or 'Не удалось получить сведения об образе')
    return result.stdout


def local_image(reference):
    result=subprocess.run(['docker','image','inspect',reference],capture_output=True,text=True,timeout=10)
    if result.returncode:
        if 'No such image' in result.stderr or 'No such object' in result.stderr:return None
        raise ValueError('Не удалось прочитать локальный образ: '+result.stderr[-500:])
    values=json.loads(result.stdout)
    if not isinstance(values,list) or not values:raise ValueError('Docker вернул некорректные сведения об образе')
    return values[0]


def manifest(reference,platform=None):
    try:
        value=json.loads(output(['docker','buildx','imagetools','inspect',reference,'--format','{{json .Manifest}}']))
        if isinstance(value,dict) and DIGEST.fullmatch(value.get('digest','')):return value
    except (ValueError,subprocess.SubprocessError):pass
    # Existing installations may have Docker without the optional Buildx plugin.
    value=json.loads(output(['docker','manifest','inspect','--verbose',reference]))
    entries=value if isinstance(value,list) else [value]
    for item in entries:
        if not isinstance(item,dict):continue
        descriptor=item.get('Descriptor') or {}
        found=descriptor.get('platform') or item.get('Platform') or {}
        if platform and any(found.get(key)!=expected for key,expected in platform.items()):continue
        digest=descriptor.get('digest') or item.get('Digest')
        config=(item.get('SchemaV2Manifest') or item.get('OCIManifest') or {}).get('config',{})
        if DIGEST.fullmatch(digest or ''):return dict(digest=digest,config_digest=config.get('digest'))
    raise ValueError('Реестр не вернул образ для нужной платформы')


def release_reference(image):
    if image['id'] not in RELEASES:return image['reference']
    repo=image['source'][len('https://github.com/'):]
    request=urllib.request.Request('https://api.github.com/repos/'+repo+'/releases/latest',headers={'Accept':'application/vnd.github+json','User-Agent':'YPtun-panel'})
    with urllib.request.urlopen(request,timeout=15) as response:value=json.loads(response.read(1_000_000))
    if not isinstance(value,dict):raise ValueError('GitHub вернул некорректные сведения о версии')
    tag=value.get('tag_name','')
    if value.get('prerelease') or value.get('draft') or not re.fullmatch(r'v?[0-9]+(?:\.[0-9]+){1,3}',tag):raise ValueError('Не удалось определить стабильную версию образа')
    old=image['reference'].rsplit(':',1)[1]
    version=lambda text:tuple(int(part) for part in text.lstrip('v').split('.'))
    if not re.fullmatch(r'v?[0-9]+(?:\.[0-9]+){1,3}',old) or version(tag)<=version(old):return image['reference']
    tag=('v' if RELEASES[image['id']] else '')+tag.lstrip('v')
    return repository(image['reference'])+':'+tag


def discover(image):
    active=current(image);local=local_image(active['reference'])
    if image.get('recipe'):
        text=output(['git','ls-remote','--exit-code',image['source']+'.git',image.get('update_ref','HEAD')],timeout=30)
        revision=next((line.split()[0] for line in text.splitlines() if line.split()),'')
        if not REVISION.fullmatch(revision):raise ValueError('Git не вернул ревизию исходников')
        installed=((local or {}).get('Config') or {}).get('Labels') or {}
        installed_revision=installed.get('org.opencontainers.image.revision',active['revision'])
        reference=repository(image['reference'])+':'+revision[:12] if revision!=active['revision'] else active['reference']
        return dict(available=bool(local and revision!=installed_revision),installed=bool(local),reference=reference,revision=revision,current_reference=active['reference'],current_revision=installed_revision,checked_at=time.time())
    platform={key:local[field] for key,field in (('os','Os'),('architecture','Architecture')) if local and local.get(field)}
    reference=release_reference(active);remote=manifest(reference,platform=platform or None)
    digests={remote['digest']}|{item.get('digest') for item in remote.get('manifests',[])}
    installed={(value.rsplit('@',1)[-1]) for value in (local or {}).get('RepoDigests',[])}
    # A saved digest is usable only while the corresponding local image ID agrees.
    if local and active.get('image_id')==local.get('Id') and active.get('digest'):installed.add(active['digest'])
    same=bool(installed.intersection(digests) or local and remote.get('config_digest') and local.get('Id')==remote['config_digest'])
    available=bool(local and (reference!=active['reference'] or not same))
    return dict(available=available,installed=bool(local),reference=reference,digest=remote['digest'],current_reference=active['reference'],checked_at=time.time())


def check_one(image,force=False):
    cached=snapshot(image['id'])
    if not force and cached and 0<=time.time()-cached.get('checked_at',0)<INTERVAL:return cached
    before=current(image)
    try:result=discover(image)
    except (OSError,ValueError,KeyError,TypeError,AttributeError,subprocess.SubprocessError) as error:
        with LOCK:
            result=dict(CHECKS.get(image['id'],{}),current_reference=before['reference'],checked_at=time.time(),error=str(error)[:1000])
    with LOCK:
        if current(image)!=before:return snapshot(image['id'])
        CHECKS[image['id']]=result;save_locked()
    return result


def check_all(catalog,force=False):
    global CHECKING
    if not CHECK_LOCK.acquire(blocking=False):return
    with LOCK:CHECKING=True
    try:
        for image in catalog:check_one(image,force=force)
    finally:
        with LOCK:CHECKING=False
        CHECK_LOCK.release()


def apply_update(image,data_dir,job,prepare,command,restart_services=None):
    candidate=snapshot(image['id'])
    if not candidate or time.time()-candidate.get('checked_at',0)>INTERVAL:candidate=check_one(image)
    if candidate.get('error'):raise ValueError('Проверка обновления завершилась ошибкой; повторите её перед обновлением')
    if not candidate.get('available'):raise ValueError('Нет доступного обновления; сначала проверьте версии')
    if not valid_selection(image,candidate):raise ValueError('Некорректная версия обновления')
    active=current(image)
    previous_local=local_image(active['reference']) if restart_services else None
    target=dict(image,reference=candidate['reference'])
    if image.get('recipe'):
        target['revision']=candidate['revision'];prepare(target,'build',data_dir,job)
    else:
        digest=candidate.get('digest','')
        if not DIGEST.fullmatch(digest):raise ValueError('Некорректный digest обновления')
        pinned=repository(target['reference'])+'@'+digest
        command(['docker','pull',pinned],job,timeout=600)
        command(['docker','tag',pinned,target['reference']],job,timeout=30)
    local=local_image(target['reference'])
    if not local:raise ValueError('Обновлённый образ не найден после установки')
    selected=dict(reference=target['reference'],image_id=local['Id'],base_reference=image['reference'],base_revision=image.get('revision'))
    if image.get('recipe'):
        labels=(local.get('Config') or {}).get('Labels') or {}
        if labels.get('org.opencontainers.image.revision')!=target['revision']:raise ValueError('Сборка не подтвердила ревизию образа')
        selected['revision']=target['revision']
    else:selected['digest']=candidate['digest']
    with LOCK:
        previous=copy.deepcopy(SELECTED);checks=copy.deepcopy(CHECKS)
        try:
            SELECTED[image['id']]=selected
            CHECKS[image['id']]=dict(candidate,available=False,current_reference=selected['reference'],checked_at=time.time(),installed=True)
            save_locked()
        except Exception:
            SELECTED.clear();SELECTED.update(previous);CHECKS.clear();CHECKS.update(checks);raise
    try:
        if restart_services:restart_services(image,selected,job)
    except Exception:
        with LOCK:
            if image['id'] in previous:SELECTED[image['id']]=previous[image['id']]
            else:SELECTED.pop(image['id'],None)
            CHECKS[image['id']]=candidate
            save_locked()
        if previous_local and previous_local.get('Id') and target['reference']==active['reference']:
            command(['docker','tag',previous_local['Id'],active['reference']],job,timeout=30)
        raise
    with LOCK:job['reference']=selected['reference']
