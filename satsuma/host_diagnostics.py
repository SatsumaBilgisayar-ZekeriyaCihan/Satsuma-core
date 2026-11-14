"""Typed systemd diagnostics and metadata-only /dev inspection."""
import os
from pathlib import Path
import re
import stat
import subprocess
import time

UNIT = re.compile(r'[A-Za-z0-9_.:@-]{1,180}\.service')
SENSITIVE = re.compile(r'^/dev/(?:mem|kmem|port|uinput|input/event\d+|sd[a-z]+\d*|nvme\d+n\d+(?:p\d+)?)$')


def systemd_security(unit=None, runner=subprocess.run):
    if unit is not None and (not isinstance(unit, str) or not UNIT.fullmatch(unit)):
        raise ValueError('An explicit service name is required; no paths or shell commands')
    args = ['/usr/bin/systemd-analyze', '--no-pager', 'security']
    if unit:
        args.append(unit)
    try:
        result = runner(args, capture_output=True, text=True, timeout=60,
                        env={'PATH':'/usr/bin:/usr/sbin:/bin', 'LC_ALL':'C', 'SYSTEMD_COLORS':'0', 'SYSTEMD_PAGER':'cat'})
        return {'status': 'COMPLETED' if result.returncode == 0 else 'FAILED',
                'returncode': result.returncode, 'output': (result.stdout+result.stderr)[-50000:],
                'assessment': 'systemd hardening estimate; not an exploit or host-cleanliness verdict'}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'status':'FAILED', 'error':str(exc)[:1000]}


def device_inventory(root=Path('/dev'), limit=8192):
    """lstat/readlink only. Never open, read, write or probe a device node."""
    items, errors = [], []
    for parent, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs+files):
            path = Path(parent)/name
            try:
                info = path.lstat()
                kind = ('symlink' if stat.S_ISLNK(info.st_mode) else 'block' if stat.S_ISBLK(info.st_mode)
                        else 'character' if stat.S_ISCHR(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode) else 'regular')
                item = {'path':str(path), 'type':kind, 'mode':f'{stat.S_IMODE(info.st_mode):04o}',
                        'uid':info.st_uid, 'gid':info.st_gid}
                if kind in ('block','character'):
                    item.update(major=os.major(info.st_rdev), minor=os.minor(info.st_rdev))
                if kind == 'symlink':
                    item['target'] = os.readlink(path)
                item['sensitive_world_access'] = bool(kind in ('block','character')
                    and SENSITIVE.fullmatch(str(path)) and info.st_mode & 0o006)
                items.append(item)
                if len(items) >= limit:
                    return {'status':'PARTIAL', 'truncated':True, 'items':items, 'errors':errors}
            except OSError as exc:
                errors.append({'path':str(path), 'error':str(exc)[:200]})
    return {'status':'COMPLETED' if not errors else 'PARTIAL', 'truncated':False, 'items':items, 'errors':errors}


def run_audit(store, kind, unit=None):
    if kind == 'systemd':
        result = systemd_security(unit)
    elif kind == 'devices':
        result = device_inventory()
    else:
        raise ValueError('Unsupported host audit')
    from .protected_storage import RootDataStore
    name = 'diagnostics/'+kind+'-'+str(time.time_ns())+'.json'
    RootDataStore(name).replace(result)
    store.set('host_audit_'+kind, {'status':result['status'], 'report':name, 'checked_at':time.time()})
    if kind == 'devices':
        from .pipeline import Pipeline
        from .config import load
        pipeline=Pipeline(store,load())
        for item in result['items']:
            if item.get('sensitive_world_access'):
                pipeline.ingest_host({'source':'device_inventory','action':'sensitive_device_world_access','file_path':item['path'],'timestamp':time.time(),'device_metadata':item})
    store.add('events', {'source':'host_diagnostics', 'action':kind, 'status':result['status'], 'report':name, 'timestamp':time.time()})
    return result


def main():
    import argparse
    import json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind', required=True, choices=('systemd','devices'))
    args=parser.parse_args()
    if os.geteuid()!=0:
        raise PermissionError('Host diagnostics require root')
    from .store import Store
    store=Store()
    try:
        result=run_audit(store,args.kind)
        print(json.dumps(result,ensure_ascii=False))
        return 0 if result['status']=='COMPLETED' else 1
    finally:
        store.close()


if __name__=='__main__':
    raise SystemExit(main())
