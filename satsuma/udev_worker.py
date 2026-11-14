"""Udev lifecycle + observed process/device associations; never infer guilt from timing."""
from collections import deque
from itertools import islice
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

FIELDS = {'ACTION','DEVPATH','DEVNAME','SUBSYSTEM','DEVTYPE','SEQNUM','ID_BUS','ID_VENDOR_ID','ID_MODEL_ID','DRIVER'}


def parse_properties(lines):
    data = {}
    for line in lines:
        key, sep, value = line.partition('=')
        if sep and key in FIELDS and len(value) <= 1024:
            data[key] = value
    name = data.get('DEVNAME', '')
    if data.get('ACTION') not in ('add','remove','change','bind','unbind','move'):
        return None
    if name and (not name.startswith('/dev/') or '..' in Path(name).parts):
        return None
    if not data.get('DEVPATH', '').startswith('/devices/'):
        return None
    return data


def device_users(targets, proc=Path('/proc'), max_pids=2048, max_fds=128):
    from .process_identity import capture_process_identity
    result = []
    with os.scandir(proc) as processes:
        for process in islice((p for p in processes if p.name.isdigit()),max_pids):
            try:
                directory=Path(process.path)
                with (directory/'stat').open() as stream:
                    before=int(stream.read(4096).rsplit(')',1)[1].split()[19])
                matching=set()
                with os.scandir(directory/'fd') as descriptors:
                    for fd in islice(descriptors,max_fds):
                        try:
                            target=os.readlink(fd.path).removesuffix(' (deleted)')
                            if target in targets:matching.add(target)
                        except OSError:continue
                if matching:
                    identity=capture_process_identity(int(process.name))
                    if identity and identity.get('starttime')==before:
                        allowed={'boot_id','pid','starttime','exe','uid','gid','ppid','exe_device','exe_inode','cgroup','systemd_unit'}
                        result.append({'identity':{k:v for k,v in identity.items() if k in allowed},'devices':sorted(matching)})
            except (OSError,ValueError,IndexError):continue
    return result



class UdevTracker:
    def __init__(self, store, pipeline, users=device_users, clock=time.time):
        self.store, self.pipeline, self.users, self.clock = store, pipeline, users, clock
        self.recent = {}
        self.seen = deque(maxlen=2048)
        self.associations = set()

    def ingest(self, event):
        key = (event.get('SEQNUM'),event['ACTION'],event['DEVPATH'])
        if key in self.seen:
            return
        now = self.clock()
        self.pipeline.ingest_host({'source':'udev', 'kind':'udev_device', 'action':'udev_device',
            'timestamp':now, 'file_path':event.get('DEVNAME',''), 'udev':event})
        if event.get('DEVNAME'):
            self.recent[event['DEVNAME']] = (now,event)
        self.store.add('findings', {'rule_id':'SATSUMA-UDEV-001', 'title':'Udev aygıt yaşam döngüsü olayı',
            'source':'udev', 'severity':'info', 'classification':'indicator', 'timestamp':now,
            'event':event, 'interpretation':'Aygıt değişikliği gözlendi; saldırı kanıtı değildir'})
        self.seen.append(key)
        self.store.set('udev_health', {'status':'RUNNING', 'last_event_at':now, 'last_action':event['ACTION']})

    def poll_processes(self):
        now = self.clock()
        self.recent = {p:v for p,v in self.recent.items() if now-v[0] <= 120}
        targets = set(list(self.recent)[-128:])
        if not targets:
            return
        for entry in self.users(targets):
            identity = entry['identity']
            for device in entry['devices']:
                key = (identity.get('boot_id'),identity['pid'],identity.get('starttime'),device)
                if key in self.associations:
                    continue
                observed, event = self.recent[device]
                evidence = {'source':'udev_process_context', 'kind':'device_process_access',
                    'action':'device_process_access', 'timestamp':now, 'file_path':device,
                    'pid':identity['pid'], 'exe':identity.get('exe'), 'uid':identity.get('uid'),
                    'device_event':event, 'process_identity':identity,
                    'elapsed_since_udev':now-observed, 'correlation_only':True}
                self.pipeline.ingest_host(evidence)
                self.store.add('findings', {**evidence, 'rule_id':'SATSUMA-UDEV-002',
                    'title':'Udev olayı sonrası aygıta erişen süreç gözlendi', 'severity':'low',
                    'classification':'indicator', 'interpretation':'Açık dosya tanıtıcısı ile ilişki; tek başına kötü niyet veya engelleme yetkisi değildir'})
                self.associations.add(key)
        if len(self.associations) > 8192:
            self.associations.clear()


def main():
    from .store import Store
    from .pipeline import Pipeline
    from .config import load
    store = Store()
    tracker = UdevTracker(store, Pipeline(store, load()))
    process = subprocess.Popen(['/usr/bin/udevadm','monitor','--udev','--property'],
        stdout=subprocess.PIPE, stderr=None, env={'PATH':'/usr/bin:/usr/sbin:/bin','LC_ALL':'C'})
    os.set_blocking(process.stdout.fileno(), False)
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    running = True
    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    buffer, lines, last = b'', [], 0
    try:
        while running and process.poll() is None:
            if selector.select(timeout=1):
                chunk = os.read(process.stdout.fileno(),65536)
                buffer += chunk
                if len(buffer) > 131072:
                    buffer, lines = b'', []
                    store.add('errors', {'component':'udev', 'error':'Oversized udev property block rejected'})
                while b'\n' in buffer:
                    raw, buffer = buffer.split(b'\n',1)
                    line = raw.decode('utf-8',errors='replace').strip()
                    if not line:
                        event = parse_properties(lines)
                        if event:
                            tracker.ingest(event)
                        lines = []
                    elif len(lines) < 256:
                        lines.append(line)
                    else:
                        lines = []
            if time.monotonic()-last >= 2:
                tracker.poll_processes()
                last = time.monotonic()
                store.set('udev_health', {'status':'RUNNING', 'updated_at':time.time(), 'coverage':'sampled open-device descriptors after observed udev events'})
        if running:
            raise RuntimeError('udevadm monitor exited: '+str(process.returncode))
    except Exception as exc:
        store.set('udev_health', {'status':'DEGRADED', 'error':str(exc)[:500], 'updated_at':time.time()})
        raise
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill();process.wait(timeout=5)
        selector.close()
        if not running:
            store.set('udev_health', {'status':'STOPPED', 'updated_at':time.time()})
        store.close()
