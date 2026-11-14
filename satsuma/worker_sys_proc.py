"""Satsuma Core — sys_proc worker.

TEK GÖREV: /proc ve /sys'den HAM veri topla, pipeline'a gönder.
"""
from .worker_delivery import delivered_tick
import shlex
import os
import re
import time
from datetime import datetime, timezone
from pathlib import Path


def _iso_now():
    """ISO 8601 timestamp (SuricataMapper string bekliyor)."""
    return datetime.now(timezone.utc).astimezone().isoformat()


class WorkerSysProc:
    name = "sys_proc"

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self._next_collect = 0.0
        self.raw_key = 'worker.sys_proc.raw'
        self.history_key = 'worker.sys_proc.history'
        self.health_key = 'worker.sys_proc.health'
        self.baseline_key = 'worker.sys_proc.baseline'
        self.boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        saved = self.store.get(self.baseline_key, None)
        if isinstance(saved,dict) and saved.get('boot_id') != self.boot_id:
            saved=None
        if isinstance(saved, dict):
            self._last_processes = {int(k): v for k, v in (saved.get('processes') or {}).items() if str(k).isdigit()}
            self._last_modules = set(saved.get('modules') or [])
            self._last_usb = set(saved.get('usb') or [])
            self._last_ports = set(saved.get('ports') or [])
            self._last_taint = int(saved.get('taint', -1))
            self._baseline_initialized = True
        else:
            self._last_processes = {}
            self._last_modules = set()
            self._last_usb = set()
            self._last_ports = set()
            self._last_taint = -1
            self._baseline_initialized = False

    def _collect_processes(self):
        procs = {}
        try:
            uptime = float(Path('/proc/uptime').read_text().split()[0])
            hz = os.sysconf('SC_CLK_TCK')
        except Exception:
            uptime = 0
            hz = 100
        try:
            for pid_dir in Path('/proc').iterdir():
                if not pid_dir.name.isdigit():
                    continue
                pid = int(pid_dir.name)
                try:
                    with (pid_dir / 'cmdline').open('rb') as stream:
                        cmdline_raw = stream.read(65536)
                    cmdline = shlex.join([part.decode('utf-8','replace') for part in cmdline_raw.split(b'\0') if part])
                    if not cmdline:
                        continue
                    status = (pid_dir / 'status').read_text(errors='replace')
                    user_match = re.search(r'^Uid:\s+(\d+)', status, re.M)
                    ppid_match = re.search(r'^PPid:\s+(\d+)', status, re.M)
                    stat_content = (pid_dir / 'stat').read_text(errors='replace')
                    stat_fields = stat_content.rsplit(')', 1)[-1].split()
                    starttime_jiffies = int(stat_fields[19]) if len(stat_fields) > 19 else 0
                    start_seconds = starttime_jiffies / hz
                    age_seconds = max(0, uptime - start_seconds)
                    try:
                        exe = os.readlink(str(pid_dir / 'exe'))
                    except (OSError, PermissionError):
                        exe = ''
                    # Retain only presence of loader variables, never environment values/secrets.
                    loader_env = ''
                    try:
                        with (pid_dir / 'environ').open('rb') as stream:
                            names = {entry.split(b'=', 1)[0] for entry in stream.read(65536).split(b'\0')}
                        loader_env = ' '.join(name+'=present' for name in ('LD_PRELOAD','LD_LIBRARY_PATH') if name.encode() in names)
                    except OSError:
                        pass
                    procs[pid] = {
                        'env': loader_env,
                        'cmd': cmdline[:4096],
                        'uid': int(user_match.group(1)) if user_match else -1,
                        'ppid': int(ppid_match.group(1)) if ppid_match else -1,
                        'age_seconds': int(age_seconds),
                        'start_seconds': int(start_seconds),
                        'starttime_jiffies': int(starttime_jiffies),
                        'exe': exe,
                    }
                except Exception:
                    continue
        except Exception:
            pass
        # Parent command bilgisini ayni snapshot icinden bagla. /proc yarisi
        # nedeniyle bulunamayan parent bos kalir, tahmin edilmez.
        for pid, item in procs.items():
            parent = procs.get(item.get('ppid'))
            item['parent_cmd'] = parent.get('cmd', '') if parent else ''
        return procs

    def _collect_modules(self):
        try:
            with open('/proc/modules') as f:
                return sorted(line.split()[0] for line in f if line.strip())
        except Exception as exc:
            raise RuntimeError('Required host telemetry unavailable') from exc

    def _collect_sys_modules(self):
        try:
            return sorted(os.listdir('/sys/module/'))
        except Exception as exc:
            raise RuntimeError('Required host telemetry unavailable') from exc

    def _collect_usb(self):
        devices = []
        usb_dir = Path('/sys/bus/usb/devices')
        if not usb_dir.exists():
            return devices
        for dev in usb_dir.iterdir():
            entry = {'path': dev.name}
            for field in ('product', 'manufacturer', 'idVendor', 'idProduct'):
                f = dev / field
                if f.exists():
                    try:
                        entry[field] = f.read_text().strip()
                    except Exception:
                        pass
            devices.append(entry)
        return devices

    def _collect_pci(self):
        devices = []
        pci_dir = Path('/sys/bus/pci/devices')
        if not pci_dir.exists():
            return devices
        for dev in pci_dir.iterdir():
            entry = {'path': dev.name}
            for field in ('vendor', 'device', 'class'):
                f = dev / field
                if f.exists():
                    try:
                        entry[field] = f.read_text().strip()
                    except Exception:
                        pass
            devices.append(entry)
        return devices

    def _collect_ports(self):
        import subprocess
        try:
            r = subprocess.run(['ss', '-tulnH'], capture_output=True, text=True, timeout=5)
            if r.returncode:
                raise RuntimeError('Listening socket collection failed: ' + r.stderr[:200])
            ports = []
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    ports.append({'proto': parts[0], 'local': parts[4]})
            return ports
        except Exception as exc:
            raise RuntimeError('Required host telemetry unavailable') from exc

    def _collect_kernel_taint(self):
        try:
            with open('/proc/sys/kernel/tainted') as f:
                return int(f.read().strip())
        except Exception:
            return -1

    def collect(self):
        return {
            'timestamp': int(time.time()),
            'uptime': float(open('/proc/uptime').read().split()[0]) if os.path.exists('/proc/uptime') else 0,
            'processes': self._collect_processes(),
            'modules': self._collect_modules(),
            'sys_modules': self._collect_sys_modules(),
            'usb': self._collect_usb(),
            'pci': self._collect_pci(),
            'ports': self._collect_ports(),
            'kernel_taint': self._collect_kernel_taint(),
        }

    def _raw_to_events(self, raw):
        """Ham veriyi host event'lerine çevir. timestamp ISO string!"""
        events = []
        ts = _iso_now()  # ← ISO string

        # İlk açılışta mevcut sistemi baseline kabul et. Böylece servis restartı
        # makinedeki tüm süreçleri yeniden "new_process" yapmaz.
        procs = raw.get('processes', {})
        modules = set(raw.get('modules', []))
        usb_paths = set(u.get('path', '') for u in raw.get('usb', []))
        port_keys = set(f"{p.get('proto')}:{p.get('local')}" for p in raw.get('ports', []))
        taint = raw.get('kernel_taint', -1)
        first_snapshot = not self._baseline_initialized
        if first_snapshot:
            self._baseline_initialized = True
        # Existing processes are inspected too; observing one does not prove it was just created.
        # 1. Süreçler — yalnızca yeni PID veya PID reuse (farklı start time)
        for pid, p in procs.items():
            previous = self._last_processes.get(pid)
            if previous and previous.get('starttime_jiffies') == p.get('starttime_jiffies') and previous.get('exe') == p.get('exe') and previous.get('cmd') == p.get('cmd'):
                continue
            events.append({
                'source': 'sys_proc',
                'kind': 'process',
                'timestamp': ts,   # ← ISO string
                'action': 'process_observed' if first_snapshot else 'new_process',
                'category': 'host',
                'severity': 'info',
                'metadata': {
                    'extensions': {
                        'host.pid': pid,
                        'host.cmd': p.get('cmd'),
                        'host.uid': p.get('uid'),
                        'host.ppid': p.get('ppid'),
                        'host.parent_cmd': p.get('parent_cmd'),
                        'host.age_seconds': p.get('age_seconds'),
                        'host.starttime': p.get('starttime_jiffies'),
                        'host.start_seconds': p.get('start_seconds'),
                        'host.exe': p.get('exe'),
                        'host.env': p.get('env', ''),
                    }
                }
            })
            from .browser_guard import classify_child
            browser=classify_child(p,procs)
            if browser:
                events.append({'source':'sys_proc','kind':'process','action':'browser_dangerous_child',
                    'timestamp':ts,'category':'browser','severity':'high',
                    'metadata':{'extensions':{'host.pid':pid,'host.starttime':p.get('starttime_jiffies'),
                        'host.exe':p.get('exe'),'host.cmd':p.get('cmd'),'host.ppid':p.get('ppid'),
                        'host.browser_guard':browser}}})
        self._last_processes = procs

        # 2. Modüller — sadece YENİ
        for mod in modules - self._last_modules:
            events.append({
                'source': 'sys_proc',
                'kind': 'module',
                'timestamp': ts,
                'action': 'new_module',
                'category': 'host',
                'severity': 'info',
                'metadata': {'extensions': {'host.module': mod}}
            })
        self._last_modules = modules

        # 3. USB — sadece YENİ
        for usb in raw.get('usb', []):
            if usb.get('path') in self._last_usb:
                continue
            events.append({
                'source': 'sys_proc',
                'kind': 'usb',
                'timestamp': ts,
                'action': 'new_usb',
                'category': 'host',
                'severity': 'info',
                'metadata': {'extensions': {'host.usb': usb}}
            })
        self._last_usb = usb_paths

        # 4. Portlar — sadece YENİ
        for port in raw.get('ports', []):
            key = f"{port.get('proto')}:{port.get('local')}"
            if key in self._last_ports:
                continue
            events.append({
                'source': 'sys_proc',
                'kind': 'port',
                'timestamp': ts,
                'action': 'new_port',
                'category': 'host',
                'severity': 'info',
                'metadata': {'extensions': {'host.port': port}}
            })
        self._last_ports = port_keys

        # 5. Kernel taint — değiştiyse
        if taint > 0 and taint != self._last_taint:
            events.append({
                'source': 'sys_proc',
                'kind': 'kernel',
                'timestamp': ts,
                'action': 'kernel_event',
                'category': 'host',
                'severity': 'warn',
                'metadata': {
                    'extensions': {
                        'host.types': ['taint'],
                        'host.taint': taint,
                    }
                }
            })
        self._last_taint = taint
        self._save_baseline()

        return events

    def _watch_execution(self,event,pipeline):
        from .watch_store import WatchStore
        from .finding_store import record_finding
        ext=event['metadata']['extensions']
        watcher=WatchStore(self.store)
        for entry in watcher.match_process(ext.get('host.exe',''),ext.get('host.cmd','')):
            observed={'source':'file_watch','action':'watched_file_executed','timestamp':time.time(),
                      'pid':ext.get('host.pid'),'file_path':entry['path'],'process_event':event,
                      'classification':'indicator'}
            pipeline.ingest_host(observed)
            finding={**observed,'rule_id':'SATSUMA-WATCH-001','severity':'medium',
                     'summary':'Takip listesindeki dosyayla ilişkili süreç gözlendi',
                     'finding_id':'watch:'+str(self.boot_id)+':'+str(ext.get('host.pid'))+':'+str(ext.get('host.starttime'))+':'+entry['path']}
            record_finding(self.store,finding,'file_watch')
            watcher.record_hit(entry['path'])

    def _save_baseline(self):
        self.store.set(self.baseline_key, {
            'processes': self._last_processes,
            'boot_id': self.boot_id,
            'modules': sorted(self._last_modules),
            'usb': sorted(self._last_usb),
            'ports': sorted(self._last_ports),
            'taint': self._last_taint,
            'updated_at': int(time.time()),
        })

    @delivered_tick('_last_processes', '_last_modules', '_last_usb', '_last_ports', '_last_taint', '_baseline_initialized')
    def tick(self, pipeline=None):
        now = time.monotonic()
        if now < self._next_collect:
            return {'ok': True, 'skipped': True}
        self._next_collect = now + 2.0
        started = time.time()
        raw = self.collect()

        self.store.set(self.raw_key, raw)

        history = self.store.get(self.history_key, [])
        history.append({
            'timestamp': raw['timestamp'],
            'process_count': len(raw['processes']),
            'module_count': len(raw['modules']),
            'usb_count': len(raw['usb']),
            'pci_count': len(raw['pci']),
            'port_count': len(raw['ports']),
            'kernel_taint': raw['kernel_taint'],
        })
        history = history[-10:]
        self.store.set(self.history_key, history)

        events_count = 0
        errors_count = 0
        if pipeline:
            for ev in self._raw_to_events(raw):
                try:
                    pipeline.ingest_host(ev)
                    if ev.get('kind')=='process':
                        self._watch_execution(ev,pipeline)
                    events_count += 1
                except Exception as e:
                    errors_count += 1
                    self.store.add('errors', {
                        'component': 'worker_sys_proc',
                        'error': str(e)[:200],
                        'event_action': ev.get('action'),
                    })

        elapsed = time.time() - started
        self.store.set(self.health_key, {
            'updated_at': int(time.time()),
            'elapsed_ms': int(elapsed * 1000),
            'status': 'DEGRADED' if errors_count else 'RUNNING',
            'process_count': len(raw['processes']),
            'events_count': events_count,
            'errors_count': errors_count,
        })

        return {
            'ok': errors_count == 0,
            'process_count': len(raw['processes']),
            'module_count': len(raw['modules']),
            'events': events_count,
            'errors': errors_count,
            'elapsed_ms': int(elapsed * 1000),
        }
