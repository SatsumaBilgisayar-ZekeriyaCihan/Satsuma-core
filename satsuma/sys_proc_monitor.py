"""Satsuma Core — /sys ve /proc izleme modülü."""
import json
import os
import re
import subprocess
import time
from pathlib import Path


class SysProcMonitor:
    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self.baseline_key = 'sys_proc.baseline'
        self.snapshot_key = 'sys_proc.snapshot'
        self.alarm_key = 'sys_proc.alarm'
        self.lifecycle_key = 'sys_proc.process_lifecycle'
        self.noise_patterns = re.compile(
            r'^('
            r'apt|apt-get|aptd|dpkg|unattended-upgrade|packagekitd|pkcon|'
            r'plocate|updatedb|locate|mlocate|tracker|'
            r'psimon|pardus-|'
            r'systemd-|systemctl|journalctl|'
            r'kworker|kthreadd|ksoftirqd|rcu_|migration|watchdog|'
            r'kcompactd|kswapd|kdevtmpfs|kintegrityd|kblockd|'
            r'bash|sh|dash|zsh|sudo|su|'
            r'grep|awk|sed|sort|uniq|head|tail|cat|less|more|'
            r'ps|pgrep|pidof|top|htop|find|fd|which|whereis|'
            r'echo|printf|date|uptime|whoami|id|'
            r'chrome_crashpad|brave_crashpad|crashpad_handler|'
            r'gvfsd|gvfs-|xdg-|dbus-|'
            r'pulseaudio|pipewire|wireplumber|'
            r'gnome-keyring|kwalletd|polkitd|accounts-daemon'
            r')',
            re.I
        )

    def _run(self, args, timeout=5):
        try:
            r = subprocess.run(args, capture_output=True, text=True,
                               timeout=timeout, check=False)
            return r.returncode, r.stdout or '', r.stderr or ''
        except Exception as e:
            return -1, '', str(e)

    def _collect_modules(self):
        from .worker_sys_proc import WorkerSysProc
        return WorkerSysProc(self.store,self.config)._collect_modules()

    def _collect_sys_modules(self):
        from .worker_sys_proc import WorkerSysProc
        return WorkerSysProc(self.store,self.config)._collect_sys_modules()

    def _collect_processes(self):
        from .worker_sys_proc import WorkerSysProc
        return WorkerSysProc(self.store,self.config)._collect_processes()

    def _collect_usb(self):
        from .worker_sys_proc import WorkerSysProc
        return WorkerSysProc(self.store,self.config)._collect_usb()

    def _collect_pci(self):
        from .worker_sys_proc import WorkerSysProc
        return WorkerSysProc(self.store,self.config)._collect_pci()

    def _collect_ports(self):
        from .worker_sys_proc import WorkerSysProc
        return WorkerSysProc(self.store,self.config)._collect_ports()

    def _collect_kernel_taint(self):
        from .worker_sys_proc import WorkerSysProc
        return WorkerSysProc(self.store,self.config)._collect_kernel_taint()

    def _snapshot(self):
        return {
            'timestamp': int(time.time()),
            'modules': self._collect_modules(),
            'sys_modules': self._collect_sys_modules(),
            'processes': self._collect_processes(),
            'usb': self._collect_usb(),
            'pci': self._collect_pci(),
            'ports': self._collect_ports(),
            'kernel_taint': self._collect_kernel_taint(),
        }

    def _diff(self, old, new):
        result = {
            'new_modules': sorted(set(new['modules']) - set(old['modules'])),
            'removed_modules': sorted(set(old['modules']) - set(new['modules'])),
            'new_processes': [],
            'removed_processes': [],
            'new_usb': [],
            'removed_usb': [],
            'new_pci': [],
            'removed_pci': [],
            'new_ports': [],
            'removed_ports': [],
            'kernel_taint_changed': False,
        }
        old_pids = set(old['processes'].keys())
        new_pids = set(new['processes'].keys())
        result['new_processes'] = [
            {'pid': pid, **new['processes'][pid]}
            for pid in new_pids - old_pids
        ]
        result['removed_processes'] = sorted(old_pids - new_pids)
        old_usb = {json.dumps(d, sort_keys=True) for d in old['usb']}
        new_usb = {json.dumps(d, sort_keys=True) for d in new['usb']}
        result['new_usb'] = [json.loads(x) for x in new_usb - old_usb]
        result['removed_usb'] = [json.loads(x) for x in old_usb - new_usb]
        old_pci = {d['path'] for d in old['pci']}
        new_pci = {d['path'] for d in new['pci']}
        result['new_pci'] = sorted(new_pci - old_pci)
        result['removed_pci'] = sorted(old_pci - new_pci)
        old_ports = {f"{p['proto']}:{p['local']}" for p in old['ports']}
        new_ports = {f"{p['proto']}:{p['local']}" for p in new['ports']}
        result['new_ports'] = sorted(new_ports - old_ports)
        result['removed_ports'] = sorted(old_ports - new_ports)
        if old['kernel_taint'] != new['kernel_taint']:
            result['kernel_taint_changed'] = True
        return result

    def _is_noise(self, cmd):
        return bool(self.noise_patterns.search(cmd))

    def _update_lifecycle(self, old_procs, new_procs):
        """Süreç yaşam döngüsü.

        KRİTİK: PID'ler int veya str olabilir (Store'dan okurken str olur).
        Her zaman str'e çevir.
        """
        lifecycle = self.store.get(self.lifecycle_key, {})
        now = int(time.time())

        # PID'leri str'e çevir — tutarlılık için
        new_pids = set(str(pid) for pid in new_procs.keys())
        old_pids = set(str(pid) for pid in old_procs.keys()) if old_procs else set()

        # 1. TÜM ÇALIŞAN SÜREÇLERİ GÜNCELLE
        for pid_str in new_pids:
            # new_procs'ta int anahtarı olabilir, onu bul
            proc = None
            for k in new_procs.keys():
                if str(k) == pid_str:
                    proc = new_procs[k]
                    break
            if proc is None:
                continue

            if pid_str in lifecycle:
                lifecycle[pid_str]['last_seen'] = now
                lifecycle[pid_str]['age_seconds'] = proc['age_seconds']
                lifecycle[pid_str]['still_running'] = True
            else:
                lifecycle[pid_str] = {
                    'cmd': proc['cmd'],
                    'uid': proc['uid'],
                    'ppid': proc['ppid'],
                    'first_seen': now,
                    'first_seen_real': now - proc['age_seconds'],
                    'last_seen': now,
                    'age_seconds': proc['age_seconds'],
                    'still_running': True,
                }

        # 2. SONLANAN SÜREÇLERİ İŞARETLE (eski snapshot'tan çıkanlar)
        if old_procs:
            gone_pids = old_pids - new_pids
            for pid_str in gone_pids:
                if pid_str in lifecycle and lifecycle[pid_str].get('still_running'):
                    lifecycle[pid_str]['still_running'] = False
                    lifecycle[pid_str]['ended_at'] = now
                    lifecycle[pid_str]['total_lifetime'] = (
                        lifecycle[pid_str]['last_seen'] - lifecycle[pid_str]['first_seen']
                    )

        # 3. 7 günden eski kayıtları temizle
        cutoff = now - 7 * 86400
        lifecycle = {k: v for k, v in lifecycle.items() if v.get('last_seen', 0) > cutoff}

        self.store.set(self.lifecycle_key, lifecycle)
        return lifecycle

    def _classify_alarm(self, diff):
        alarms = []
        suspicious = re.compile(
            r'root|hack|backdoor|hidden|keylog|snoop|inject|hook|malware|trojan|diamorphine|reptile',
            re.I
        )
        for mod in diff['new_modules']:
            if suspicious.search(mod):
                alarms.append({
                    'severity': 'critical',
                    'type': 'suspicious_module',
                    'detail': f'Yeni şüpheli modül: {mod}',
                })
        if diff['kernel_taint_changed']:
            alarms.append({
                'severity': 'critical',
                'type': 'kernel_taint',
                'detail': 'Kernel taint değişti',
            })
        for port in diff['new_ports']:
            # Port identifiers are stored as '<proto>:<local-address>:<port>'.
            # Only wildcard-bound listeners should trigger this alarm.
            local = port.split(':', 1)[1] if ':' in port else port
            if local.startswith(('0.0.0.0:', '*:', '[::]:', ':::')):
                alarms.append({
                    'severity': 'high',
                    'type': 'new_listening_port',
                    'detail': f'Yeni dinleyici port: {port}',
                })
        for usb in diff['new_usb']:
            alarms.append({
                'severity': 'medium',
                'type': 'new_usb',
                'detail': f"Yeni USB: {usb.get('manufacturer', '?')} {usb.get('product', '?')}",
            })
        non_noise_new = [
            p for p in diff['new_processes']
            if not self._is_noise(p['cmd'])
        ]
        if len(non_noise_new) > 20:
            alarms.append({
                'severity': 'medium',
                'type': 'process_burst',
                'detail': f'{len(non_noise_new)} yeni (gürültü olmayan) süreç',
                'sample_processes': [
                    {
                        'pid': p['pid'],
                        'uid': p['uid'],
                        'ppid': p['ppid'],
                        'cmd': p['cmd'][:100],
                        'age_seconds': p.get('age_seconds', 0),
                    }
                    for p in non_noise_new[:30]
                ],
            })
        # Yakin takip (watch_files): file sensor'nin isaret ettigi bir dosya
        # calistirildiysa yuksek oncelikli alarm uret.
        try:
            from .watch_store import WatchStore
            for p in diff['new_processes']:
                watcher = WatchStore(self.store)
                hits = watcher.match_process(p.get('exe', ''), p.get('cmd', ''))
                for entry in hits:
                    watcher.record_hit(entry['path'])
                    alarms.append({
                        'severity': 'high',
                        'type': 'watched_file_executed',
                        'detail': f"Yakin takipteki dosya calistirildi: {entry['path']}",
                        'watch_path': entry['path'],
                        'watch_reason': entry.get('reason'),
                        'pid': p['pid'],
                        'uid': p['uid'],
                        'cmd': p['cmd'][:200],
                    })
        except Exception as exc:
            raise RuntimeError('Legacy process watch failed') from exc
        return alarms

    def tick(self):
        now = int(time.time())
        new_snapshot = self._snapshot()
        old_snapshot = self.store.get(self.snapshot_key, None)

        if old_snapshot is None:
            self.store.set(self.snapshot_key, new_snapshot)
            self.store.set(self.baseline_key, new_snapshot)
            self._update_lifecycle({}, new_snapshot['processes'])
            return {'ok': True, 'detail': 'baseline created'}

        diff = self._diff(old_snapshot, new_snapshot)
        lifecycle = self._update_lifecycle(
            old_snapshot['processes'],
            new_snapshot['processes']
        )
        alarms = self._classify_alarm(diff)

        event = {
            'event': {
                'timestamp': now,
                'category': 'sys_proc_monitor',
                'action': 'tick',
                'outcome': 'alarm' if alarms else 'ok',
                'severity': 'critical' if any(a['severity'] == 'critical' for a in alarms) else (
                    'warn' if alarms else 'info'
                ),
            },
            'source': {
                'type': 'satsuma-core',
                'module': 'sys_proc_monitor',
            },
            'metadata': {
                'diff_summary': {
                    'new_modules': len(diff['new_modules']),
                    'new_processes': len(diff['new_processes']),
                    'new_usb': len(diff['new_usb']),
                    'new_ports': len(diff['new_ports']),
                    'kernel_taint_changed': diff['kernel_taint_changed'],
                },
                'diff_detail': {
                    'new_modules': diff['new_modules'][:20],
                    'new_processes': [
                        {
                            'pid': p['pid'],
                            'uid': p['uid'],
                            'ppid': p['ppid'],
                            'cmd': p['cmd'][:100],
                            'age_seconds': p.get('age_seconds', 0),
                        }
                        for p in diff['new_processes'][:50]
                    ],
                    'new_ports': diff['new_ports'][:20],
                    'new_usb': diff['new_usb'][:10],
                },
                'alarms': alarms,
            },
        }
        self.store.add('events', event)

        if alarms:
            self.store.set(self.alarm_key, {
                'timestamp': now,
                'alarms': alarms,
                'diff_summary': event['metadata']['diff_summary'],
            })

        self.store.set(self.snapshot_key, new_snapshot)
        return {'ok': True, 'alarms': len(alarms)}

    def reconcile(self):
        return self.tick()
