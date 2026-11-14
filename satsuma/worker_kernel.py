"""Satsuma Core — Kernel worker.

TEK GÖREV: dmesg / journalctl -k üzerinden kernel olaylarını topla, pipeline'a gönder.
ANLAMLANDIRMA YOK.
"""
from .worker_delivery import delivered_tick
import re
import subprocess
import time


class WorkerKernel:
    name = "kernel"

    PATTERNS = {
        'panic': re.compile(r'kernel panic|panic occurred', re.I),
        'oom': re.compile(r'Out of memory|oom-killer|oom_reaper', re.I),
        'segfault': re.compile(r'segfault', re.I),
        'module_load': re.compile(r'(loading|loaded).*module', re.I),
        'module_unload': re.compile(r'(unloading|removed).*module', re.I),
        'usb_new': re.compile(r'usb \d+-[\d.]+: new (high|full|low|super)-speed USB device', re.I),
        'usb_disconnect': re.compile(r'usb \d+-[\d.]+: USB disconnect', re.I),
        'net_up': re.compile(r'(link is up|link becomes ready|NIC Link is up)', re.I),
        'net_down': re.compile(r'(link is down|NIC Link is Down)', re.I),
        'firewall': re.compile(r'(nft|iptables|netfilter)', re.I),
        'audit': re.compile(r'audit:', re.I),
        'mount': re.compile(r'(mounted|mounting|unmounted)', re.I),
        'taint': re.compile(r'kernel taint|tainted', re.I),
    }

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self.raw_key = 'worker.kernel.raw'
        self.cursor_key = 'worker.kernel.cursor'
        self.health_key = 'worker.kernel.health'
        self.baseline_key = 'worker.kernel.baseline'
        saved = self.store.get(self.baseline_key, None)
        if isinstance(saved, dict):
            self._last_lines = set(saved.get('lines') or [])
            self._baseline_initialized = True
        else:
            self._last_lines = set()
            self._baseline_initialized = False

    def _collect_dmesg(self, max_lines=500):
        r = subprocess.run(
            ['/usr/bin/dmesg', '--time-format', 'iso'],
            capture_output=True, text=True, timeout=10, check=False,
            env={'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'}
        )
        if r.returncode:
            raise RuntimeError('Kernel log unavailable: ' + r.stderr[:300])
        lines = r.stdout.splitlines()
        if len(lines) > max_lines:
            # Keep the complete ring snapshot; silently truncating loses alerts.
            return lines
        return lines

    def collect(self):
        lines = self._collect_dmesg()
        events = []
        for line in lines:
            matched_types = []
            for ptype, pattern in self.PATTERNS.items():
                if pattern.search(line):
                    matched_types.append(ptype)
            if matched_types:
                events.append({
                    'timestamp': int(time.time()),
                    'raw': line[:500],
                    'types': matched_types,
                })
        return {
            'timestamp': int(time.time()),
            'events': events,
            'total_lines': len(lines),
        }

    def _raw_to_events(self, raw):
        events = []
        severity_map = {
            'panic': 'critical',
            'oom': 'critical',
            'segfault': 'high',
            'module_load': 'medium',
            'module_unload': 'medium',
            'usb_new': 'low',
            'usb_disconnect': 'low',
            'net_up': 'info',
            'net_down': 'medium',
            'firewall': 'medium',
            'audit': 'low',
            'mount': 'low',
            'taint': 'critical',
        }

        current_lines = set(ev.get('raw', '') for ev in raw.get('events', [])[-500:])
        if not self._baseline_initialized:
            self._last_lines = current_lines
            self._baseline_initialized = True
            self.store.set(self.baseline_key, {
                'lines': sorted(self._last_lines),
                'updated_at': int(time.time()),
            })
            return events

        for ev in raw.get('events', []):
            raw_line = ev.get('raw', '')
            # Sadece YENİ satırlar
            if raw_line in self._last_lines:
                continue

            types = ev.get('types', [])
            severity = 'info'
            for t in types:
                s = severity_map.get(t)
                if s == 'critical':
                    severity = 'critical'
                    break
                if s == 'high' and severity != 'critical':
                    severity = 'high'
                elif s == 'medium' and severity == 'info':
                    severity = 'medium'

            events.append({
                'source': 'kernel',
                'kind': 'kernel_event',
                'timestamp': ev['timestamp'],
                'action': 'kernel_event',
                'category': 'host',
                'types': types,
                'severity': severity,
                'metadata': {
                    'extensions': {
                        'host.types': types,
                        'host.raw': raw_line,
                    }
                },
            })

        # Son 500 satırı kalıcı tut; worker restartı eski dmesg'i tekrar alarm yapmasın.
        self._last_lines = current_lines
        self.store.set(self.baseline_key, {
            'lines': sorted(self._last_lines),
            'updated_at': int(time.time()),
        })
        return events

    @delivered_tick('_last_lines', '_baseline_initialized')
    def tick(self, pipeline=None):
        started = time.time()
        raw = self.collect()

        self.store.set(self.raw_key, raw)

        events_count = 0
        if pipeline:
            for ev in self._raw_to_events(raw):
                try:
                    pipeline.ingest_host(ev)
                    events_count += 1
                except Exception as e:
                    self.store.add('errors', {
                        'component': 'worker_kernel',
                        'error': str(e)[:200],
                        'event_action': ev.get('action'),
                    })

        elapsed = time.time() - started
        self.store.set(self.health_key, {
            'updated_at': int(time.time()),
            'elapsed_ms': int(elapsed * 1000),
            'status': 'RUNNING',
            'event_count': events_count,
        })

        return {
            'ok': True,
            'events': events_count,
            'total_lines': raw['total_lines'],
            'elapsed_ms': int(elapsed * 1000),
        }
