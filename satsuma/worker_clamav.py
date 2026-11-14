"""Satsuma Core — ClamAV worker.

TEK GÖREV: ClamAV tarama sonuçlarını topla.
Kaynak: /var/log/clamav/clamav.log veya host.db
"""
from .worker_delivery import delivered_tick
from .worker_log import read_batch
from .sqlite_closing import ClosingConnection
import json
import os
import re
import time
from pathlib import Path


class WorkerClamav:
    name = "clamav"

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self.raw_key = 'worker.clamav.raw'
        self.cursor_key = 'worker.clamav.cursor'
        self.health_key = 'worker.clamav.health'
        self.log_paths = [
            Path('/var/log/clamav/clamav.log'),
            Path('/var/log/clamav/freshclam.log'),
        ]

    def _read_new_lines(self):
        lines = []
        self.pending_cursors = {}
        available = 0
        for log_path in self.log_paths:
            if not log_path.exists():
                continue
            key = f'worker.clamav.cursor.{log_path.name}'
            import pwd
            try:
                writer_uid = pwd.getpwnam('clamav').pw_uid
            except KeyError:
                writer_uid = 0
            new_lines, cursor = read_batch(log_path, self.store.get(key), writer_uid=writer_uid, limit=500)
            available += 1
            self.pending_cursors[key] = cursor
            lines.extend((log_path.name, line.strip()) for line in new_lines)
        if not available:
            raise FileNotFoundError('ClamAV log telemetry unavailable; scheduled scanning has separate health')
        return lines

    def _scan_results(self):
        import sqlite3
        path=Path(self.config.get('audit_host_db_path','/var/lib/satsuma-core/host/host.db'))
        if not path.exists():return None
        from .protected_storage import check
        check(path.lstat())
        key=self.cursor_key+'.scheduled'
        cursor=int(self.store.get(key,0) or 0)
        with sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True,timeout=2,factory=ClosingConnection) as db:
            rows=db.execute("SELECT id,body FROM records WHERE kind='security_scan' AND id>? ORDER BY id LIMIT 100",(cursor,)).fetchall()
        records=[]
        for ident,body in rows:
            item=json.loads(body)
            if item.get('tool')=='clamav':
                for line in item.get('output_excerpt','').splitlines():
                    if re.search(r'\bFOUND\s*$',line):
                        records.append({'timestamp':item.get('completed_at',time.time()),'type':'virus_found',
                                        'source':'scheduled_scan','raw':line[:4096]})
                if item.get('status') in ('ERROR','WARNING','UNAVAILABLE'):
                    records.append({'timestamp':time.time(),'type':'error','source':'scheduled_scan',
                                    'raw':str(item.get('error') or item.get('status'))[:500]})
            self.store.set(key,int(ident))
        self.pending_cursors={}
        self.telemetry_source='scheduled_scan:host.db'
        return {'timestamp':int(time.time()),'records':records}

    def collect(self):
        scans=self._scan_results()
        if scans is not None:return scans
        self.telemetry_source='legacy_clamav_logs'
        lines = self._read_new_lines()
        records = []

        # ClamAV log pattern'leri
        pattern_found = re.compile(r'FOUND', re.I)
        pattern_error = re.compile(r'(ERROR|WARNING)', re.I)

        for source, line in lines:
            if pattern_found.search(line):
                records.append({
                    'timestamp': int(time.time()),
                    'type': 'virus_found',
                    'source': source,
                    'raw': line[:500],
                })
            elif pattern_error.search(line):
                records.append({
                    'timestamp': int(time.time()),
                    'type': 'error',
                    'source': source,
                    'raw': line[:500],
                })

        return {
            'timestamp': int(time.time()),
            'records': records,
        }

    @delivered_tick()
    def tick(self, pipeline=None):
        started = time.time()
        raw = self.collect()

        self.store.set(self.raw_key, raw)

        events = self._raw_to_events(raw)

        if pipeline:
            for ev in events:
                try:
                    pipeline.ingest_host(ev)
                except (ValueError, KeyError):
                    raise

        if pipeline:
            for key,value in self.pending_cursors.items():self.store.set(key,value)

        elapsed = time.time() - started
        self.store.set(self.health_key, {
            'updated_at': int(time.time()),
            'elapsed_ms': int(elapsed * 1000),
            'status': 'RUNNING',
            'record_count': len(raw['records']),
            'telemetry_source':self.telemetry_source,
            'event_count': len(events),
        })

        return {
            'ok': True,
            'records': len(raw['records']),
            'events': len(events),
            'elapsed_ms': int(elapsed * 1000),
        }

    def _raw_to_events(self, raw):
        events = []
        for rec in raw.get('records', []):
            if rec['type'] == 'virus_found':
                # FOUND satırından dosya ve virüs adını çıkar
                m = re.search(r'^(.*):\s*(\S+)\s+FOUND$', rec['raw'])
                file_path = m.group(1) if m else None
                virus_name = m.group(2) if m else None
                events.append({
                    'source': 'clamav',
                    'kind': 'virus_detected',
                    'action': 'virus_detected',
                    'category': 'file',
                    'severity': 'high',
                    'timestamp': rec['timestamp'],
                    'file': file_path,
                    'virus': virus_name,
                    'raw': rec['raw'],
                })
            elif rec['type'] == 'error':
                events.append({
                    'source': 'clamav',
                    'kind': 'clamav_error',
                    'action': 'clamav_error',
                    'category': 'file',
                    'severity': 'medium',
                    'timestamp': rec['timestamp'],
                    'raw': rec['raw'],
                })
        return events
