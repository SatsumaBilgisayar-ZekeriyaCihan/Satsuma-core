"""Satsuma Core — Suricata worker.

TEK GÖREV: Suricata eve.json'dan HAM alert'leri topla.
Not: Pipeline zaten Suricata'yı işliyor, ama takım bazlı
analiz için ayrı bir worker katmanı gerekir.
"""
from .worker_delivery import delivered_tick
from .worker_log import read_batch
import json
import os
import time
from pathlib import Path


class WorkerSuricata:
    name = "suricata"

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self.raw_key = 'worker.suricata.raw'
        self.cursor_key = 'worker.suricata.cursor'
        self.health_key = 'worker.suricata.health'
        self.eve_path = Path(self.config.get('eve_path', '/var/log/suricata/eve.json'))

    def _read_new_lines(self):
        from .source_guard import resolve_writer_uid
        uid = resolve_writer_uid(self.config.get('eve_writer_uid', 'managed_suricata'))
        lines, cursor = read_batch(self.eve_path, self.store.get(self.cursor_key), writer_uid=uid)
        self.store.set(self.cursor_key, cursor)
        return lines

    def collect(self, max_lines=1000):
        lines = self._read_new_lines()
        records = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                records.append(obj)
            except json.JSONDecodeError as exc:
                raise ValueError('Invalid EVE record; cursor retained') from exc
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
                    continue

        elapsed = time.time() - started
        self.store.set(self.health_key, {
            'updated_at': int(time.time()),
            'elapsed_ms': int(elapsed * 1000),
            'status': 'RUNNING',
            'record_count': len(raw['records']),
            'interfaces': sorted({r['in_iface'] for r in raw['records'] if isinstance(r.get('in_iface'),str)}),
            'scope': 'EVE records from configured host sensor; interface only when recorded',
            'last_event': raw['records'][-1].get('timestamp') if raw['records'] else None,
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
            event_type = rec.get('event_type', 'unknown')
            if event_type == 'alert':
                alert = rec.get('alert', {})
                events.append({
                    'source': 'suricata',
                    'kind': 'alert',
                    'timestamp': rec.get('timestamp', int(time.time())),
                    'signature': alert.get('signature'),
                    'signature_id': alert.get('signature_id'),
                    'severity': alert.get('severity'),
                    'category': alert.get('category'),
                    'src_ip': rec.get('src_ip'),
                    'dest_ip': rec.get('dest_ip'),
                    'src_port': rec.get('src_port'),
                    'dest_port': rec.get('dest_port'),
                    'proto': rec.get('proto'),
                    'flow_id': rec.get('flow_id'),
                })
            elif event_type == 'dns':
                dns = rec.get('dns', {})
                events.append({
                    'source': 'suricata',
                    'kind': 'dns',
                    'timestamp': rec.get('timestamp', int(time.time())),
                    'query': dns.get('query'),
                    'rrtype': dns.get('rrtype'),
                    'answers': dns.get('answers', []),
                })
            elif event_type == 'http':
                http = rec.get('http', {})
                events.append({
                    'source': 'suricata',
                    'kind': 'http',
                    'timestamp': rec.get('timestamp', int(time.time())),
                    'hostname': http.get('hostname'),
                    'url': http.get('url'),
                    'method': http.get('http_method'),
                })
            elif event_type == 'tls':
                tls = rec.get('tls', {})
                events.append({
                    'source': 'suricata',
                    'kind': 'tls',
                    'timestamp': rec.get('timestamp', int(time.time())),
                    'sni': tls.get('sni'),
                    'version': tls.get('version'),
                    'subject': tls.get('subject'),
                })
        return events
