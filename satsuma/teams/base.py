"""Satsuma Core — Takım tabanı.

BaseWorker: Ham veri toplayıcı (analiz yapmaz)
BaseTeamLead: Takım yöneticisi (worker'ları koordine eder, eşleştirir)
"""
import json
import time
from satsuma.finding_store import record_finding
from satsuma.normalized_window import recent_rows
from satsuma import shutdown


class BaseWorker:
    """Saf toplayıcı — analiz yok, yorum yok."""
    name = "base_worker"
    source = "unknown"

    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}

    def collect(self):
        """Alt sınıf uygular."""
        raise NotImplementedError

    def tick(self, pipeline=None):
        """Tek toplama döngüsü."""
        started = time.time()
        raw = self.collect()

        self.store.set(f'worker.{self.name}.raw', raw)
        self.store.set(f'worker.{self.name}.health', {
            'updated_at': int(time.time()),
            'status': 'RUNNING',
            'elapsed_ms': int((time.time() - started) * 1000),
        })

        # Pipeline'a gönderilirse ham veriyi ilet
        if pipeline and hasattr(raw, 'get'):
            events = raw.get('events', [])
            for ev in events:
                try:
                    pipeline.ingest_host(ev)
                except (ValueError, KeyError):
                    continue

        return {'ok': True, 'elapsed_ms': int((time.time() - started) * 1000)}


class BaseTeamLead:
    """Takım yöneticisi — worker'ları çalıştırır, eşleştirir, bulgu üretir."""
    name = "base_team"
    description = ""
    workers = []       # Bu takımın worker sınıfları
    rules = []         # Bu takımın kural sınıfları

    def __init__(self, store, config=None, pipeline=None):
        self.store = store
        self.config = config or {}
        self.pipeline = pipeline
        # Worker instance'ları
        self.worker_instances = [
            W(store, config) for W in self.workers
        ]
        # Kural instance'ları
        self.rule_instances = [
            R(window_seconds=10) for R in self.rules
        ]

    def run_workers(self):
        """Tüm worker'ları çalıştır."""
        results = {}
        for w in self.worker_instances:
            if shutdown.requested():
                results[w.name] = {'ok': True, 'stopped': True}
                continue
            try:
                results[w.name] = w.tick(pipeline=self.pipeline)
            except Exception as e:
                results[w.name] = {'ok': False, 'status': 'DEGRADED', 'error': str(e)[:200]}
                self.store.set(f'worker.{w.name}.health', {**results[w.name], 'updated_at': time.time()})
        return results

    def _read_normalized(self, since_ts=None, limit=2000):
        """core.db'den normalize event'leri oku."""
        if since_ts is None:
            since_ts = int(time.time()) - 300

        rows = recent_rows(self.store.db, since_ts)

        events = []
        for rid, body_str in rows:
            try:
                outer = json.loads(body_str)
                inner = outer.get('event', {})
                ev = inner.get('event', {})
                ts = ev.get('timestamp', '')
                if isinstance(ts, str):
                    try:
                        from datetime import datetime, timezone
                        dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                        ts_int = int(dt.timestamp())
                    except (ValueError, TypeError):
                        ts_int = 0
                else:
                    ts_int = int(ts) if ts else 0

                if ts_int < since_ts:
                    continue

                events.append({
                    'id': rid,
                    'timestamp': ts_int,
                    'category': ev.get('category'),
                    'action': ev.get('action'),
                    'severity': ev.get('severity'),
                    'source': inner.get('source', {}),
                    'metadata': inner.get('metadata', {}),
                    'host': inner.get('host', {}),
                    'network': inner.get('network', {}),
                    'raw': inner.get('raw', {}),
                    'raw_id': outer.get('raw_id'),
                })
            except (json.JSONDecodeError, KeyError, TypeError):
                continue

        return events

    def correlate(self):
        """Kendi kurallarını çalıştır."""
        events = self._read_normalized()
        findings = []
        self.rule_errors = 0
        for rule in self.rule_instances:
            try:
                findings.extend(rule.match(events))
            except Exception as e:
                self.rule_errors += 1
                self.store.add('events', {
                    'event': {
                        'timestamp': int(time.time()),
                        'category': 'team_error',
                        'action': 'rule_error',
                        'outcome': 'error',
                        'severity': 'warn',
                    },
                    'source': {'type': 'satsuma-core', 'module': self.name},
                    'metadata': {'rule': rule.name, 'error': str(e)[:300]},
                })
        return findings

    def write_findings(self, findings):
        """Bulgu havuzuna dedup uygula; sadece yeni bulgulari geri ver."""
        fresh = []
        for f in findings:
            f['team'] = self.name
            result = record_finding(self.store, f, self.name)
            f['_dedup'] = result
            if result.get('written'):
                fresh.append(f)
        return fresh

    def tick(self):
        """Tek takım döngüsü."""
        started = time.time()

        # 1. Worker'ları çalıştır
        worker_results = self.run_workers()

        # 2. Kendi alanında eşleştir
        findings = self.correlate()

        # 3. Bulgu havuzuna yaz
        fresh_findings = self.write_findings(findings)

        elapsed = time.time() - started

        # 4. Takım sağlığı
        self.store.set(f'team.{self.name}.health', {
            'updated_at': int(time.time()),
            'status': 'RUNNING' if all(v.get('ok') for v in worker_results.values()) and not self.rule_errors else 'DEGRADED',
            'elapsed_ms': int(elapsed * 1000),
            'worker_results': worker_results,
            'findings_count': len(findings),
            'new_findings_count': len(fresh_findings),
        })

        return {
            'ok': all(v.get('ok') for v in worker_results.values()) and not self.rule_errors,
            'team': self.name,
            'workers': len(worker_results),
            'findings': len(findings),
            'new_findings': len(fresh_findings),
            'elapsed_ms': int(elapsed * 1000),
            'findings_list': fresh_findings,
        }
