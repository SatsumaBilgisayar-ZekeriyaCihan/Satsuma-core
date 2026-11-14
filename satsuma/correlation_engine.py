"""Satsuma Core — Yerel Kural Motoru.

Bu modül YEREL çalışır:
  - Dış AI bağımlılığı YOK
  - İnternet gerekmez
  - Ücretsiz
  - Gizli

Kaynaklar:
  - normalized event'ler (core.db.records kind='normalized')
  - worker'lar (sys_proc, systemd_dbus)
  - suricata (pipeline üzerinden)

Çıktı:
  - findings tablosu (host.db)
  - events (core.db, category='correlation')
"""
import json
import time

from .rules.process_chain import ProcessChainRule
from .rules.sensitive_file import SensitiveFileRule
from .rules.privilege_escalation import PrivilegeEscalationRule
from .rules.unknown_destination import UnknownDestinationRule
from .finding_store import record_finding
from .normalized_window import recent_rows


class CorrelationEngine:
    def __init__(self, store, config=None):
        self.store = store
        self.config = config or {}
        self.window_seconds = int(self.config.get('correlation_window_seconds', 10))
        self.lookback_seconds = int(self.config.get('correlation_lookback_seconds', 300))

        # Kural seti
        self.rules = [
            ProcessChainRule(window_seconds=self.window_seconds),
            SensitiveFileRule(window_seconds=self.window_seconds),
            PrivilegeEscalationRule(window_seconds=self.window_seconds),
            UnknownDestinationRule(window_seconds=self.window_seconds),
        ]

    def _read_normalized(self, since_ts):
        """core.db'den normalized event'leri oku."""
        rows = recent_rows(self.store.db, since_ts)

        events = []
        for rid, body_str in rows:
            try:
                outer = json.loads(body_str)
                inner = outer.get('event', {})
                ev = inner.get('event', {})
                ts = ev.get('timestamp', '')
                # String → int çevirme (ISO 8601)
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
                    'raw_id': outer.get('raw_id'),
                })
            except (json.JSONDecodeError, KeyError, TypeError):
                continue

        return events

    def _write_finding(self, finding):
        """core.db finding havuzuna dedup uygulanarak yaz."""
        return record_finding(self.store, finding, 'correlation_engine')

    def correlate(self):
        """Ana döngü — son N saniyeyi analiz et."""
        since = int(time.time()) - self.lookback_seconds
        events = self._read_normalized(since)

        all_findings = []
        fresh_findings = []
        errors = []
        for rule in self.rules:
            try:
                findings = rule.match(events)
                for f in findings:
                    f.setdefault('team', 'correlation_engine')
                    result = self._write_finding(f)
                    f['_dedup'] = result
                    if result.get('written'):
                        fresh_findings.append(f)
                all_findings.extend(findings)
            except Exception as e:
                errors.append({'rule': rule.name, 'error': str(e)[:300]})
                # Kural hatası → audit'e yaz, devam et
                self.store.add('events', {
                    'event': {
                        'timestamp': int(time.time()),
                        'category': 'finding',
                        'action': 'rule_error',
                        'outcome': 'error',
                        'severity': 'warn',
                    },
                    'source': {'type': 'satsuma-core', 'module': 'correlation_engine'},
                    'metadata': {'rule': rule.name, 'error': str(e)[:300]},
                })

        self.store.set('correlation_engine.health', {'status':'DEGRADED' if errors else 'RUNNING', 'updated_at':time.time(), 'errors':errors})
        return fresh_findings

    def tick(self):
        """Timer için tek çağrı."""
        started = time.time()
        findings = self.correlate()
        elapsed = time.time() - started

        return {
            'ok': self.store.get('correlation_engine.health', {}).get('status') == 'RUNNING',
            'findings_count': len(findings),
            'elapsed_ms': int(elapsed * 1000),
        }

    def reconcile(self):
        return self.tick()
