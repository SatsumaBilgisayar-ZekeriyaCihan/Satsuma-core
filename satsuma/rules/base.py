"""Ortak kural tabanı — yerel zeka."""
from abc import ABC, abstractmethod
import time


class Rule(ABC):
    name = "unnamed"
    severity = "info"
    description = ""

    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds

    @abstractmethod
    def match(self, events):
        """events: normalized event listesi → findings listesi."""
        return []

    def _in_window(self, e1_ts, e2_ts):
        """İki olay arasında ±window_seconds var mı?"""
        return abs(e1_ts - e2_ts) <= self.window_seconds

    def _finding(self, finding_type, events, summary, severity=None,
                 confidence='medium', extra=None):
        """Standart bulgu üret."""
        sev = severity or self.severity
        ts = int(time.time())
        finding = {
            'finding_id': f"{finding_type}_{events[0].get('id', ts) if events else ts}",
            'type': finding_type,
            'severity': sev,
            'confidence': confidence,
            'timestamp': ts,
            'summary': summary,
            'events': [
                {
                    'source': e.get('source', {}).get('collector_id', '?'),
                    'action': e.get('action', '?'),
                    'category': e.get('category', '?'),
                    'timestamp': e.get('timestamp', '?'),
                    'pid': e.get('metadata', {}).get('extensions', {}).get('host.pid'),
                    'cmd': e.get('metadata', {}).get('extensions', {}).get('host.cmd'),
                }
                for e in events[:10]
            ],
            'attribution': 'rule-based',
        }
        if extra:
            finding.update(extra)
        return finding
