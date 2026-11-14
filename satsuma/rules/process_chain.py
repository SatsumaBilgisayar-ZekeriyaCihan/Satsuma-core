"""Kural: systemd transient unit → yeni süreç → dış bağlantı."""
from .base import Rule
import re


class ProcessChainRule(Rule):
    name = "process_chain"
    severity = "high"
    description = "systemd transient unit sonrası şüpheli süreç zinciri"

    def match(self, events):
        findings = []

        # 1. StartTransientUnit olaylarını topla
        transient_events = [
            e for e in events
            if 'StartTransientUnit' in str(e.get('metadata', {}).get('extensions', {}))
            or 'start_transient' in e.get('action', '').lower()
        ]

        for te in transient_events:
            ts = te.get('timestamp', 0)
            if isinstance(ts, str):
                continue
            # 2. Bu andan sonra ±10 saniyedeki süreçler
            related = []
            for e in events:
                if e.get('action') in ('new_process', 'process_new'):
                    e_ts = e.get('timestamp', 0)
                    if isinstance(e_ts, str):
                        continue
                    if self._in_window(ts, e_ts):
                        related.append(e)

            if len(related) >= 2:
                findings.append(self._finding(
                    finding_type='suspicious_process_chain',
                    events=[te] + related,
                    summary=f"Transient unit sonrası {len(related)} süreç başlatıldı",
                    severity='high',
                    confidence='medium',
                ))

        return findings
