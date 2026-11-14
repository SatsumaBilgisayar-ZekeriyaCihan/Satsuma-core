"""Kural: yeni süreç → bilinmeyen dış IP."""
from .base import Rule
import ipaddress


class UnknownDestinationRule(Rule):
    name = "unknown_destination"
    severity = "low"
    description = "Yeni süreç bilinmeyen dış hedefe bağlandı"

    def match(self, events):
        findings = []

        # 1. Yeni süreçler
        new_procs = [
            e for e in events
            if e.get('action') in ('new_process', 'process_new')
        ]

        # 2. Ağ bağlantıları
        net_events = [
            e for e in events
            if e.get('category') == 'network'
        ]

        for np in new_procs:
            np_ts = np.get('timestamp', 0)
            if isinstance(np_ts, str):
                continue
            for ne in net_events:
                ne_ts = ne.get('timestamp', 0)
                if isinstance(ne_ts, str):
                    continue
                if self._in_window(np_ts, ne_ts):
                    # Dış IP mi?
                    exts = ne.get('metadata', {}).get('extensions', {})
                    dst = exts.get('network.dst_ip') or exts.get('host.dst_ip')
                    if dst:
                        try:
                            ip = ipaddress.ip_address(dst)
                            if ip.is_global:
                                findings.append(self._finding(
                                    finding_type='new_process_unknown_destination',
                                    events=[np, ne],
                                    summary=f"Yeni süreç → {dst}",
                                    severity='low',
                                    confidence='low',
                                ))
                        except ValueError:
                            pass

        return findings
