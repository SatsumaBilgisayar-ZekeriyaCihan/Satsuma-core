"""Host team rules. Each finding's events carry the program's executable,
command line, user and parent when the sensor reported them (2.2.11).

Host Ekibi kuralları. Her bulgunun olayları, sensör bildirdiyse programın
çalıştırılabilir dosyasını, komut satırını, kullanıcısını ve üst sürecini
taşır (2.2.11).
"""


class _BaseRule:
    name = "base"
    severity = "info"

    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds

    def _in_window(self, t1, t2):
        return abs(t1 - t2) <= self.window_seconds

    def _finding(self, t, events, summary, severity=None,
                 confidence='medium', classification=None, extra=None):
        sev = severity or self.severity
        if classification is None:
            classification = 'likely' if confidence == 'high' else 'suspicious' if confidence == 'medium' else 'indicator'
        f = {
            'finding_id': f"{t}_{events[0].get('id', 0) if events else 0}",
            'type': t,
            'severity': sev,
            'confidence': confidence,
            'classification': classification,
            'timestamp': int(events[0].get('timestamp', 0)) if events else 0,
            'summary': summary,
            'events': [
                {
                    'source': e.get('source', {}).get('collector_id'),
                    'action': e.get('action'),
                    'category': e.get('category'),
                    'timestamp': e.get('timestamp'),
                    'pid': e.get('metadata', {}).get('extensions', {}).get('host.pid'),
                    # Which program it was, so a correlated finding can name it.
                    **{key: e.get('metadata', {}).get('extensions', {}).get('host.' + key)
                       for key in ('exe', 'cmd', 'uid', 'ppid', 'parent_cmd')
                       if e.get('metadata', {}).get('extensions', {}).get('host.' + key) is not None},
                }
                for e in events[:10]
            ],
            'attribution': 'rule-based',
        }
        if extra:
            f.update(extra)
        return f


class ProcessChainRule(_BaseRule):
    name = "suspicious_process_chain"
    severity = "high"

    def match(self, events):
        findings = []
        transient = [
            e for e in events
            if 'StartTransientUnit' in str(e.get('metadata', {}).get('extensions', {}))
            or 'transient' in e.get('action', '').lower()
        ]
        for te in transient:
            ts = te.get('timestamp', 0)
            if isinstance(ts, str):
                continue
            related = [
                e for e in events
                if e.get('action') in ('new_process', 'process_new')
                and isinstance(e.get('timestamp'), int)
                and self._in_window(ts, e['timestamp'])
            ]
            if len(related) >= 2:
                findings.append(self._finding(
                    'suspicious_process_chain',
                    [te] + related,
                    f"Transient unit sonrası {len(related)} süreç",
                    severity='high',
                ))
        return findings


class KernelTaintRule(_BaseRule):
    name = "kernel_taint_change"
    severity = "critical"

    def match(self, events):
        findings = []
        for e in events:
            if e.get('action') == 'kernel_event':
                exts = e.get('metadata', {}).get('extensions', {})
                types = exts.get('host.types', [])
                if isinstance(types, str):
                    types = [types]
                if 'taint' in types:
                    findings.append(self._finding(
                        'kernel_taint_change',
                        [e],
                        'Kernel taint değişti',
                        severity='critical',
                    ))
        return findings
