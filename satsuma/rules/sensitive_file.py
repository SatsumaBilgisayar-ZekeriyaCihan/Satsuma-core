"""Kural: hassas dosya erişimi → modül yükleme."""
from .base import Rule


SENSITIVE_PATHS = {
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    '/etc/ssh/sshd_config', '/root/.ssh',
    '/proc/sys/kernel', '/sys/kernel',
}


class SensitiveFileRule(Rule):
    name = "sensitive_file_access"
    severity = "critical"
    description = "Hassas dosya erişimi sonrası modül yükleme"

    def match(self, events):
        findings = []

        # 1. Hassas dosya erişimi
        sensitive_events = []
        for e in events:
            exts = e.get('metadata', {}).get('extensions', {})
            paths = []
            for key, value in exts.items():
                if 'path' in key.lower() and isinstance(value, str):
                    paths.append(value)
                if isinstance(value, list):
                    paths.extend([v for v in value if isinstance(v, str)])

            for p in paths:
                if any(p.startswith(sp) for sp in SENSITIVE_PATHS):
                    sensitive_events.append(e)
                    break

        # 2. Modül yükleme
        module_events = [
            e for e in events
            if e.get('action') in ('new_module', 'module_load')
        ]

        # 3. Bağlantı kur
        for se in sensitive_events:
            se_ts = se.get('timestamp', 0)
            if isinstance(se_ts, str):
                continue
            for me in module_events:
                me_ts = me.get('timestamp', 0)
                if isinstance(me_ts, str):
                    continue
                if self._in_window(se_ts, me_ts):
                    findings.append(self._finding(
                        finding_type='sensitive_file_then_module',
                        events=[se, me],
                        summary="Hassas dosya erişimi sonrası modül yüklendi",
                        severity='critical',
                        confidence='medium',
                    ))

        return findings
