"""Kimlik Ekibi kuralları."""
from satsuma.teams.host_team.rules import _BaseRule


PRIV_TOOLS = ('sudo', 'su', 'pkexec', 'doas', 'setpriv')
SENSITIVE_PATHS = ('/etc/passwd', '/etc/shadow', '/etc/sudoers', '/root/.ssh')


class PrivilegeEscalationRule(_BaseRule):
    name = "privilege_escalation_attempt"
    severity = "medium"

    def match(self, events):
        findings = []
        for e in events:
            exts = e.get('metadata', {}).get('extensions', {})
            cmd = str(exts.get('host.cmd', '')) or str(exts.get('host.exe', ''))
            for tool in PRIV_TOOLS:
                if f'/{tool}' in cmd or cmd.startswith(f'{tool} '):
                    uid = exts.get('host.uid')
                    if uid is not None and str(uid) != '0':
                        findings.append(self._finding(
                            'privilege_escalation_attempt',
                            [e],
                            f"UID {uid} -> {tool}",
                            severity='medium',
                        ))
                    break
        return findings


class LoginAnomalyRule(_BaseRule):
    name = "login_anomaly"
    severity = "medium"

    def match(self, events):
        findings = []
        for e in events:
            if e.get('action') == 'user_event':
                exts = e.get('metadata', {}).get('extensions', {})
                subtype = exts.get('host.subtype', '')
                if subtype in ('USER_LOGIN', 'USER_AUTH'):
                    result = exts.get('host.result', '')
                    if result and result != 'success':
                        findings.append(self._finding(
                            'login_failure',
                            [e],
                            f"{subtype} başarısız",
                            severity='medium',
                        ))
        return findings


class SensitiveFileRule(_BaseRule):
    name = "sensitive_file_access"
    severity = "high"

    def match(self, events):
        findings = []
        for e in events:
            exts = e.get('metadata', {}).get('extensions', {})
            path = str(exts.get('host.path', ''))
            if path and any(path.startswith(sp) for sp in SENSITIVE_PATHS):
                findings.append(self._finding(
                    'sensitive_file_access',
                    [e],
                    f"Hassas dosya erişimi: {path}",
                    severity='high',
                ))
        return findings
