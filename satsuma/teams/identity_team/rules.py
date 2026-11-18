"""Kimlik Ekibi kuralları."""
from satsuma.teams.host_team.rules import _BaseRule


PRIV_TOOLS = ('sudo', 'su', 'pkexec', 'doas', 'setpriv')
# 2.2.38: exact files and folder contents only. A prefix match counted
# /etc/passwd-, /etc/shadow+ and the like. /etc/passwd and /etc/shadow are
# judged by what a write changed in the rule engine (satsuma.account_change);
# a second "high" alarm for the same write is not raised here.
# Yalnızca tam dosya ve klasör içeriği; passwd/shadow yazmasını kural motoru
# içeriğine bakarak değerlendirir, burada ikinci alarm verilmez.
SENSITIVE_PATHS = ('/etc/sudoers', '/root/.ssh')


def sensitive(path):
    return any(path == item or path.startswith(item + '/') for item in SENSITIVE_PATHS)


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
            if path and sensitive(path):
                findings.append(self._finding(
                    'sensitive_file_access',
                    [e],
                    f"Hassas dosya erişimi: {path}",
                    severity='high',
                ))
        return findings
