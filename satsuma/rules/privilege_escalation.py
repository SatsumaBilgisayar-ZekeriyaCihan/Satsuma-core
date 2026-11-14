"""Kural: root olmayan → sudo/su/pkexec kullanımı."""
from .base import Rule


PRIV_TOOLS = ('sudo', 'su', 'pkexec', 'doas', 'setpriv')


class PrivilegeEscalationRule(Rule):
    name = "privilege_escalation"
    severity = "medium"
    description = "Yetki yükseltme girişimi"

    def match(self, events):
        findings = []

        # 1. Yetki yükseltme araçları
        priv_events = []
        for e in events:
            cmd = str(e.get('metadata', {}).get('extensions', {}).get('host.cmd', ''))
            for tool in PRIV_TOOLS:
                if f'/{tool}' in cmd or cmd.startswith(f'{tool} '):
                    priv_events.append((e, tool))
                    break

        # 2. UID kontrolü (root olmayan)
        for e, tool in priv_events:
            exts = e.get('metadata', {}).get('extensions', {})
            uid = exts.get('host.uid')
            if uid is not None and uid != 0:
                findings.append(self._finding(
                    finding_type='privilege_escalation_attempt',
                    events=[e],
                    summary=f"UID {uid} → {tool} çalıştırdı",
                    severity='medium',
                    confidence='high',
                ))

        return findings
