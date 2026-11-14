"""Ag Ekibi kurallari. Normalized Suricata semasini kullanir."""
from satsuma.teams.host_team.rules import _BaseRule


def _ext(e):
    return (e.get('metadata') or {}).get('extensions') or {}

def _net(e):
    return e.get('network') or {}


class C2CommunicationRule(_BaseRule):
    """Yuksek Suricata alert + ayni hedefte bagimsiz TLS/HTTP aktivitesi."""
    name = "c2_communication"
    severity = "high"

    def match(self, events):
        findings = []
        alerts = [e for e in events if e.get('action') == 'alert' and str(_ext(e).get('suricata.severity_raw')) == '1']
        for alert in alerts:
            dst = _net(alert).get('dst_ip')
            if not dst:
                continue
            related = [alert]
            for e in events:
                if e is alert:
                    continue
                if _net(e).get('dst_ip') == dst and e.get('action') in ('tls', 'http'):
                    related.append(e)
            if len(related) >= 2:
                findings.append(self._finding(
                    'c2_communication', related,
                    f"Yuksek oncelikli Suricata alert + ayni hedefte ag aktivitesi: {dst}",
                    severity='high', confidence='medium', classification='suspicious',
                    extra={'dst_ip': dst},
                ))
        return findings


class PortScanRule(_BaseRule):
    """Ayni kaynak icin Suricata alertlerinde cok sayida farkli hedef port."""
    name = "port_scan"
    severity = "high"

    def match(self, events):
        by_src = {}
        for e in events:
            if e.get('action') != 'alert':
                continue
            net = _net(e)
            src, dst_port = net.get('src_ip'), net.get('dst_port')
            if src and dst_port is not None:
                by_src.setdefault(src, set()).add(int(dst_port))
        findings = []
        for src, ports in by_src.items():
            if len(ports) < 10:
                continue
            related = [e for e in events if _net(e).get('src_ip') == src and e.get('action') == 'alert'][:10]
            findings.append(self._finding(
                'port_scan', related, f"Coklu port tarama gostergesi: {src} -> {len(ports)} port",
                severity='high', confidence='medium', classification='suspicious',
                extra={'src_ip': src, 'port_count': len(ports)},
            ))
        return findings


class DnsTunnelingRule(_BaseRule):
    """Uzun ve yuksek karakter cesitliligine sahip DNS adini supheli sinyal olarak isaretler."""
    name = "dns_tunneling"
    severity = "medium"

    def match(self, events):
        findings = []
        for e in events:
            if e.get('action') != 'dns':
                continue
            query = str(_ext(e).get('suricata.dns.query') or _ext(e).get('suricata.dns.rrname') or '')
            if not query or len(query) <= 60 or query.count('.') < 3:
                continue
            unique_chars = len(set(query.replace('.', '')))
            if unique_chars <= 20:
                continue
            findings.append(self._finding(
                'dns_tunneling', [e], f"Uzun/yuksek cesitlilikli DNS sorgusu: {query[:80]}",
                severity='medium', confidence='low', classification='indicator',
                extra={'query': query[:200]},
            ))
        return findings
