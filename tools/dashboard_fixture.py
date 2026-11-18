"""Fixture reader and operator for the Qt panel: screenshots and offscreen tests, no root, no sockets.

Qt paneli için örnek okuyucu ve yönetim servisi: ekran görüntüleri ve ekransız testler.
"""
import time

from satsuma import home_view

NOW = time.time()


def _info(healthy=False):
    info = {
        'reachable': True,
        'health': {'status': 'PASSED' if healthy else 'DEGRADED', 'updated_at': NOW - 120,
                   'checks': {'dns_filter': {'ok': healthy, 'error': None if healthy else 'dnsmasq DNS readiness failed; no new redirect applied'},
                              'nfqueue_consumers': {'ok': True}, 'packet_drop': {'ok': True},
                              'services': {'ok': healthy, 'states': {
                                  'satsuma-core.service': {'ActiveState': 'active'}, 'satsuma-teams.service': {'ActiveState': 'active'},
                                  'satsuma-reader.service': {'ActiveState': 'active'}, 'satsuma-suricata-ips.service': {'ActiveState': 'active'},
                                  'satsuma-network.service': {'ActiveState': 'active'}, 'satsuma-app-control.service': {'ActiveState': 'active'},
                                  'satsuma-core-dns.service': {'ActiveState': 'active' if healthy else 'failed'},
                                  'satsuma-dns-netns.service': {'ActiveState': 'active'}}}}},
        'summary': {'files': 'Sağlıklı', 'configuration': 'Sağlıklı', 'protection': 'Sağlıklı' if healthy else 'Sorun var',
                    'checked_at': NOW - 300, 'protection_checked_at': NOW - 120},
        'enforcement': {'enabled': True}, 'test_mode': False,
        'dns_policy': {'enabled': True}, 'dns_health': {'ok': healthy, 'blocked_count': 1843,
                                                        'error': None if healthy else 'Filtre yanıt vermiyor'},
        'app': {'status': 'ACTIVE', 'pending': [] if healthy else [
            {'id': 'a' * 32, 'application': {'executable': '/usr/lib64/firefox/firefox'}, 'destination': '151.101.1.91:443',
             'connection_count': 3}]},
        'otx': {'status': 'ACTIVE' if healthy else 'KEY_MISSING'},
        'approvals': {'enabled': False, 'pending_count': 0},
        'network_identity': {'status': 'MATCHED_USER_APPROVAL'}, 'admin_configured': True,
    }
    return info


def _records():
    findings, actions = [], []
    for i in range(11):
        findings.append((NOW - 600 - 3 * i, {'finding_id': 'fl%d' % i, 'rule_id': 'SATSUMA-FILELESS-002', 'severity': 'high',
                                             'rule_name': "Fileless — /dev/shm veya /tmp'den yürütme",
                                             'summary': 'Geçici klasörden çalıştırılan program',
                                             'event': {'exe': '/tmp/.mount_EdenXq/AppRun'}, 'timestamp': NOW - 600 - 3 * i}))
    findings.append((NOW - 3600, {'finding_id': 'm1', 'rule_id': 'RAM-001', 'severity': 'critical',
                                  'rule_name': 'Yazılabilir ve çalıştırılabilir bellek alanı', 'event': {'exe': '/var/tmp/.x/kworkerd'},
                                  'recommendation': 'Programın nereden geldiğini kontrol edin.', 'timestamp': NOW - 3600}))
    actions.append((NOW - 3599, {'action': 'process.terminate', 'finding_id': 'm1', 'status': 'terminated', 'exit_verified': True}))
    findings.append((NOW - 7200, {'finding_id': 'n1', 'rule_id': 'SATSUMA-NET-OTX', 'severity': 'medium',
                                  'rule_name': 'OTX listesindeki adrese bağlantı', 'dest_ip': '203.0.113.77', 'timestamp': NOW - 7200}))
    actions.append((NOW - 7199, {'action': 'otx.indicator_block', 'finding_id': 'n1', 'ip': '203.0.113.77', 'status': 'blocked'}))
    findings.append((NOW - 9000, {'finding_id': 'acc', 'rule_id': 'IDENTITY-ACCOUNT', 'severity': 'low',
                                  'rule_name': 'Hesap dosyası değişti (sistem güncellemesi)', 'event': {'path': '/etc/passwd'},
                                  'timestamp': NOW - 9000}))
    return findings, actions


class FakeReader:
    """What the root reader would answer; ``healthy`` switches between the two states shown."""

    def __init__(self, healthy=False):
        self.healthy = healthy
        self.last_error = None

    def invalidate(self):
        pass

    def close(self):
        pass

    def ping(self):
        return True

    def call(self, method, **params):
        findings, actions = _records()
        if method == 'home':
            page = home_view.home(_info(self.healthy), findings, actions, now=NOW)
            page.update(data_state='OK', version='2.2.45')
            return page
        if method == 'activity':
            rows = home_view.group_activity(findings, actions)
            if params.get('outcome'):
                rows = [r for r in rows if r['outcome'] == params['outcome']]
            text = str(params.get('search') or '').lower()
            if text:
                rows = [r for r in rows if text in (r['title'] + r['subject']).lower()]
            return {'items': rows, 'counts': home_view.activity_counts(rows, NOW), 'data_state': 'OK'}
        if method == 'protection':
            info = _info(self.healthy)
            return {'data_state': 'OK', 'enforcement': True, 'test_mode': False, 'auto_network': True, 'lan_access': True,
                    'subnet_protection': True, 'otx_enabled': False, 'otx_blocker': False, 'dns_filter': True,
                    'dns_upstream': '208.67.222.222', 'dns_health': {**info['dns_health'], 'updated_at': NOW - 60},
                    'allowed_domains': ['ornek-banka.com.tr'], 'allow_ips': [],
                    'custom_lists': {'sources': [{'url': 'https://lists.example.org/malware.txt', 'count': 1843, 'updated_at': NOW - 86400}]},
                    'approvals': {'enabled': False, 'pending_count': 0},
                    'app': {'status': 'ACTIVE', 'enabled': True, 'pending': info['app']['pending'], 'rule_count': 14},
                    'egress': {'base': 'Her zaman açık: DNS (TCP/UDP 53) ve HTTPS (TCP 443).',
                               'incoming': 'Dışarıdan başlatılan bağlantılar her profilde kapalıdır.',
                               'selection': {'addons': ['http'], 'custom': {'tcp': [], 'udp': []}},
                               'addons': [{'id': 'http', 'title': 'Şifresiz web (HTTP, TCP 80)', 'explain': 'Eski siteler ve bazı güncelleme sunucuları.', 'enabled': True},
                                          {'id': 'mail', 'title': 'E-posta istemcisi (IMAP/SMTP)', 'explain': 'Thunderbird gibi programlar için.', 'enabled': False},
                                          {'id': 'quic', 'title': 'QUIC / HTTP3 (UDP 443)', 'explain': 'Bazı sitelerde daha hızlı bağlantı.', 'enabled': False}]},
                    'blocked_ips': [{'ip': '203.0.113.77', 'reason': 'OTX: 4 kaynak'}, {'ip': '198.51.100.23', 'reason': 'Suricata: ET SCAN'}]}
        if method == 'self_health':
            report = dict(_info(self.healthy)['health'])
            report['repairs'] = []
            return report
        if method == 'health_summary':
            return _info(self.healthy)['summary']
        if method == 'maintenance_report':
            return {'status': 'OK', 'updated_at': NOW - 4000, 'repaired': 1, 'rows': [
                {'name': 'Birim satsuma-core-dns.service', 'ok': self.healthy, 'detail': 'Durumu failed; başlatılamadı: dnsmasq'},
                {'name': 'Uygulama imajı', 'ok': True, 'detail': '536 dosya doğrulandı'}]}
        if method == 'system_health':
            return {'admin_credential': {'configured': True}, 'data_state': 'OK'}
        if method == 'ping':
            return 'pong'
        if method in ('findings', 'dns', 'audit', 'suricata', 'response', 'network', 'services', 'rules', 'integrity'):
            return {'items': [], 'data_state': 'OK'}
        return {}


def FakeBackend(healthy=False):
    """The real Backend bridge with the fixture reader in place of the socket."""
    from satsuma.dashboard_qt.backend import Backend, ReaderUpdates

    class _Backend(Backend):
        def __init__(self):
            self.updates = ReaderUpdates()
            self.client = FakeReader(healthy)
            self.health_client = self.client
            self.db_path = 'fixture'
    return _Backend()


class FakeOperator:
    def __init__(self):
        self.calls = []

    def call(self, method, **params):
        self.calls.append((method, {k: v for k, v in params.items() if k not in ('password', 'token')}))
        if method == 'login':
            return {'ok': True, 'token': 't' * 32} if params.get('password') == 'dogru' else {'ok': False, 'error': 'invalid_credentials'}
        if method == 'status':
            return {'ok': True, 'process_approval_pending': [], 'wireguard': {'profiles': [{'name': 'ev-vpn', 'active': False}]}}
        if method == 'repair':
            return {'ok': True, 'accepted': True, 'status': 'RUNNING', 'operation': 'repair'}
        return {'ok': True}
