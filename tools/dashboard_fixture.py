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


def _logbook(params):
    """record_catalog.timeline over an in-memory copy of the fixture records."""
    import json
    import sqlite3
    from contextlib import contextmanager
    from satsuma.record_catalog import timeline
    findings, actions = _records()
    rows = [(ts, 'findings', f) for ts, f in findings] + [(ts, 'actions', a) for ts, a in actions]
    rows += [(NOW - 1800, 'errors', {'component': 'DNS filtresi', 'error': 'dnsmasq yanıt vermedi; yeniden başlatıldı'}),
             (NOW - 2400, 'flow_guard', {'code': 'engine_restarted', 'ok': True, 'detail': 'Kural motoru 4 sn sessiz kaldı'}),
             (NOW - 300, 'events', {'source': 'sys_proc', 'action': 'exec', 'exe': '/usr/bin/curl', 'cmd': 'curl https://example.org'})]
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE records (id INTEGER PRIMARY KEY, created REAL, kind TEXT, body TEXT)')
    for ts, kind, body in sorted(rows, key=lambda r: r[0]):
        db.execute('INSERT INTO records(created,kind,body) VALUES(?,?,?)', (ts, kind, json.dumps(body, ensure_ascii=False)))

    @contextmanager
    def connect():
        yield db
    return timeline((('core', connect),), view=params.get('view', 'important'), hours=params.get('hours', 24),
                    search=params.get('search', ''), before=params.get('before'), limit=params.get('limit', 100), now=NOW)


def _scanners():
    excerpt = ('/home/kullanici/İndirilenler/fatura.pdf.exe: Win.Trojan.Agent-1234 FOUND\n----------- SCAN SUMMARY -----------\n'
               'Scanned directories: 12034\nScanned files: 184512\nInfected files: 1\nData scanned: 9876.43 MiB\n'
               'Time: 1532.118 sec (25 m 32 s)\n')
    clam = {'_id': 31, 'timestamp': NOW - 5400, 'completed_at': NOW - 3868, 'tool': 'clamav', 'status': 'FINDINGS', 'findings': 1,
            'exit_code': 1, 'output_excerpt': excerpt,
            'files': [{'path': '/home/kullanici/İndirilenler/fatura.pdf.exe', 'signature': 'Win.Trojan.Agent-1234', 'sha256': 'ab' * 32}],
            'quarantine': [{'source': '/home/kullanici/İndirilenler/fatura.pdf.exe', 'status': 'quarantined'}]}
    old = {'_id': 21, 'timestamp': NOW - 90000, 'completed_at': NOW - 88500, 'tool': 'clamav', 'status': 'COMPLETED', 'findings': 0,
           'exit_code': 0, 'fallback_from': 'clamdscan',
           'summary': {'scanned_files': 183977, 'infected_files': 0, 'data_scanned': '9841.10 MiB'}}
    rk = {'_id': 32, 'timestamp': NOW - 3860, 'completed_at': NOW - 3700, 'tool': 'rkhunter', 'status': 'WARNING', 'findings': 2, 'exit_code': 1}
    chk = {'_id': 33, 'timestamp': NOW - 3690, 'completed_at': NOW - 3690, 'tool': 'chkrootkit', 'status': 'UNAVAILABLE', 'findings': 0,
           'error': 'chkrootkit komutu bulunamadı'}
    hide = {'_id': 34, 'timestamp': NOW - 3600, 'completed_at': NOW - 3500, 'tool': 'unhide', 'status': 'FINDINGS', 'findings': 1,
            'hidden': [{'kind': 'hidden_pid', 'pid': 31337, 'executable': '/usr/lib/.x/kworker', 'verdict': 'hidden'}],
            'recheck': {'checked': 41, 'still_hidden': [31337], 'dismissed': {'thread': 38, 'transient': 2}}}
    return {'items': [chk, hide, rk, clam, old], 'data_state': 'OK',
            'hidden': {'open': [{'pid': 31337, 'executable': '/usr/lib/.x/kworker', 'timestamp': NOW - 3600}],
                       'closed': {'thread': 38, 'transient': 2}}, 'scope': 'Bu bilgisayarda yerel dosya ve sistem taraması',
            'engines': {'clamav': {'installed': True, 'last_result': clam}, 'rkhunter': {'installed': True, 'last_result': rk},
                        'chkrootkit': {'installed': False, 'last_result': chk}},
            'quarantine': [{'quarantine_id': 'q1', 'path': '/home/kullanici/İndirilenler/fatura.pdf.exe'}]}


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
                    'blocked_ips': [{'ip': '203.0.113.77', 'reason': 'OTX: 4 kaynak'}, {'ip': '198.51.100.23', 'reason': 'Suricata: ET SCAN'}],
                    'network_blocks': [{'network': '192.168.0.0/16', 'reason': 'Misafir ağı', 'added_at': NOW - 3000}]}
        if method == 'logbook':
            return _logbook(params)
        if method == 'security_scanners':
            return _scanners()
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
        if method == 'rules':
            from satsuma import rule_effect
            rows = []
            for rid, name, cls, sev in (('SATSUMA-C2-001', 'Ters shell', 'likely', 'critical'),
                                        ('SATSUMA-CRED-001', '/etc/shadow okuma', 'suspicious', 'critical'),
                                        ('SATSUMA-COLL-002', 'Ekran goruntusu', 'indicator', 'medium'),
                                        ('SATSUMA-BPF-CLI-001', 'BPF utility invocation', 'indicator', 'low')):
                rule = {'id': rid, 'name': name, 'classification': cls, 'severity': sev}
                rows.append({**rule, 'rule_id': rid, **rule_effect.row(rule, True),
                             'last_intervention': 'Durduruldu' if rid == 'SATSUMA-C2-001' else '—'})
            counts = {'stopped': 3, 'gone': 12, 'denied': 1, 'failed': 0}
            return {'rules': rows, 'data_state': 'OK', 'stop_outcomes_24h': counts,
                    'summary_text': rule_effect.summary_text(251, 136, 115, True, counts, ai_total=20)}
        if method in ('findings', 'dns', 'audit', 'suricata', 'response', 'network', 'services', 'integrity'):
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
