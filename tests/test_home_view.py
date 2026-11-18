"""2.2.45 user-centred panel model: verdict, what waits for the user, layers, folded activity.

Kullanıcı merkezli panel modeli; ekran olmadan sınanır.
"""
import time

from satsuma import home_view as hv

NOW = 1_800_000_000.0


def healthy_info(**extra):
    info = {
        'reachable': True,
        'health': {'status': 'PASSED', 'updated_at': NOW - 60,
                   'checks': {'dns_filter': {'ok': True}, 'nfqueue_consumers': {'ok': True}}},
        'summary': {'files': 'Sağlıklı', 'configuration': 'Sağlıklı', 'protection': 'Sağlıklı'},
        'enforcement': {'enabled': True}, 'test_mode': False,
        'dns_policy': {'enabled': True}, 'dns_health': {'ok': True, 'blocked_count': 12},
        'app': {'status': 'ACTIVE', 'pending': []}, 'otx': {'status': 'ACTIVE'},
        'approvals': {'enabled': False, 'pending_count': 0},
        'network_identity': {'status': 'MATCHED_USER_APPROVAL'}, 'admin_configured': True,
    }
    info.update(extra)
    return info


def test_everything_on_and_nothing_waiting_says_protected():
    page = hv.home(healthy_info(), now=NOW)
    assert page['verdict']['tone'] == 'ok' and page['verdict']['title'] == 'Korunuyorsunuz'
    assert page['attention'] == []
    assert {l['id']: l['state'] for l in page['layers']} == {
        'process': 'on', 'network': 'on', 'dns': 'on', 'apps': 'on', 'files': 'on', 'intel': 'on'}


def test_failed_health_check_waits_with_a_repair_button_and_names_the_check():
    info = healthy_info(health={'status': 'DEGRADED', 'updated_at': NOW,
                                'checks': {'dns_filter': {'ok': False}, 'nfqueue_consumers': {'ok': True}}},
                        dns_health={'ok': False, 'error': 'dnsmasq DNS readiness failed'})
    page = hv.home(info, now=NOW)
    item = page['attention'][0]
    assert item['title'] == 'DNS filtresi çalışmıyor'
    assert {'label': 'Onar', 'method': 'repair', 'params': {}} in item['actions']
    assert page['verdict']['tone'] == 'attention' and 'DNS filtresi' in page['verdict']['detail']
    assert next(l for l in page['layers'] if l['id'] == 'dns')['state'] == 'problem'


def test_app_requests_are_answered_from_home_and_capped_at_three():
    pending = [{'id': 'r%d' % i, 'application': {'executable': '/usr/bin/app%d' % i}, 'destination': '1.2.3.4:443',
                'connection_count': 2} for i in range(5)]
    page = hv.home(healthy_info(app={'status': 'ACTIVE', 'pending': pending}), now=NOW)
    apps = [i for i in page['attention'] if i['id'].startswith('app:')]
    assert len(apps) == 3 and apps[0]['title'] == 'app0 internete çıkmak istiyor'
    allow = apps[0]['actions'][0]
    assert allow['method'] == 'application_control' and allow['params']['request_id'] == 'r0'
    assert allow['params']['decision'] == 'allow'
    assert next(l for l in page['layers'] if l['id'] == 'apps')['label'] == 'Açık · 5 bekliyor'


def test_critical_integrity_comes_first_and_sets_the_verdict():
    page = hv.home(healthy_info(critical_integrity={'status': 'CRITICAL', 'reason': 'manifest mismatch'},
                                otx={'status': 'KEY_MISSING'}), now=NOW)
    assert page['attention'][0]['id'] == 'integrity' and page['verdict']['tone'] == 'critical'
    assert page['attention'][-1]['id'] == 'otx'   # suggestions last


def test_test_mode_is_described_as_asking_before_stopping():
    page = hv.home(healthy_info(test_mode=True, approvals={'enabled': True, 'pending_count': 2}), now=NOW)
    layer = next(l for l in page['layers'] if l['id'] == 'process')
    assert layer['label'] == 'Açık · durdurmadan önce sorar'
    assert any(i['title'] == '2 program durdurulmak için onayınızı bekliyor' for i in page['attention'])


def test_unreachable_reader_never_claims_protection():
    page = hv.home(healthy_info(reachable=False), now=NOW)
    assert page['verdict']['tone'] == 'unknown' and 'okuyucu' in page['verdict']['detail']


def test_repeated_reports_fold_into_one_row_with_a_count():
    findings = [(NOW - 3 * i, {'finding_id': 'f%d' % i, 'rule_id': 'SATSUMA-FILELESS-002', 'severity': 'high',
                               'rule_name': "Fileless — /dev/shm veya /tmp'den yürütme",
                               'event': {'exe': '/tmp/.mount_appXYZ/AppRun'}, 'timestamp': NOW - 3 * i})
                for i in range(11)]
    rows = hv.group_activity(findings, [])
    assert len(rows) == 1
    row = rows[0]
    assert row['count'] == 11 and row['subject'] == '/tmp/.mount_appXYZ/AppRun'
    assert row['outcome'] == 'reported' and row['first_at'] == NOW - 30 and row['last_at'] == NOW
    assert row['finding_id'] == 'f0'


def test_actions_decide_what_satsuma_did():
    findings = [(NOW, {'finding_id': 'a', 'rule_id': 'R1', 'severity': 'critical', 'event': {'exe': '/tmp/x'}}),
                (NOW, {'finding_id': 'b', 'rule_id': 'R2', 'severity': 'medium', 'event': {'exe': '/usr/bin/y'}})]
    actions = [(NOW, {'action': 'process.terminate', 'finding_id': 'a', 'status': 'terminated', 'exit_verified': True}),
               (NOW, {'action': 'process.terminate', 'finding_id': 'b', 'status': 'exempt'}),
               (NOW, {'action': 'otx.indicator_block', 'ip': '203.0.113.9', 'status': 'blocked'})]
    rows = {r['subject']: r for r in hv.group_activity(findings, actions)}
    assert rows['/tmp/x']['outcome_label'] == 'Durduruldu'
    assert rows['/usr/bin/y']['outcome'] == 'not_stopped' and 'Korunan' in rows['/usr/bin/y']['what_satsuma_did']
    blocked = rows['203.0.113.9']
    assert blocked['outcome'] == 'blocked'
    assert {a['method'] for a in blocked['actions'] if 'method' in a} == {'unblock', 'allow_ip'}
    assert all(a['weakens'] for a in blocked['actions'] if 'method' in a)


def test_counts_cover_the_last_day_only():
    old = [(NOW - 3 * 86400, {'finding_id': 'o', 'rule_id': 'R', 'event': {'exe': '/a'}, 'timestamp': NOW - 3 * 86400})]
    new = [(NOW, {'finding_id': 'n', 'rule_id': 'R', 'event': {'exe': '/b'}, 'timestamp': NOW})]
    rows = hv.group_activity(old + new, [(NOW, {'action': 'process.terminate', 'finding_id': 'n',
                                                 'status': 'terminated', 'exit_verified': True})])
    assert hv.activity_counts(rows, now=NOW) == {'stopped': 1, 'blocked': 0, 'quarantined': 0, 'reported': 0,
                                                 'waiting': 0, 'findings': 1}


def test_reader_exposes_home_activity_and_maintenance(monkeypatch):
    from satsuma import dashboard_api as api
    assert {'home', 'activity', 'maintenance_report'} <= set(api.METHODS)
    monkeypatch.setattr(api, '_home_info', lambda: healthy_info())

    def no_db():
        raise OSError('no database here')
    monkeypatch.setattr(api, '_connect', no_db)
    page = api.METHODS['home']({})
    assert page['verdict']['title'] == 'Korunuyorsunuz' and page['recent'] == [] and page['version']
    assert api.METHODS['activity']({})['data_state'] == 'UNKNOWN'


def test_recent_records_reads_findings_events_and_actions(tmp_path):
    import json
    import sqlite3
    db = sqlite3.connect(tmp_path / 'core.db')
    db.execute('CREATE TABLE records (id INTEGER PRIMARY KEY, kind TEXT, created REAL, body TEXT)')
    now = time.time()
    rows = [('findings', {'finding_id': 'x', 'rule_id': 'R'}),
            ('events', {'metadata': {'finding': {'finding_id': 'y', 'rule_id': 'S'}}}),
            ('events', {'event': {'category': 'process'}}),
            ('actions', {'action': 'process.terminate', 'finding_id': 'x'})]
    for kind, body in rows:
        db.execute('INSERT INTO records (kind, created, body) VALUES (?,?,?)', (kind, now, json.dumps(body)))
    from satsuma.dashboard_api import _recent_records
    result = _recent_records(db, ('findings', 'events', 'actions'), 24, 100)
    assert sorted(f['finding_id'] for _, f in result['findings']) == ['x', 'y']
    assert len(result['actions']) == 1


def test_repair_is_a_bounded_maintenance_job():
    from satsuma.maintenance_jobs import MaintenanceJobs
    started = []

    class Popen:
        def __init__(self, command, **kwargs):
            started.append(command)

        def poll(self):
            return None
    jobs = MaintenanceJobs(store=None, popen=Popen)
    assert jobs.start('repair')['operation'] == 'repair'
    assert started == [['/usr/bin/systemctl', 'start', '--wait', 'satsuma-maintenance.service']]
    from satsuma.operator_service import weakens
    assert weakens('repair', {}) is False
