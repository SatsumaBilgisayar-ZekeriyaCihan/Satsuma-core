"""2.2.10: automatic modem enrollment and the full on/running check.

2.2.10: otomatik modem kaydı ve tam açık/çalışıyor kontrolü.
"""
from types import SimpleNamespace

from installer import integrity
from satsuma import full_check, modem_identity as m
from satsuma.store import Store


def _data(candidates):
    return {'candidates': candidates, 'route_fingerprint': 'f' * 64, 'rejected': [], 'manual_routes': []}


MODEM = {'table': '254', 'interface': 'enp3s0', 'interface_mac': '52:54:00:12:34:56',
         'gateway': '192.168.1.1', 'gateway_mac': 'a8:9a:93:00:00:01', 'id': 'x'}


def test_single_modem_is_enrolled_automatically(monkeypatch):
    monkeypatch.setattr(integrity, 'read_key', lambda: b'k' * 32)
    saved = []
    result = m.approve_automatic(data=_data([MODEM]), writer=saved.append)
    assert result['status'] == 'AUTOMATICALLY_ENROLLED'
    assert saved[0]['policy']['source'] == 'automatic_single_candidate' and saved[0]['policy']['modem'] == MODEM
    assert 'automatic_single_candidate' in m.SOURCES


def test_none_or_two_modems_are_not_guessed(monkeypatch):
    monkeypatch.setattr(integrity, 'read_key', lambda: b'k' * 32)
    for candidates in ([], [MODEM, {**MODEM, 'gateway': '192.168.2.1', 'id': 'y'}]):
        saved = []
        result = m.approve_automatic(data=_data(candidates), writer=saved.append)
        assert result['status'] == 'NOT_ENROLLED' and not saved and result['reasons']


def test_full_check_switches_everything_back_on_and_reports(tmp_path):
    store = Store(tmp_path / 'data', test=True)
    try:
        store.set('enforcement_policy', {'enabled': False})
        store.set('auto_action_policy', {'network_enabled': False})
        store.set('operator_otx_policy', {'enabled': False, 'blocker_mode': False})
        store.set('operator_pause', True)
        store.set('subnet_health', {'status': 'running', 'updated_at': __import__('time').time()})
        runner = lambda cmd, **kw: SimpleNamespace(returncode=1 if 'nft' in cmd[0] else 0, stdout='active\n')
        rows = full_check.check(store, runner=runner, config_loader=lambda: ({k: True for k in __import__('satsuma.full_protection', fromlist=['x']).FULL_PROTECTION},),
                                modem=lambda: full_check._row('Modem', True, 'Tanındı'),
                                ipv6=lambda: {'ipv6_off': True, 'enabled_on': []}, keys=lambda: [], sudo=lambda: [],
                                binary=lambda: full_check._row('Sistem programları', True, 'temiz'),
                                ssh=lambda: full_check._row('SSH anahtarları', True, 'temiz'),
                                python=lambda: full_check._row('Python betikleri', True, 'temiz'),
                                media=lambda: full_check._row('Medya', True, 'temiz'),
                                systemd=lambda: full_check._row('systemd', True, 'temiz'),
                                boot=lambda: full_check._row('Açılış', True, 'temiz'),
                                mitm=lambda: full_check._row('Ortadaki adam', True, 'temiz'),
                                browser=lambda: full_check._row('Tarayıcı politikaları', True, 'kilitli'),
                                aide=lambda: full_check._row('AIDE bekçisi', True, 'Örnekle aynı'))
        by = {r['name']: r for r in rows}
        assert 'enforcement_policy' in by['Panel anahtarları']['detail']
        assert by['Otomatik engelleme']['ok'] and by['Otomatik ağ engeli']['ok'] and by['OTX sorgu ve engeli']['ok']
        assert 'Aksiyonlar' not in by and store.get('operator_pause') is False
        assert not by['Güvenlik duvarı (satsuma_core)']['ok']
        text = full_check.report(rows)
        assert '[SORUN] Güvenlik duvarı' in text and '1 maddede sorun var' in text
    finally:
        store.close()


def test_route_change_alone_is_reported_as_a_problem(monkeypatch):
    # The health check counts only MATCHED_USER_APPROVAL as healthy.
    policy = {'modem': MODEM, 'route_fingerprint': 'a' * 64}
    monkeypatch.setattr(m, 'inventory', lambda: _data([MODEM]))
    monkeypatch.setattr(m, 'load', lambda: policy)
    row = full_check.modem_row()
    assert row['ok'] is False and 'sudo satsuma-admin modem' in row['detail']
    monkeypatch.setattr(m, 'load', lambda: {**policy, 'route_fingerprint': 'f' * 64})
    assert full_check.modem_row()['ok'] is True


def test_cross_team_finding_names_the_program(tmp_path):
    from satsuma.correlation_manager import CorrelationManager, process_identity
    events = [{'pid': 4242, 'exe': '/usr/bin/python3', 'cmd': '/usr/bin/python3 /usr/bin/satsuma-admin tam-kontrol', 'uid': 0}]
    assert process_identity('4242', events, proc_root=str(tmp_path))['cmd'].endswith('tam-kontrol')
    manager = CorrelationManager.__new__(CorrelationManager)
    cross = manager._cross_team_link([
        {'team': 'host_team', 'type': 'root_exec', 'summary': 'root komutu', 'events': events},
        {'team': 'identity_team', 'type': 'sudo', 'summary': 'sudo kullanımı', 'events': [{'pid': 4242}]}])
    assert 'satsuma-admin tam-kontrol' in cross[0]['summary']
    assert cross[0]['process']['uid'] == 0 and {f['summary'] for f in cross[0]['findings']} == {'root komutu', 'sudo kullanımı'}


def test_refused_action_shows_its_reasons_and_indicators_read_as_reported():
    from satsuma.presentation import action_view
    view = action_view({'action': 'process.terminate', 'status': 'policy_denied',
                        'reasons': ['missing_event_process_identity', 'historical_or_future_event']})
    assert view['reason'] == 'Olayda süreç kimliği (PID) yok, Olay zamanı güncel müdahale aralığı dışında (eski veya ileri tarihli)'
    view = action_view({'action': 'process.terminate', 'status': 'report_only',
                        'reasons': ['activity_indicator_reports_only']})
    assert view['outcome'] == 'Süreç durdurulmadı; bulgu yalnızca bildirildi' and 'yalnızca bildirilir' in view['reason']


def test_field_outcomes_2026_11_04_read_correctly():
    from satsuma.presentation import action_view
    gone = action_view({'status': 'identity_verification_failed', 'reason': 'live_process_not_found', 'pid': 51404})
    assert gone['outcome'].startswith('Durdurulmadı: süreç bundan önce kendiliğinden sonlanmıştı')
    cut = action_view({'status': 'connection_terminated', 'terminated': True, 'verified': True,
                       'source': 'suricata_guard', 'ip': '104.26.6.74'})
    assert cut['outcome'] == 'Bağlantı kesildi; doğrulandı'
    step = action_view({'status': 'process_termination_authorized', 'pid': 52236})
    assert 'ara adım' in step['outcome']
