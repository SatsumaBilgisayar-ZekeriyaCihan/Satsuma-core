"""Network protection is judged by the subnet blocker, not by the OTX key.

Ağ koruması OTX anahtarıyla değil alt ağ engelleyiciyle değerlendirilir.
"""
from satsuma.self_health import UNITS, subnet_check
from satsuma.status_view import health_summary

NOW = 1_000_000.0


def test_running_blocker_is_healthy_without_otx():
    row = subnet_check(None, {'status': 'running', 'updated_at': NOW - 5, 'threshold': 10}, now=NOW)
    assert row['ok'] and row['status'] == 'ACTIVE'


def test_locked_blocker_is_a_failed_check_with_its_reason():
    row = subnet_check({'enabled': True}, {'status': 'boot_integrity_locked', 'updated_at': NOW}, now=NOW)
    assert not row['ok'] and row['status'] == 'LOCKED' and 'kilitli' in row['message']


def test_silent_disabled_or_failing_blocker_is_never_healthy():
    assert subnet_check({'enabled': True}, {'status': 'running', 'updated_at': NOW - 600}, now=NOW)['status'] == 'NO_RECENT_RESULT'
    assert subnet_check({'enabled': False}, {'status': 'running', 'updated_at': NOW}, now=NOW)['status'] == 'DISABLED'
    assert not subnet_check({}, {'status': 'error', 'updated_at': NOW, 'error': 'nft'}, now=NOW)['ok']


def test_subnet_unit_is_watched_and_its_failure_is_named():
    assert 'satsuma-core-subnet.service' in UNITS
    summary = health_summary({}, {}, {'status': 'DEGRADED', 'updated_at': NOW,
                                     'checks': {'subnet_protection': {'ok': False}}}, now=NOW)
    assert summary['failed_checks'] == ['Alt ağ engelleyici']


def test_full_check_reports_the_subnet_blocker():
    from satsuma.full_check import check

    class Store:
        data = {'subnet_health': {'status': 'running', 'updated_at': __import__('time').time()}}
        def get(self, key, default=None): return self.data.get(key, default)
        def set(self, key, value): self.data[key] = value

    class Done:
        returncode, stdout = 0, 'active'

    rows = check(Store(), runner=lambda *a, **k: Done(), config_loader=lambda: ({}, None, None),
                 modem=lambda: {'name': 'm', 'ok': True, 'detail': ''}, ipv6=lambda: {'ipv6_off': True, 'enabled_on': []},
                 keys=lambda: [], sudo=lambda: [], protection=lambda: [], binary=lambda: {'name': 'b', 'ok': True, 'detail': ''},
                 ssh=lambda: {'name': 's', 'ok': True, 'detail': ''}, python=lambda: {'name': 'p', 'ok': True, 'detail': ''},
                 media=lambda: {'name': 'm2', 'ok': True, 'detail': ''}, systemd=lambda: {'name': 'sd', 'ok': True, 'detail': ''},
                 boot=lambda: {'name': 'bt', 'ok': True, 'detail': ''}, mitm=lambda: {'name': 'mi', 'ok': True, 'detail': ''},
                 browser=lambda: {'name': 'br', 'ok': True, 'detail': ''},
                 aide=lambda: {'name': 'ai', 'ok': True, 'detail': ''}, fix=False)
    row = next(r for r in rows if r['name'] == 'Alt ağ engelleyici')
    assert row['ok'] and 'OTX anahtarı gerekmez' in row['detail']
