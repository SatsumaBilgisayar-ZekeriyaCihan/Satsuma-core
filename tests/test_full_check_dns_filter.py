"""2.2.36: the full check reports the DNS filter and switches it back on when it is off.

2.2.36: tam kontrol DNS filtresini bildirir, kapalıysa yeniden açar.

Field 2026-11-04: dns_policy.enabled was False; self-health said "DNS filtresi kapalı",
but `satsuma-admin tam-kontrol` printed no DNS filter row and left it off.
Saha 2026-11-04: dns_policy.enabled False idi; sağlık kontrolü "DNS filtresi kapalı"
diyordu ama `satsuma-admin tam-kontrol` DNS filtresi satırı yazmıyor ve kapalı bırakıyordu.
"""
import pytest

from satsuma import full_check
from satsuma.store import Store


class Calls:
    def __init__(self, fail_at=None):
        self.order, self.fail_at = [], fail_at

    def step(self, name, *args):
        self.order.append(name if not args else (name, *args))
        if self.fail_at == name:
            raise RuntimeError(f'{name} failed')

    def hooks(self):
        return dict(rule=lambda: self.step('rule'), refresh=lambda store: self.step('refresh'),
                    probe=lambda: self.step('probe'), apply=lambda table, on: self.step('apply', table, on),
                    ready=lambda store: self.step('ready'))


@pytest.fixture()
def store(tmp_path):
    handle = Store(tmp_path / 'data', test=True)
    yield handle
    handle.close()


def test_disabled_filter_is_switched_on_in_order(store):
    store.set('dns_policy', {'enabled': False, 'upstream': '208.67.222.222'})
    calls = Calls()
    row = full_check.dns_filter_row(store, True, **calls.hooks())
    assert calls.order == ['rule', 'refresh', 'probe', ('apply', 'satsuma_dns', True), 'ready']
    assert store.get('dns_policy')['enabled'] is True and store.get('dns_policy')['upstream'] == '208.67.222.222'
    assert row['ok'] is True and 'açıldı' in row['detail']


@pytest.mark.parametrize('fail_at', ['refresh', 'probe', 'apply', 'ready'])
def test_failed_switch_on_restores_the_policy_and_reports_the_reason(store, fail_at):
    store.set('dns_policy', {'enabled': False, 'upstream': '208.67.222.222'})
    row = full_check.dns_filter_row(store, True, **Calls(fail_at).hooks())
    assert store.get('dns_policy') == {'enabled': False, 'upstream': '208.67.222.222'}
    assert row['ok'] is False and f'{fail_at} failed' in row['detail']


def test_without_fix_nothing_is_changed(store):
    store.set('dns_policy', {'enabled': False, 'upstream': '208.67.222.222'})
    calls = Calls()
    row = full_check.dns_filter_row(store, False, **calls.hooks())
    assert calls.order == [] and store.get('dns_policy')['enabled'] is False
    assert row['ok'] is False and 'Kapalı' in row['detail']


def test_never_configured_filter_starts_with_the_pinned_opendns(store):
    calls = Calls()
    row = full_check.dns_filter_row(store, True, **calls.hooks())
    assert store.get('dns_policy')['upstream'] == '208.67.222.222' and row['ok'] is True


@pytest.mark.parametrize('bad', ['127.0.0.1', '0.0.0.0', '224.0.0.1', 'not-an-ip'])
def test_an_unusable_stored_upstream_is_replaced_by_the_pinned_opendns(store, bad):
    store.set('dns_policy', {'enabled': False, 'upstream': bad})
    full_check.dns_filter_row(store, True, **Calls().hooks())
    assert store.get('dns_policy')['upstream'] == '208.67.222.222'


def test_an_enabled_healthy_filter_is_left_alone(store):
    store.set('dns_policy', {'enabled': True, 'upstream': '208.67.220.220'})
    store.set('dns_filter_health', {'ok': True, 'status': 'ACTIVE'})
    calls = Calls()
    row = full_check.dns_filter_row(store, True, **calls.hooks())
    assert calls.order == [] and row['ok'] is True


def test_an_enabled_but_unhealthy_filter_is_reported_with_its_error(store):
    store.set('dns_policy', {'enabled': True, 'upstream': '208.67.220.220'})
    store.set('dns_filter_health', {'ok': False, 'status': 'FAILED', 'error': 'readiness timed out'})
    calls = Calls()
    row = full_check.dns_filter_row(store, True, **calls.hooks())
    assert calls.order == [] and row['ok'] is False and 'readiness timed out' in row['detail']


def _check(store, **extra):
    from types import SimpleNamespace
    ok = lambda name: (lambda: full_check._row(name, True, ''))
    return full_check.check(
        store, runner=lambda *a, **k: SimpleNamespace(stdout='active', returncode=0), protection=lambda: [], fix=False,
        config_loader=lambda: ({}, None), modem=ok('m'), ipv6=lambda: {'ipv6_off': True, 'enabled_on': []},
        sudo=lambda: [], keys=lambda: [], binary=ok('b'), ssh=ok('s'), python=ok('p'), media=ok('md'),
        systemd=ok('sd'), boot=ok('bt'), mitm=ok('mt'), **extra)


def test_injected_runners_skip_the_real_dns_steps(store):
    assert 'DNS filtresi' not in [row['name'] for row in _check(store)]


def test_check_adds_the_dns_filter_row(store):
    rows = _check(store, dns_filter=lambda: full_check._row('DNS filtresi', False, 'Kapalı'))
    assert [row for row in rows if row['name'] == 'DNS filtresi'] == [{'name': 'DNS filtresi', 'ok': False, 'detail': 'Kapalı'}]
