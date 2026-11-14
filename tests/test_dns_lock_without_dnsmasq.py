"""The DNS lock works without dnsmasq; no list is downloaded (owner, 2026-11-13).

dnsmasq ve indirilen HaGeZi listeleri kullanılmaz; DNS kilidi onlarsız çalışır.
"""
from types import SimpleNamespace

from installer import network_modes_setup
from satsuma import configuration_reload, domain_lists
from satsuma.network_modes import DNS_TABLE, LAN_TABLE


class Store:
    def __init__(self, **state):
        self.state = dict(state)

    def get(self, key, default=None):
        return self.state.get(key, default)

    def set(self, key, value):
        self.state[key] = value


class Modes:
    def __init__(self):
        self.applied = []

    def apply(self, table, enabled):
        self.applied.append((table, enabled))
        return {'ok': True, 'enabled': enabled}


def test_the_lock_is_applied_and_checked_without_any_local_filter(monkeypatch):
    import satsuma.dnsmasq_control as dnsmasq
    monkeypatch.setattr(dnsmasq, 'probe', lambda *a, **k: (_ for _ in ()).throw(AssertionError('no dnsmasq probe')))
    store, modes = Store(dns_policy={'enabled': True, 'upstream': '208.67.222.222'}), Modes()
    network_modes_setup.configure(store, modes, probe=lambda: {'system_ready': True, 'resolver': '127.0.0.53'})
    assert (DNS_TABLE, True) in modes.applied and (LAN_TABLE, False) in modes.applied
    health = store.state['dns_filter_health']
    assert health['status'] == 'LOCK_ACTIVE' and health['ok'] is True and health['system_ready'] is True


def test_configuration_reload_turns_the_lists_off_and_downloads_nothing(monkeypatch):
    monkeypatch.setattr(domain_lists, '_download_retired', lambda *a, **k: (_ for _ in ()).throw(AssertionError('download')))
    import inspect
    source = inspect.getsource(configuration_reload)
    assert 'update_list' not in source
    assert "hagezi_enabled=False" in source and "threat_lists_enabled=False" in source
