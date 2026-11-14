"""OpenDNS is the default DNS upstream (user decision 2026-10-26).

OpenDNS varsayılan DNS üst sunucusudur (kullanıcı kararı 2026-10-26).
"""
import pytest

from installer import dns_setup
from satsuma.dnsmasq_control import OPENDNS, upstream_servers
from satsuma.self_health import dns_resolver_alignment


class Store:
    def __init__(self, policy):
        self.policy = policy

    def get(self, key, default=None):
        return self.policy if key == 'dns_policy' else default

    def set(self, key, value):
        self.policy = value


def test_a_new_installation_starts_with_opendns():
    store = Store({})
    dns_setup.configure(store, refresh=lambda s: None)
    assert store.policy['upstream'] == '208.67.222.222' and store.policy['enabled'] is True


def test_dnsmasq_gets_both_opendns_servers_and_only_the_chosen_one_otherwise():
    assert upstream_servers('208.67.220.220') == ['208.67.220.220', '208.67.222.222']
    assert upstream_servers('208.67.222.222') == list(OPENDNS)
    assert upstream_servers('9.9.9.9') == ['9.9.9.9']
    with pytest.raises(ValueError):
        upstream_servers('not-an-address')


@pytest.mark.parametrize('policy,upstream,source', [
    ({}, '208.67.222.222', 'opendns_default'),
    ({'upstream': '192.168.1.1'}, '208.67.222.222', 'opendns_default'),   # taken from the modem
    ({'upstream': '195.175.39.39'}, '195.175.39.39', 'kept'),             # a public server stays
    ({'upstream': '192.168.1.1', 'upstream_source': 'operator'}, '192.168.1.1', 'operator'),
])
def test_reload_moves_a_modem_upstream_to_opendns_once(monkeypatch, policy, upstream, source):
    from satsuma import configuration_reload, dnsmasq_control, network_modes, protected_storage, app_firewall
    monkeypatch.setattr(dnsmasq_control, 'refresh', lambda store: None)
    monkeypatch.setattr(network_modes.NetworkModes, 'apply', lambda self, table, enabled: None)
    monkeypatch.setattr(app_firewall, 'policy', lambda: {})
    monkeypatch.setattr(protected_storage.RootDataStore, 'replace', lambda self, data: None)
    values = {'dns_policy': dict(policy)}

    class Core:
        def get(self, key, default=None): return values.get(key, default)
        def set(self, key, value): values[key] = value
    configuration_reload.apply_features(Core(), {'hagezi_enabled': False})
    assert values['dns_policy']['upstream'] == upstream
    assert values['dns_policy']['upstream_source'] == source


def test_both_opendns_servers_count_as_satsumas_resolvers():
    result = dns_resolver_alignment({'upstream': '208.67.222.222'}, [], 'nameserver 208.67.220.220\n')
    assert result['state'] == 'ALIGNED'
