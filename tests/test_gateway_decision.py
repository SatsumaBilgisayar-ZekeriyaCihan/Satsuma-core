"""Shared MITM decision (owner's decision 2026-11-11): pin the approved modem, write back routes, DNS and proxy.

Ortak MITM kararı: onaylı modem sabitlenir; rota, DNS ve proxy geri yazılır.
"""
import pytest

from satsuma import gateway_decision as gd

APPROVED = {'gateway': '192.168.1.1', 'mac': 'aa-bb-cc-dd-ee-ff', 'interface': 12}
DNS = ('208.67.222.222', '208.67.220.220')


def obs(**extra):
    base = {'gateways': [{'ip': '192.168.1.1', 'interface': 12}],
            'neighbours': {'192.168.1.1': 'AA:BB:CC:DD:EE:FF'}, 'pinned': {'192.168.1.1': True},
            'dns': list(DNS), 'proxies': []}
    base.update(extra)
    return base


def test_a_clean_network_needs_nothing():
    assert gd.decide(APPROVED, obs(), DNS) == ([], [])


def test_another_mac_for_the_gateway_is_arp_spoofing_and_the_mac_is_pinned_back():
    findings, actions = gd.decide(APPROVED, obs(neighbours={'192.168.1.1': '11-22-33-44-55-66'}), DNS)
    assert findings[0]['kind'] == 'arp_spoofing' and findings[0]['severity'] == 'critical'
    assert actions == [{'action': 'pin_gateway_mac', 'gateway': '192.168.1.1', 'mac': 'aa-bb-cc-dd-ee-ff',
                        'interface': 12}]


def test_an_unpinned_gateway_is_pinned_without_a_finding():
    assert gd.decide(APPROVED, obs(pinned={}), DNS) == ([], [
        {'action': 'pin_gateway_mac', 'gateway': '192.168.1.1', 'mac': 'aa-bb-cc-dd-ee-ff', 'interface': 12}])


def test_an_extra_or_replaced_default_gateway_is_removed_and_restored():
    findings, actions = gd.decide(APPROVED, obs(gateways=[{'ip': '192.168.1.66', 'interface': 12}]), DNS)
    assert [f['kind'] for f in findings] == ['default_gateway_added', 'approved_gateway_missing']
    assert [a['action'] for a in actions] == ['remove_default_route', 'restore_default_route']


def test_changed_dns_and_a_proxy_are_written_back():
    findings, actions = gd.decide(APPROVED, obs(dns=['1.2.3.4'] + list(DNS), proxies=['http=10.0.0.5:8080']), DNS)
    assert [f['kind'] for f in findings] == ['dns_server_changed', 'proxy_set']
    assert [a['action'] for a in actions] == ['lock_dns', 'remove_proxy']


def test_the_modem_is_approved_only_from_one_visible_gateway():
    assert gd.approve(obs()) == APPROVED
    with pytest.raises(ValueError):
        gd.approve(obs(gateways=[]))
    with pytest.raises(ValueError):
        gd.approve(obs(gateways=[{'ip': '192.168.1.1'}, {'ip': '10.0.0.1'}]))
    with pytest.raises(ValueError):
        gd.approve(obs(neighbours={'192.168.1.1': 'ff-ff-ff-ff-ff-ff'}))
