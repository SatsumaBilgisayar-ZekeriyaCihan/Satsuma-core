import copy
import pytest
from satsuma.network_identity import check_loopback,differences
from satsuma.loopback_guard import render,tokens

@pytest.mark.parametrize('failure',['none','type','flags','address'])
def test_loopback_identity_rejects_wrong_type_state_or_nonlocal_address(failure):
    link={'ifname':'lo','link_type':'loopback','flags':['UP','LOOPBACK'],'ifindex':1}
    address={'addr_info':[{'family':'inet','local':'127.0.0.1'},{'family':'inet6','local':'::1'}]}
    if failure=='type': link['link_type']='ether'
    if failure=='flags': link['flags']=['UP']
    if failure=='address': address['addr_info'].append({'family':'inet','local':'8.8.8.8'})
    if failure=='none': assert check_loopback([link],[address])['status']=='checked'
    else:
        with pytest.raises(RuntimeError): check_loopback([link],[address])

@pytest.mark.parametrize('field',['interface','mac','gateway','gateway_mac'])
def test_recorded_interface_or_gateway_changes_are_not_auto_adopted(field):
    policy={'gateways':[{'interface':'eth0','mac':'02:00:00:00:00:01','gateway':'192.168.1.1','gateway_mac':'02:00:00:00:00:02'}]}
    observed=copy.deepcopy(policy)
    assert differences(policy,observed)==[]
    observed['gateways'][0][field]+='changed'
    assert differences(policy,observed)

def test_loopback_guard_has_no_unconditional_loopback_allow_and_checks_spoofing():
    text=render()
    assert 'iifname "lo" accept' not in text
    assert 'oifname "lo" accept' not in text
    assert 'fib saddr type local fib daddr type local accept' in text
    assert 'iifname != "lo" ip saddr 127.0.0.0/8 counter drop' in text
    assert 'ct status dnat ct original proto-dst 53 accept' in text
    assert tokens(text.replace('counter drop','counter packets 17 bytes 1000 drop'))==tokens(text)


def test_numeric_kernel_enums_are_exact_not_weakened():
    text=render()
    numeric=text.replace('type local','type 2').replace('ct status dnat','ct status 0x20')
    assert tokens(text)==tokens(numeric)
    assert tokens(text)!=tokens(numeric.replace('type 2','type 1'))
    assert tokens(text)!=tokens(numeric.replace('ct status 0x20','ct status 0x8'))


def test_identity_cannot_write_routes_neighbors_or_auto_enroll(monkeypatch):
    from satsuma import network_identity as n
    called=[]
    monkeypatch.setattr(n,'command',lambda args:called.append(args) or '[]')
    for args in [('neigh','replace','192.168.1.1','lladdr','aa:bb:cc:dd:ee:ff'),('route','replace','default','via','192.168.1.2')]:
        with pytest.raises(PermissionError):n.ip(*args)
    with pytest.raises(PermissionError):n.pin_neighbors({})
    with pytest.raises(PermissionError):n.restrict(True)
    with pytest.raises(PermissionError):n.save({})
    assert called==[]
    from pathlib import Path
    service=(Path(__file__).parents[1]/'systemd/satsuma-network-identity.service').read_text()
    assert 'CapabilityBoundingSet=\n' in service
    assert 'CAP_NET_ADMIN' not in service and 'CAP_NET_RAW' not in service
    assert 'RestrictAddressFamilies=AF_UNIX AF_NETLINK' in service
