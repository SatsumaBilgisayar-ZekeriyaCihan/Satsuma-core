"""2.2.9 full protection: the product turns every function on by itself.

2.2.9 tam koruma: ürün bütün işlevleri kendiliğinden açar.
"""
from satsuma import full_protection
from satsuma.config import validate
from satsuma.policy import DEFAULT_DESTRUCTIVE, DEFAULT_OTX


def test_an_old_all_off_configuration_is_switched_on():
    old = {**validate({}), 'response_enabled': False, 'destructive_response_enabled': False,
           'destructive_allowed_actions': [], 'auto_action_network_enabled': False,
           'otx_enabled': False, 'otx_blocker_mode': False, 'sudo_autoblock_enabled': False}
    on = full_protection.apply(old)
    for key in full_protection.FULL_PROTECTION:
        assert on[key] is True, key
    assert {'network_isolate', 'process_kill', 'file_quarantine', 'user_disable'} <= set(on['destructive_allowed_actions'])


def test_defaults_are_on():
    assert DEFAULT_OTX['enabled'] and DEFAULT_OTX['blocker_mode']
    assert DEFAULT_DESTRUCTIVE['enabled'] and DEFAULT_DESTRUCTIVE['sudo_autoblock_enabled']
    assert validate({})['auto_action_network_enabled'] is True


def test_installer_no_longer_forces_responses_off():
    text = open('installer/configure.py', encoding='utf-8').read()
    assert "['enabled']=False" not in text and "'response_enabled':False" not in text


def test_gateway_dns_and_loopback_are_never_blocked_automatically():
    protected = {'192.168.1.1', '208.67.222.222'}
    assert full_protection.protected_reason('127.0.0.1', protected) == 'protected_target'
    assert full_protection.protected_reason('192.168.1.1', protected) == 'protected_gateway_or_dns'
    assert full_protection.protected_reason('208.67.222.222', protected) == 'protected_gateway_or_dns'
    assert full_protection.protected_reason('192.168.1.50', protected) is None
    assert full_protection.protected_reason('45.33.32.10', protected) is None


def test_gateway_and_resolvers_are_read_from_the_system(tmp_path):
    route = tmp_path / 'route'
    route.write_text('Iface\tDestination\tGateway\tFlags\n'
                     'eth0\t00000000\t0101A8C0\t0003\n'
                     'eth0\t0001A8C0\t00000000\t0001\n')
    assert full_protection._gateways(str(route), str(tmp_path / 'none')) == {'192.168.1.1'}
    resolv = tmp_path / 'resolv.conf'
    resolv.write_text('# comment\nnameserver 208.67.222.222\nnameserver fe80::1%eth0\nsearch lan\n')
    assert full_protection._resolvers((str(resolv),)) == {'208.67.222.222', 'fe80::1'}
