"""2.2.44: dnsmasq in its own network namespace, never on loopback (owner, 2026-11-13).

dnsmasq kendi ağ ad alanında; loopback hiç kullanılmaz. Ana makinenin ağı
değiştirilmez: komutlar sahte çalıştırıcıyla kaydedilir.
"""
import configparser
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from installer import dns_setup, network_modes_setup
from satsuma import application_control, dns_netns, network_control
from satsuma.network_modes import DNS_TABLE, LAN_TABLE, dns_script

ROOT = Path(__file__).parents[1]


class Store:
    def __init__(self, **state):
        self.state = dict(state)

    def get(self, key, default=None):
        return self.state.get(key, default)

    def set(self, key, value):
        self.state[key] = value


class Runner:
    def __init__(self, netns='[]', link_missing=True, forward='0'):
        self.calls, self.inputs = [], []
        self.netns, self.link_missing, self.forward = netns, link_missing, forward

    def __call__(self, args, **kwargs):
        self.calls.append(list(args))
        if 'input' in kwargs:
            self.inputs.append(kwargs['input'])
        out, code = '', 0
        if args[:3] == [dns_netns.IP, '-j', 'netns']:
            out = self.netns
        elif args[:3] == [dns_netns.IP, 'link', 'show']:
            code = 1 if self.link_missing else 0
        elif args[:2] == [dns_netns.SYSCTL, '-n']:
            out = self.forward + '\n'
        elif args[:3] == [dns_netns.NFT, '-j', 'list']:
            out = '{"nftables": []}'
        return SimpleNamespace(returncode=code, stdout=out, stderr='')


def test_setup_builds_namespace_veth_and_listens_only_on_the_link_address(tmp_path, monkeypatch):
    monkeypatch.setattr(dns_netns, 'FORWARD_SAVE', str(tmp_path / 'forward'))
    monkeypatch.setattr(dns_netns, 'FIREWALL_CMD', str(tmp_path / 'no-firewall-cmd'))
    runner = Runner()
    result = dns_netns.setup(runner)
    assert result['listen'] == '169.254.53.2:53' and set(result['created']) == {'netns', 'veth'}
    flat = [' '.join(c) for c in runner.calls]
    assert any('netns add satsuma-dns' in c for c in flat)
    assert any('veth peer name satsuma-dns1' in c for c in flat)
    assert any('addr replace 169.254.53.1/30 dev satsuma-dns0' in c for c in flat)
    assert any('netns exec satsuma-dns /usr/sbin/ip addr replace 169.254.53.2/30 dev satsuma-dns1' in c for c in flat)
    assert any('route replace default via 169.254.53.1' in c for c in flat)
    assert not any('127.0.0.1' in c or '53053' in c for c in flat)
    assert (tmp_path / 'forward').read_text() == '0'
    nat = runner.inputs[-1]
    assert 'masquerade' in nat and 'policy drop' in nat and 'th dport 53 accept' in nat
    assert '853' not in nat and '208.67.222.222' in nat


def test_setup_is_idempotent_and_teardown_restores_forwarding(tmp_path, monkeypatch):
    monkeypatch.setattr(dns_netns, 'FORWARD_SAVE', str(tmp_path / 'forward'))
    monkeypatch.setattr(dns_netns, 'FIREWALL_CMD', str(tmp_path / 'no-firewall-cmd'))
    runner = Runner(netns=json.dumps([{'name': 'satsuma-dns'}]), link_missing=False)
    assert dns_netns.setup(runner)['created'] == []
    assert not any(c[:3] == [dns_netns.IP, 'netns', 'add'] for c in runner.calls)
    down = Runner(netns=json.dumps([{'name': 'satsuma-dns'}]))
    assert dns_netns.teardown(down)['ip_forward_restored'] == '0'
    assert [dns_netns.SYSCTL, '-q', '-w', 'net.ipv4.ip_forward=0'] in down.calls
    assert not (tmp_path / 'forward').exists()


def test_dns_lock_redirects_everything_but_loopback_to_the_filter():
    script = dns_script()
    assert 'ip daddr 127.0.0.0/8 return' in script
    assert script.count('dnat ip to 169.254.53.2') == 2 and '53053' not in script


def test_forward_chain_only_carries_the_filter_and_always_through_suricata():
    text = network_control.render_ruleset(ports={'tcp': (53, 443), 'udp': (53,)})
    forward = text.split('chain forward', 1)[1]
    assert 'accept' not in forward
    for line in forward.splitlines():
        if 'satsuma-dns0' in line:
            assert line.rstrip().endswith('queue num 100') and ('dport 53' in line or 'sport 53' in line)
            assert '{ 208.67.220.220, 208.67.222.222 }' in line
    assert 'ct state established ct direction reply ip saddr' in forward
    assert (ROOT / 'packaging/root/etc/satsuma-core/nftables.nft').read_text() == network_control.render_ruleset(
        ports={'tcp': (53, 443), 'udp': (53,)})


def test_application_control_keeps_the_namespace_dns_when_it_drops_forwarding():
    text = application_control.render([], enabled=True)
    forward = text.split('chain forward', 1)[1]
    assert forward.index('satsuma-dns0') < forward.index('counter drop')
    assert all('dport 53' in l or 'sport 53' in l for l in forward.splitlines() if 'satsuma-dns0' in l)


def test_units_bind_dnsmasq_to_the_namespace():
    dns = (ROOT / 'systemd/satsuma-core-dns.service').read_text()
    assert 'NetworkNamespacePath=/run/netns/satsuma-dns' in dns and 'BindsTo=satsuma-dns-netns.service' in dns
    assert 'CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n' in dns and 'AmbientCapabilities=CAP_NET_BIND_SERVICE\n' in dns
    assert 'User=satsuma-dns' in dns and 'NoNewPrivileges=yes' in dns
    netns = (ROOT / 'systemd/satsuma-dns-netns.service').read_text()
    assert 'Before=satsuma-core-dns.service' in netns and 'satsuma.dns_netns setup' in netns
    # A private mount namespace would hide /run/netns/satsuma-dns from dnsmasq.
    for option in ('PrivateTmp', 'ProtectSystem', 'ProtectHome', 'PrivateMounts', 'ReadOnlyPaths'):
        assert option + '=' not in netns
    nm = configparser.ConfigParser()
    nm.read(ROOT / 'packaging/root/usr/lib/NetworkManager/conf.d/90-satsuma-dns.conf')
    assert 'satsuma-dns0' in nm['keyfile']['unmanaged-devices+']


def test_network_modes_bring_up_the_filter_before_the_lock():
    order = []

    class Modes:
        def apply(self, table, enabled):
            order.append((table, enabled))
            return {'ok': True, 'enabled': enabled}
    store = Store(dns_policy={'enabled': True, 'upstream': '208.67.222.222'})
    network_modes_setup.configure(store, Modes(), probe=lambda: {'system_ready': True, 'resolver': '127.0.0.53'},
                                  dns_filter=lambda s: order.append('filter'))
    assert order == [(LAN_TABLE, False), 'filter', (DNS_TABLE, True)]
    health = store.state['dns_filter_health']
    assert health['status'] == 'ACTIVE' and health['ok'] and '169.254.53.2' in health['filter']


def test_a_dead_filter_gets_no_new_redirect():
    applied = []

    class Modes:
        def apply(self, table, enabled):
            applied.append((table, enabled))
            return {'ok': True}
    store = Store(dns_policy={'enabled': True, 'upstream': '208.67.222.222'})
    def dead(s):
        raise RuntimeError('dnsmasq DNS readiness failed')
    with pytest.raises(RuntimeError):
        network_modes_setup.configure(store, Modes(), dns_filter=dead)
    assert (DNS_TABLE, True) not in applied and (DNS_TABLE, False) not in applied
    assert store.state['dns_filter_health']['status'] == 'FAILED'


def test_system_dnsmasq_is_masked_and_its_files_kept_as_evidence(tmp_path):
    etc = tmp_path / 'etc'
    (etc / 'dnsmasq.d').mkdir(parents=True)
    (etc / 'dnsmasq.conf').write_text('interface=eth0\n')
    (etc / 'dnsmasq.d' / 'local.conf').write_text('address=/x/1.2.3.4\n')
    (etc / 'NetworkManager' / 'conf.d').mkdir(parents=True)
    (etc / 'NetworkManager' / 'conf.d' / 'dns.conf').write_text('[main]\ndns=dnsmasq\n')
    (etc / 'NetworkManager' / 'conf.d' / 'other.conf').write_text('[main]\nplugins=keyfile\n')
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        if args[1:] == ['is-enabled', 'dnsmasq.service']:
            return SimpleNamespace(returncode=0, stdout='enabled\n', stderr='')
        return SimpleNamespace(returncode=0, stdout='', stderr='')
    report = dns_setup.retire_system_dnsmasq(runner, etc, tmp_path / 'evidence', now=0)
    assert ['/usr/bin/systemctl', 'mask', 'dnsmasq.service'] in calls
    assert ['/usr/bin/nmcli', 'general', 'reload'] in calls
    moved = {Path(m['from']).name for m in report['moved']}
    assert moved == {'dnsmasq.conf', 'local.conf', 'dns.conf'}
    assert all(Path(m['to']).read_text() for m in report['moved'])      # kept, not deleted
    assert (etc / 'NetworkManager' / 'conf.d' / 'other.conf').exists()


def test_inactive_system_dnsmasq_is_left_alone(tmp_path):
    etc = tmp_path / 'etc'; etc.mkdir()
    (etc / 'dnsmasq.conf').write_text('# default\n')
    def runner(args, **kwargs):
        return SimpleNamespace(returncode=3 if 'is-active' in args else 1, stdout='disabled\n', stderr='')
    report = dns_setup.retire_system_dnsmasq(runner, etc, tmp_path / 'evidence')
    assert report['service'] is None and report['moved'] == [] and (etc / 'dnsmasq.conf').exists()


def test_operator_cannot_point_the_filter_outside_opendns(tmp_path):
    source = (ROOT / 'satsuma/operator_service.py').read_text()
    assert "DNS filtresi yalnızca OpenDNS" in source and 'if str(resolver) not in OPENDNS:' in source


def test_user_list_is_fetched_only_on_request_and_kept_signed(tmp_path, monkeypatch):
    from satsuma import custom_dns_lists as lists
    kept = []
    store = Store()
    store.add = lambda *a: None
    result = lists.change(store, 'https://lists.example/block.txt', 'update', lambda: {'status': 'configured'},
                          fetcher=lambda url: b'bad.example\n', keep=(lambda i, n: kept.append((i, n)), lambda i: None))
    assert result['ok'] and kept and kept[0][1] == ['bad.example']
    directory = tmp_path / 'custom'
    monkeypatch.setattr('installer.integrity.read_key', lambda: b'k' * 32)
    signed = []
    monkeypatch.setattr('installer.integrity.sign', lambda path, key: signed.append(path))
    path = Path(lists.keep_copy('abc', ['bad.example'], directory))
    assert path.read_text() == 'bad.example\n' and (path.stat().st_mode & 0o777) == 0o444 and signed == [path]
    lists.drop_copy('abc', directory)
    assert not path.exists()
