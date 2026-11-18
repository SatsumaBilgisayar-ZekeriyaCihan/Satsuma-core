"""2.2.9: IPv6 is switched off in the kernel, the firewall and DNS.

2.2.9: IPv6 çekirdekte, güvenlik duvarında ve DNS'te kapatılır.
"""
import pytest
from pathlib import Path

from satsuma import ipv6_off, network_control


def test_every_interface_gets_disable_ipv6(tmp_path):
    conf = tmp_path / 'net' / 'ipv6' / 'conf'
    for name in ('all', 'default', 'lo', 'enp3s0', 'wlp2s0'):
        (conf / name).mkdir(parents=True)
        (conf / name / 'disable_ipv6').write_text('0\n')
    assert ipv6_off.status(tmp_path) == {'ipv6_off': False, 'enabled_on': ['all', 'default', 'enp3s0', 'lo', 'wlp2s0']}
    result = ipv6_off.apply(tmp_path)
    assert result['ok'] and set(result['disabled']) == {'all', 'default', 'lo', 'enp3s0', 'wlp2s0'}
    assert ipv6_off.status(tmp_path) == {'ipv6_off': True, 'enabled_on': []}


def test_kernel_without_ipv6_is_already_off(tmp_path):
    assert ipv6_off.apply(tmp_path)['ipv6'] == 'absent_in_kernel'


def test_first_rule_of_every_chain_drops_ipv6():
    for chain in ('input', 'output', 'forward'):
        assert network_control.expected_rules(chain)[0] == [
            {'match': {'op': '==', 'left': {'meta': {'key': 'nfproto'}}, 'right': 'ipv6'}}, {'counter': {}}, {'drop': None}]
    text = network_control.render_ruleset()
    for block in text.split(' chain ')[1:]:
        assert block.splitlines()[1] == '  meta nfproto ipv6 counter drop'
    assert Path('packaging/root/etc/satsuma-core/nftables.nft').read_text() == text


def test_sysctl_file_service_and_dns_follow():
    sysctl = Path('packaging/root/usr/lib/sysctl.d/91-satsuma-ipv6.conf').read_text()
    for name in ipv6_off.NAMES:
        assert f'net.ipv6.conf.{name}.disable_ipv6 = 1' in sysctl
    assert '/usr/lib/sysctl.d/91-satsuma-ipv6.conf' in Path('packaging/satsuma-core.spec').read_text()
    assert 'boot_setup.py --ipv6-off' in Path('systemd/satsuma-memory-hardening.service').read_text()
    dns = Path('satsuma/dnsmasq_control.py').read_text()
    # 2.2.44: IPv4 only, in the filter's own namespace (satsuma.dns_netns).
    assert "listen-address=' + DNS_ADDR" in dns and '::1' not in dns.split('listen-address=')[1].split('\\n')[0]
    from satsuma.dns_netns import DNS_ADDR
    assert DNS_ADDR == '169.254.53.2'


def test_nftables_service_loads_satsuma_without_ever_flushing():
    dropin = Path('packaging/root/usr/lib/systemd/system/nftables.service.d/90-satsuma.conf').read_text()
    lines = [line for line in dropin.splitlines() if line and not line.startswith('#')]
    assert 'ExecStop=' in lines and not any(l.startswith('ExecStop=') and l != 'ExecStop=' for l in lines)
    assert 'flush' not in ''.join(lines)
    starts = [l for l in lines if l.startswith(('ExecStart=/', 'ExecReload=/'))]
    assert len(starts) == 2 and all('list table inet satsuma_core' in l and '-f /etc/satsuma-core/nftables.nft' in l for l in starts)
    spec = Path('packaging/satsuma-core.spec').read_text()
    assert '/usr/lib/systemd/system/nftables.service.d/90-satsuma.conf' in spec
    assert 'systemctl enable nftables.service' in spec


def test_hand_edited_ruleset_is_set_aside_and_rewritten_not_loaded(tmp_path):
    import json
    from types import SimpleNamespace as NS
    from network_fixture import table_json
    ruleset = tmp_path / 'nftables.nft'
    ruleset.write_text('table inet satsuma_core { chain input { type filter hook input priority 0; policy accept; } }\n')
    scripts = []
    def runner(args, **kw):
        if args[1:] == ['-j', 'list', 'tables']:
            return NS(returncode=0, stdout=json.dumps({'nftables': []}), stderr='')
        if args[1:3] == ['-j', 'list']:
            return NS(returncode=0, stdout=table_json(), stderr='')
        scripts.append(kw.get('input'))
        return NS(returncode=0, stdout='', stderr='')
    assert network_control.setup(runner=runner, ruleset_path=ruleset)['status'] == 'ready'
    assert ruleset.read_text() == network_control.render_ruleset()
    kept = list(tmp_path.glob('nftables.nft.elle-degistirilmis-*'))
    assert len(kept) == 1 and 'policy accept' in kept[0].read_text()
    assert scripts and all(s == network_control.render_ruleset() for s in scripts)


def test_loopback_is_closed_except_replies_and_listed_local_services():
    text = network_control.render_ruleset()
    for chain, iface in (('input', 'iifname'), ('output', 'oifname')):
        block = text.split(f' chain {chain} ', 1)[1].split('\n }', 1)[0].splitlines()
        assert block[1:6] == ['  meta nfproto ipv6 counter drop',
                              f'  {iface} "lo" ct state established,related accept',
                              f'  {iface} "lo" tcp dport {{ 53, 5939 }} accept',
                              f'  {iface} "lo" udp dport 53 accept',
                              f'  {iface} "lo" counter drop']
    assert '"lo" accept' not in text


def test_an_earlier_satsuma_layout_is_migrated_not_refused(tmp_path):
    import json
    from types import SimpleNamespace as NS
    from network_fixture import table_json
    old = json.loads(table_json())
    for entry in old['nftables']:
        rule = entry.get('rule')
        if rule and rule['chain'] == 'input' and any('meta' in str(e) and "'lo'" in str(e) for e in rule['expr']):
            rule['expr'] = [{'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'lo'}}, {'accept': None}]
    ruleset = tmp_path / 'nftables.nft'
    ruleset.write_text(network_control.render_ruleset())
    scripts = []
    def runner(args, **kw):
        if args[1:] == ['-j', 'list', 'tables']:
            return NS(returncode=0, stdout=json.dumps({'nftables': [{'table': {'family': 'inet', 'name': 'satsuma_core'}}]}), stderr='')
        if args[1:3] == ['-j', 'list']:
            data = old if not scripts else json.loads(table_json())
            return NS(returncode=0, stdout=json.dumps(data), stderr='')
        scripts.append(kw.get('input'))
        return NS(returncode=0, stdout='', stderr='')
    assert network_control.setup(runner=runner, ruleset_path=ruleset)['status'] == 'ready'
    assert scripts and 'delete chain inet satsuma_core input' in scripts[-1]
    foreign = {'nftables': [{'table': {'family': 'inet', 'name': 'satsuma_core', 'comment': 'someone else'}}]}
    def foreign_runner(args, **kw):
        if args[1:] == ['-j', 'list', 'tables']:
            return NS(returncode=0, stdout=json.dumps(foreign), stderr='')
        return NS(returncode=0, stdout=json.dumps(foreign), stderr='')
    with pytest.raises(RuntimeError, match='foreign'):
        network_control.setup(runner=foreign_runner, ruleset_path=ruleset)
