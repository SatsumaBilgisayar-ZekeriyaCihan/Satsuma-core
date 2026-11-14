"""Windows network protection, tested with fake PowerShell and a fake connection table.

Windows ağ koruması; sahte PowerShell ve sahte bağlantı tablosuyla sınanır.
"""
import json
from types import SimpleNamespace

import pytest

from satsuma_win import connections, dns, firewall, inbound, protect
from satsuma_win.guard import Guard
from satsuma_win.peers import PeerRule
from satsuma_win.subnet import SubnetRule
from satsuma.peer_watch import NO_PTR, PTR, UNKNOWN


class PowerShell:
    """Answers by what the script asks for; records every script."""
    def __init__(self, enabled=True, servers=dns.SERVERS, resolves=True, fail=False, inbound_state=None):
        self.scripts, self.enabled, self.servers, self.resolves, self.fail = [], enabled, servers, resolves, fail
        self.inbound_state = inbound_state or locked_state()

    def __call__(self, argv, **kwargs):
        if argv[0] == 'icacls':
            self.icacls = argv
            return SimpleNamespace(returncode=5 if self.fail else 0, stdout='', stderr='Access is denied.')
        assert argv[:-1] == firewall.POWERSHELL and 'shell' not in kwargs
        script = argv[-1]
        self.scripts.append(script)
        if self.fail:
            return SimpleNamespace(returncode=1, stdout='', stderr='Access is denied.')
        if 'Get-NetFirewallProfile' in script:
            if 'Set-NetFirewallProfile' in script:
                self.inbound_state = locked_state()
            out = self.inbound_state
        elif 'Get-NetRoute' in script:
            out = {'gateways': ['192.168.1.1'], 'dns': ['208.67.222.222', 'not-an-ip']}
        elif 'Set-DnsClientServerAddress' in script:
            out = {'interfaces': [{'index': 12, 'servers': list(self.servers)}], 'resolves': self.resolves}
        else:
            names = [part.split("'")[1] for part in script.split("-Name ")[1:] if "'" in part]
            out = [{'Name': n, 'Enabled': self.enabled, 'Action': 'Block'} for n in dict.fromkeys(names)]
        return SimpleNamespace(returncode=0, stdout=json.dumps(out), stderr='')


def locked_state():
    return {'profiles': [{'name': n, 'enabled': 'True', 'inbound': 'Block', 'rules': 'False'}
                         for n in ('Domain', 'Private', 'Public')],
            'services': [{'name': n, 'status': 'Stopped', 'start': 'Disabled'} for n in inbound.SERVICES],
            'registry': [{'path': p, 'name': n, 'value': v} for p, n, v in inbound.REGISTRY],
            'smb1': 'False', 'terminal': ['Windows.Terminal.Azure']}


# -- firewall ------------------------------------------------------------------

@pytest.mark.parametrize('bad', ["1.2.3.4'; Remove-Item C:\\ -Recurse #", 'example.com', '127.0.0.1', '0.0.0.0', '224.0.0.1'])
def test_nothing_but_a_valid_public_address_reaches_powershell(bad):
    with pytest.raises(ValueError):
        firewall.block_script(bad, 'x')


def test_block_is_confirmed_only_when_both_rules_read_back_enabled():
    ps = PowerShell()
    result = firewall.block_ip('203.0.113.7', "rule'; evil", ps)
    assert result['status'] == 'blocked' and result['rules'] == sorted(firewall.rule_names('203.0.113.7'))
    script = ps.scripts[0]
    assert '-Direction Outbound' in script and '-Direction Inbound' in script and 'evil' in script
    assert "'; evil" not in script                      # the reason is reduced to a safe tag
    with pytest.raises(firewall.FirewallError):
        firewall.block_ip('203.0.113.7', 'x', PowerShell(enabled=False))
    with pytest.raises(firewall.FirewallError):
        firewall.block_ip('203.0.113.7', 'x', PowerShell(fail=True))


def test_ipv6_rule_names_have_no_colons():
    out_name, in_name = firewall.rule_names('2001:db8::7')
    assert ':' not in out_name + in_name


def test_port_853_is_closed_for_tcp_and_udp():
    ps = PowerShell()
    assert firewall.close_port_853(ps)['status'] == 'closed'
    assert '-Protocol TCP -RemotePort 853' in ps.scripts[0] and '-Protocol UDP -RemotePort 853' in ps.scripts[0]
    assert '-Direction Outbound -Action Block' in ps.scripts[0]
    with pytest.raises(firewall.FirewallError):
        firewall.close_port_853(PowerShell(enabled=False))


# -- DNS lock ------------------------------------------------------------------

def test_dns_lock_is_verified_by_readback_and_resolution():
    assert dns.lock(PowerShell())['status'] == 'LOCKED'
    assert dns.lock(PowerShell(servers=('192.168.1.1',)))['status'] == 'SERVERS_NOT_SET'
    assert dns.lock(PowerShell(resolves=False))['status'] == 'RESOLUTION_FAILED'
    assert dns.SERVERS == ('208.67.222.222', '208.67.220.220')


# -- protected addresses ---------------------------------------------------------

def test_gateway_dns_and_remote_support_are_protected():
    infra = protect.infrastructure(PowerShell())
    assert infra == {'192.168.1.1', '208.67.222.222'}
    support = protect.support_peers([{'remote': '198.51.100.9', 'process': 'TeamViewer.exe'},
                                     {'remote': '198.51.100.10', 'process': 'chrome.exe'}])
    assert support == {'198.51.100.9'}
    assert protect.protected_reason('192.168.1.1', infra, support) == 'gateway_or_dns'
    assert protect.protected_reason('198.51.100.9', infra, support) == 'remote_support'
    assert protect.protected_reason('169.254.1.1', infra, support) == 'protected_address'
    assert protect.protected_reason('198.51.100.10', infra, support) is None


# -- connection table ---------------------------------------------------------------

def test_connection_table_keeps_public_peers_with_their_program():
    addr = lambda ip, port: SimpleNamespace(ip=ip, port=port)
    socks = [SimpleNamespace(raddr=addr('93.184.216.34', 443), laddr=addr('192.168.1.3', 50000), type=1,
                             status='ESTABLISHED', pid=10),
             SimpleNamespace(raddr=addr('192.168.1.1', 53), laddr=addr('192.168.1.3', 50001), type=2,
                             status='NONE', pid=11),
             SimpleNamespace(raddr=addr('93.184.216.35', 443), laddr=addr('192.168.1.3', 50002), type=1,
                             status='TIME_WAIT', pid=10),
             SimpleNamespace(raddr=(), laddr=addr('0.0.0.0', 445), type=1, status='LISTEN', pid=4)]
    fake = SimpleNamespace(net_connections=lambda kind: socks, SOCK_STREAM=1,
                           Process=lambda pid: SimpleNamespace(name=lambda: {10: 'firefox.exe', 11: 'svchost.exe'}[pid]))
    rows = connections.read(fake)
    assert [(r['remote'], r['process'], r['protocol']) for r in rows] == [('93.184.216.34', 'firefox.exe', 'tcp')]


# -- the no-PTR rule ------------------------------------------------------------------

class Resolver:
    def __init__(self, answer):
        self.answer, self.cache = answer, {}
    def lookup(self, ip):
        self.cache[ip] = (self.answer, 0)
        return self.answer


def flood(n, ip='203.0.113.50'):
    return [{'remote': ip, 'remote_port': 443, 'local': '192.168.1.3', 'local_port': 50000 + i,
             'protocol': 'tcp', 'pid': 7, 'process': 'x.exe'} for i in range(n)]


def test_no_ptr_peer_is_blocked_at_its_sixth_connection_not_before():
    rule = PeerRule(lambda ip: None, resolver=Resolver(NO_PTR), clock=lambda: 100.0)
    assert rule.poll(flood(5)) == []
    decision = rule.poll(flood(6))
    assert [(d['ip'], d['connections_in_visit'], d['threshold']) for d in decision] == [('203.0.113.50', 6, 5)]


@pytest.mark.parametrize('answer', [PTR, UNKNOWN])
def test_a_peer_with_ptr_or_an_unreadable_dns_answer_is_not_blocked(answer):
    rule = PeerRule(lambda ip: None, resolver=Resolver(answer), clock=lambda: 100.0)
    assert rule.poll(flood(20)) == []


def test_a_protected_peer_is_never_decided():
    rule = PeerRule(lambda ip: 'gateway_or_dns', resolver=Resolver(NO_PTR), clock=lambda: 100.0)
    assert rule.poll(flood(20)) == []


# -- the subnet limit ------------------------------------------------------------------

def peers(n, prefix='203.0.113.'):
    return [{'remote': prefix + str(i), 'remote_port': 443, 'local': '192.168.1.3', 'local_port': 40000 + i,
             'protocol': 'tcp', 'pid': 9, 'process': 'x.exe'} for i in range(1, n + 1)]


def test_ten_distinct_peers_in_one_slash24_are_blocked_nine_are_not():
    assert SubnetRule(lambda ip: None, clock=lambda: 1.0).poll(peers(9)) == []
    decisions = SubnetRule(lambda ip: None, clock=lambda: 1.0).poll(peers(10))
    assert len(decisions) == 10 and {d['subnet'] for d in decisions} == {'203.0.113.0/24'}


def test_subnet_limit_never_below_ten_and_protected_addresses_stay_open():
    with pytest.raises(ValueError):
        SubnetRule(lambda ip: None, threshold=9)
    decisions = SubnetRule(lambda ip: 'remote_support' if ip.endswith('.1') else None, clock=lambda: 1.0).poll(peers(10))
    assert '203.0.113.1' not in {d['ip'] for d in decisions} and len(decisions) == 9


# -- the guard ----------------------------------------------------------------------------

def test_guard_closes_853_locks_dns_blocks_and_records(tmp_path):
    ps = PowerShell()
    guard = Guard(runner=ps, read=lambda: peers(10), clock=lambda: 50.0, directory=tmp_path, echo=lambda *_: None,
                  peer_rule=PeerRule(lambda ip: None, resolver=Resolver(PTR)))
    startup = guard.start()
    assert startup['port_853']['ok'] and startup['dns_lock']['ok']
    events = guard.poll()
    assert sum(e['kind'] == 'blocked' for e in events) == 10 and guard.counts['blocked'] == 10
    lines = (tmp_path / 'events.jsonl').read_text().splitlines()
    kinds = [json.loads(line)['kind'] for line in lines]
    assert kinds[:10] == ['startup_state_dir_lock', 'startup_machine_key', 'startup_port_853', 'startup_dns_lock',
                          'startup_inbound_lock', 'startup_accounts', 'startup_gateway', 'startup_memory',
                          'startup_sysmon', 'startup_ram_signatures']
    assert len(lines) == 20 and kinds.count('blocked') == 10
    assert startup['ram_signatures'] == {'ok': True, 'status': 'STARTED', 'enforce': True}
    assert startup['gateway']['status'] == 'APPROVED_AT_INSTALL'
    assert startup['machine_key']['status'] == 'CREATED' and len(startup['machine_key']['fingerprint']) == 16
    assert startup['state_dir_lock']['ok'] and ps.icacls[2:] == [
        '/inheritance:r', '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F']
    assert startup['inbound_lock']['ok']
    assert json.loads((tmp_path / 'state.json').read_text())['counts']['blocked'] == 10


def test_guard_records_a_failed_block_and_a_failed_startup(tmp_path):
    guard = Guard(runner=PowerShell(fail=True), read=lambda: peers(10), clock=lambda: 50.0, directory=tmp_path,
                  echo=lambda *_: None, peer_rule=PeerRule(lambda ip: None, resolver=Resolver(PTR)))
    startup = guard.start()
    assert not startup['port_853']['ok'] and not startup['dns_lock']['ok'] and not startup['inbound_lock']['ok']
    assert startup['state_dir_lock'] == {'ok': False, 'status': 'OPEN', 'error': 'Access is denied.'}
    events = guard.poll()
    assert {e['kind'] for e in events} == {'block_failed'} and guard.counts['block_failed'] == 10


# -- no incoming connections ------------------------------------------------------------

def test_a_fully_locked_machine_has_nothing_open():
    assert inbound.evaluate(locked_state()) == []
    result = inbound.lock(PowerShell())
    assert result == {'ok': True, 'status': 'LOCKED', 'open': []}


def test_each_open_door_is_named():
    state = locked_state()
    state['profiles'][2].update(enabled='False', inbound='Allow', rules='True')
    state['services'][0].update(status='Running', start='Automatic')
    state['registry'][0]['value'] = 0
    state['smb1'] = 'True'
    problems = inbound.evaluate(state)
    assert len(problems) == 6
    assert any('Public' in p and 'kapalı' in p for p in problems)
    assert any('TermService' in p for p in problems) and 'SMB1 açık' in problems
    assert inbound.evaluate({}) == ['güvenlik duvarı profilleri okunamadı', 'Windows Terminal Azure Cloud Shell profili açık']


def test_lock_script_blocks_inbound_and_disables_remote_services():
    script = inbound.apply_script()
    assert '-DefaultInboundAction Block -AllowInboundRules False' in script
    for name in ('TermService', 'WinRM', 'LanmanServer', 'RemoteRegistry'):
        assert f"Set-Service -Name '{name}' -StartupType Disabled" in script
    assert 'EnableSMB1Protocol $false' in script and 'fDenyTSConnections' in script


def test_guard_writes_back_a_reopened_door_and_records_it(tmp_path):
    clock = [0.0]
    opened = locked_state()
    opened['profiles'][1]['inbound'] = 'Allow'
    ps = PowerShell()
    guard = Guard(runner=ps, read=lambda: [], clock=lambda: clock[0], directory=tmp_path, echo=lambda *_: None,
                  peer_rule=PeerRule(lambda ip: None, resolver=Resolver(PTR)))
    guard.start()
    ps.inbound_state = opened
    clock[0] = 61.0
    guard.poll()
    event = [json.loads(l) for l in (tmp_path / 'events.jsonl').read_text().splitlines()][-1]
    assert event['kind'] == 'inbound_changed' and event['restored'] is True
    assert any('Private' in p for p in event['open']) and guard.counts['inbound_restored'] == 1


def test_azure_cloud_shell_profile_is_disabled_by_machine_policy():
    script = inbound.apply_script()
    assert 'DisabledProfileSources' in script and 'Windows.Terminal.Azure' in script and 'MultiString' in script
    state = locked_state()
    state['terminal'] = None
    assert inbound.evaluate(state) == ['Windows Terminal Azure Cloud Shell profili açık']
