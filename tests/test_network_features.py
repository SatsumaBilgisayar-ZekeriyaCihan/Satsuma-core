import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import pytest
from satsuma.presentation import fields, priority_key
from satsuma.subnet_protection import connection_counts, evaluate
from satsuma.network_modes import NetworkModes, LAN_TABLE, DNS_TABLE, lan_script, dns_script
from satsuma.dnsmasq_control import render
from satsuma.domain_lists import domain, parse, update
from satsuma.store import Store
from satsuma import otx


def test_priority_before_recency_and_process_attribution():
    rows = [{'severity': 'low', 'timestamp': 300}, {'severity': 'critical', 'classification': 'indicator', 'timestamp': 100},
            {'severity': 'high', 'timestamp': 500}, {'severity': 'critical', 'classification': 'confirmed', 'timestamp': 50}]
    assert [r['timestamp'] for r in sorted(rows, key=priority_key)] == [50, 100, 500, 300]
    view = fields({'timestamp': '2026-10-16T01:00:00Z', 'event': {'process': {'name': 'nginx', 'pid': 42}}})
    assert view['process_name'] == 'nginx' and view['pid'] == '42'
    assert view['time_label'] != 'Bilinmiyor'
    assert fields({})['pid'] == '—'   # 2.2.53: no process is not "unknown"
    assert fields({'timestamp': float('nan')})['time_label'] == 'Bilinmiyor'


def _hex4(ip, port):
    return ''.join(f'{int(part):02X}' for part in reversed(ip.split('.'))) + f':{port:04X}'


def _proc_net(tmp_path, tcp=(), udp=()):
    head = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n'
    def rows(items):
        return ''.join(f'  {i}: {_hex4(l[0], l[1])} {_hex4(r[0], r[1])} {st} 00000000:00000000 00:00000000 '
                       f'00000000     0        0 {1000 + i} 1 0\n' for i, (l, r, st) in enumerate(items))
    net = tmp_path / 'net'
    net.mkdir()
    (net / 'tcp').write_text(head + rows(tcp))
    (net / 'udp').write_text(head + rows(udp))
    return str(tmp_path)


def test_connection_counts_come_from_proc_net_established_only(tmp_path):
    me = ('192.168.1.10', 50000)
    proc = _proc_net(
        tmp_path,
        tcp=[(me, ('8.8.8.8', 443), '01'), ((me[0], 50001), ('8.8.8.8', 443), '01'),
             ((me[0], 50002), ('8.8.4.4', 443), '01'),
             ((me[0], 50003), ('8.8.8.8', 443), '06'),      # TIME_WAIT: not connected
             ((me[0], 80), ('0.0.0.0', 0), '0A'),            # LISTEN
             ((me[0], 50004), ('127.0.0.1', 631), '01')],    # loopback is never a peer
        udp=[((me[0], 50005), ('1.1.1.1', 53), '01')])
    assert connection_counts(proc) == {'8.8.8.8': 2, '8.8.4.4': 1, '1.1.1.1': 1}


def test_connection_counts_survive_missing_tables(tmp_path):
    assert connection_counts(str(tmp_path)) == {}


def test_subnet_counting_never_runs_ss(tmp_path):
    import subprocess
    with patch.object(subprocess, 'run', side_effect=AssertionError('ss must not be used')):
        assert connection_counts(_proc_net(tmp_path)) == {}


def test_subnet_threshold_counts_distinct_ips_and_respects_policy(tmp_path):
    store=Store(tmp_path/'data',test=True); calls=[]
    fake=SimpleNamespace(block_ip=lambda ip,reason:calls.append(ip) or {'status':'set_membership_confirmed'})
    boot=lambda:{'response_unlocked':True}
    try:
        assert evaluate(store,{'192.168.1.1':100},{},fake,boot_provider=boot)==[]
        nine={f'192.168.1.{n}':20 for n in range(1,10)}
        assert evaluate(store,nine,{},fake,boot_provider=boot)==[]
        ten={**nine,'192.168.1.10':1}
        out=evaluate(store,ten,{},fake,now=100,boot_provider=boot)
        assert len(out)==10 and len(calls)==10
        assert all(x['ip_count']==10 and x['subnet']=='192.168.1.0/24' for x in out)
        assert evaluate(store,ten,{},fake,now=101,boot_provider=boot)==[]
        other={f'192.168.2.{n}':1 for n in range(1,10)}
        assert evaluate(store,other,{},fake,boot_provider=boot)==[]
        store.set('subnet_protection_policy',{'enabled':False,'threshold':10})
        assert evaluate(store,ten,{},fake,boot_provider=boot)==[]
    finally: store.close()


class Firewall:
    def __init__(self, owned=True):
        self.tables = set()
        self.owned = owned
        self.scripts = []
    def __call__(self, args, **kwargs):
        if args[1:4] == ['-j', 'list', 'tables']:
            data = {'nftables': [{'table': {'family': 'inet', 'name': name}} for name in self.tables]}
        elif args[1:4] == ['-j', 'list', 'table']:
            data = {'nftables': [{'table': {'name': args[-1], 'comment': 'Satsuma Core managed' if self.owned else 'Other app'}}]}
        else:
            script = kwargs['input']; self.scripts.append(script)
            for name in (LAN_TABLE, DNS_TABLE):
                if 'delete table inet '+name in script: self.tables.discard(name)
                if 'table inet '+name+' {' in script: self.tables.add(name)
            data = {}
        return SimpleNamespace(returncode=0, stdout=json.dumps(data), stderr='')


def test_lan_toggle_only_changes_owned_table_and_preserves_dns(tmp_path):
    store = Store(tmp_path / 'data', test=True)
    nft = Firewall()
    try:
        modes = NetworkModes(store, nft)
        assert modes.apply(LAN_TABLE, True)['enabled']
        assert modes.apply(LAN_TABLE, False)['enabled'] is False
        assert 'flush ruleset' not in '\n'.join(nft.scripts)
        script = lan_script()
        assert script.index('udp dport 53 accept') < script.index('ip saddr 10.0.0.0/8 counter drop')
        assert '0.0.0.0/0' not in script and '::/0' not in script
        nft.tables.add(LAN_TABLE); nft.owned = False
        with pytest.raises(RuntimeError, match='ownership'):
            modes.apply(LAN_TABLE, False)
        # 2.2.44: the lock sends DNS to the filter in its own namespace, never to loopback.
        script = dns_script()
        assert 'dnat ip to 169.254.53.2' in script and 'ip daddr 127.0.0.0/8 return' in script
        assert '53053' not in script and 'redirect' not in script and '208.67' not in script
        assert 'dnat ip to 169.254.53.2' in dns_script('208.67.220.220')
        for bad in ('192.168.1.1', '127.0.0.1', '::1', '0.0.0.0'):
            with pytest.raises(ValueError):
                dns_script(bad)
    finally:
        store.close()


@pytest.mark.parametrize('name', ['bad/name.com', 'evil.com/#', 'evil.com\nserver=attacker', 'bad..com', '*', 'example.com;other'])
def test_dnsmasq_config_rejects_injection(name):
    with pytest.raises(ValueError):
        render({'upstream': '1.1.1.1'}, [name], [])


def test_dnsmasq_keeps_unblocked_names_on_upstream_and_allows_exceptions():
    config = render({'upstream': '1.1.1.1'}, ['bad.example', 'safe.bad.example'], ['safe.bad.example'])
    lines = config.splitlines()
    assert 'address=/bad.example/#' in lines and 'local=/bad.example/' in lines
    assert 'server=/example.com/1.1.1.1' in lines and 'server=/safe.bad.example/1.1.1.1' in lines  # probe name always forwarded
    assert 'address=/safe.bad.example/#' not in lines
    # 2.2.63: encrypted-DNS servers are blocked and Firefox's canary answers NXDOMAIN.
    assert 'address=/doh.opendns.com/#' in lines and 'address=/dns.google/#' in lines
    assert 'address=/use-application-dns.net/' in lines
    assert parse('# metadata\nBAD.EXAMPLE\nbad.example\ninternal.local\n') == ['bad.example']


def test_dns_readiness_retries_while_ultimate_list_is_loading():
    from satsuma.dnsmasq_control import probe
    with patch('satsuma.dnsmasq_control._probe_once', side_effect=[ConnectionRefusedError('loading'), None]) as attempt, patch('time.sleep'):
        probe()
        assert attempt.call_count == 2


def test_dns_readiness_never_succeeds_without_a_valid_reply():
    from satsuma.dnsmasq_control import probe
    with patch('satsuma.dnsmasq_control._probe_once', side_effect=ConnectionRefusedError('not listening')):
        with pytest.raises(RuntimeError, match='no new redirect applied'):
            probe(timeout=0)


def test_list_update_downloads_nothing_and_keeps_existing_data(tmp_path):
    # 2.2.38 (owner, 2026-11-13): no domain list is downloaded any more.
    store = Store(tmp_path/'data', test=True); target = tmp_path/'list.txt'; target.write_text('existing.example\n')
    def opener(*a, **kw): raise AssertionError('nothing may be downloaded')
    try:
        info = update(store, path=target, opener=opener)
        assert info['status'] == 'retired_in_2.2.38' and target.read_text() == 'existing.example\n'
    finally: store.close()


def test_otx_domain_reputation_is_cached_and_tls_is_required(tmp_path):
    import time
    store = Store(tmp_path/'data', test=True)
    store.add('dns', {'query': 'bad.example'})
    cfg = {'api_key': 'test-fixture-only', 'cache_ttl_seconds': 3600, 'max_queries_per_cycle': 12}
    data = {'pulse_info': {'count': 11, 'pulses': [{'modified': time.time()}]}}
    try:
        with patch.object(otx, 'request_indicator', return_value=(data, {'verified': True})) as query, patch('satsuma.dnsmasq_control.refresh'):
            otx.run_domains(store, cfg, {'otx_pulse_threshold': 11, 'otx_recent_pulse_days': 14})
            assert 'bad.example' in store.get('dns_blocked_domains')
            otx.run_domains(store, cfg, {'otx_pulse_threshold': 11, 'otx_recent_pulse_days': 14})
            assert query.call_count == 1
        assert not otx._should_block({'pulse_count': 99, 'latest_pulse_age_days': 0, 'tls': {}}, {'require_tls': True, 'pulse_threshold': 11, 'recent_pulse_days': 14})[0]
    finally: store.close()



def test_k3_otx_blocker_mode_never_blocks_on_one_verified_pulse(tmp_path, monkeypatch):
    store = Store(tmp_path/'data', test=True)
    calls = []
    fake = SimpleNamespace(block_ip=lambda ip, reason, **kw: calls.append(ip) or {'status': 'set_membership_confirmed'})
    monkeypatch.setattr(otx, 'load_config', lambda: {'api_key': 'fixture-key', 'cache_ttl_seconds': 3600,
                                                    'max_queries_per_cycle': 5})
    monkeypatch.setattr(otx, 'load_with_policy', lambda: ({
        'otx_enabled': True, 'otx_blocker_mode': True, 'otx_pulse_threshold': 11,
        'otx_match_mode': 'threshold', 'otx_require_tls': True,
        'otx_recent_pulse_days': 14, 'expected_dns_servers': [],
    }, None, None))
    monkeypatch.setattr(otx, 'request_ipv4', lambda ip, key: (
        {'pulse_info': {'count': 1, 'pulses': []}, 'reputation': 0},
        {'verified': True, 'version': 'TLSv1.3', 'cipher': 'fixture', 'host': 'otx.alienvault.com'}))
    monkeypatch.setattr(otx, 'run_domains', lambda *_: None)
    from satsuma import early_guard
    monkeypatch.setattr(early_guard, 'read_verdict', lambda: {'response_unlocked': True})
    try:
        records = otx.run_once(store=store, response=fake, candidates=['45.33.32.10'])
        assert calls == []
        assert records[0]['decision'] == 'observe'
        assert records[0]['block_reason'] == 'below_pulse_threshold'
        assert records[0]['classification'] == 'indicator'
    finally:
        store.close()


def test_network_management_is_session_and_uid_bound(tmp_path):
    from satsuma.operator_service import OperatorController
    class Auth:
        def login(self, password, client): return {'ok': True, 'token': 'test-session'}
        def validate_session(self, token): return token == 'test-session'
    store = Store(tmp_path/'data', test=True)
    controller = OperatorController(store, auth=Auth(), boot_provider=lambda: {'response_unlocked': True})
    try:
        for method in ('lan_access', 'dns_filter', 'subnet_protection', 'hagezi_update'):
            with pytest.raises(PermissionError):
                controller.dispatch(1000, method, {'enabled': True})
        controller.dispatch(1000, 'login', {'password': 'test-only'})
        with pytest.raises(PermissionError):
            controller.dispatch(1001, 'subnet_protection', {'token': 'test-session', 'enabled': True})
        result = controller.dispatch(1000, 'subnet_protection', {'token': 'test-session', 'enabled': True})
        assert result['ok'] and store.get('subnet_protection_policy')['threshold'] == 10
    finally: store.close()


def test_private_peer_is_counted_and_only_explicit_count_policy_can_block_it(tmp_path):
    from satsuma.response import ResponseWorker
    from network_fixture import table_json
    store = Store(tmp_path/'data', test=True)
    commands = []
    def run(args):
        commands.append(args)
        return {'returncode':0, 'stdout':table_json() if '-j' in args else ''}
    try:
        worker = ResponseWorker(store, {'response_enabled':True}, runner=run)
        with patch('satsuma.full_protection.protected_local_targets', lambda: {'192.168.1.1'}):
            assert worker.block_ip('192.168.1.1','generic')['status']=='protected_gateway_or_dns'
        worker.config['subnet_limit_authorized']=True
        def incoming(worker,ip,*args):
            commands.append(['incoming_original_only',ip])
            return {'status':'set_membership_confirmed'}
        with patch('satsuma.incoming_response.block',side_effect=incoming):
            result=evaluate(store,{f'192.168.1.{n}':1 for n in range(20,30)}, {}, response=worker, boot_provider=lambda:{'response_unlocked':True})
        assert result[0]['status']=='set_membership_confirmed'
        assert any('192.168.1.20' in command for command in commands)
        assert worker.block_ip('127.0.0.1','count limit')['status']=='protected_target'
    finally: store.close()


def test_key_setup_enables_queries_blocker_and_worker_without_logging_secret(tmp_path,monkeypatch):
    store=Store(tmp_path/'data', test=True); saved=[]; commands=[]
    monkeypatch.setattr(otx,'save_key',saved.append)
    try:
        result=otx.configure_key('fixture-secret',store=store,runner=lambda args,**kw:commands.append(args) or SimpleNamespace(returncode=0))
        assert result['enabled'] and result['blocker_mode'] and result['service_started']
        assert store.get('operator_otx_policy')=={'enabled':True,'blocker_mode':True,'match_mode':'threshold'}
        assert saved==['fixture-secret']
        assert commands[-1]==['/usr/bin/systemctl','restart','satsuma-core-otx.service']
        assert 'fixture-secret' not in str(store.db.execute('SELECT body FROM records').fetchall())
    finally: store.close()


def test_hot_add_from_a_service_without_kill_rights_goes_through_systemd():
    """2.2.63 (field 2026-11-20): core-otx could not signal dnsmasq ("could not re-read the added names")."""
    from types import SimpleNamespace
    from satsuma.dnsmasq_control import reload_hosts
    calls = []

    def runner(cmd, **kw):
        calls.append(cmd)
        return SimpleNamespace(returncode=0, stdout='1932\n', stderr='')

    def denied(*a):
        raise PermissionError('no CAP_SYS_PTRACE')
    assert reload_hosts(runner, kill=lambda *a: None, readlink=denied)
    assert calls[-1] == ['/usr/bin/systemctl', 'reload', 'satsuma-core-dns.service']
