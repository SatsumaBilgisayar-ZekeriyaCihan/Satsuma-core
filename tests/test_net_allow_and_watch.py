"""2.2.50: allowed address ranges, and the watch that puts removed firewall tables back.

Owner, 2026-11-19: "Opera VPN is blocked as soon as I open it; let me allow a
range", and, after removing every Satsuma table by hand, "doesn't our guard
put it back?" — it did not: the one-shot services still looked healthy.
"""
import ipaddress
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from satsuma import firewall_watch as watch, net_allow
from satsuma.store import Store

sys.path.insert(0, str(Path(__file__).parents[1] / 'integrations'))


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / 'data', test=True)
    yield value
    value.close()


# -- allowed ranges

def test_parse_accepts_v4_and_v6_ranges_and_refuses_too_wide():
    assert str(net_allow.parse('77.111.244.9/22')) == '77.111.244.0/22'
    assert str(net_allow.parse('203.0.113.7')) == '203.0.113.7/32'
    assert str(net_allow.parse('2001:db8::/32')) == '2001:db8::/32'
    for bad, words in (('', 'yazın'), ('0.0.0.0/4', 'çok geniş'), ('2001::/8', 'çok geniş'), ('abc', 'Geçerli'),
                       ('224.0.0.0/8', 'izin verilemez')):
        with pytest.raises(ValueError, match=words):
            net_allow.parse(bad)


def test_allowed_covers_addresses_and_ranges(store):
    store.set('operator_allow_ips', ['198.51.100.9'])
    assert net_allow.add(store, '77.111.244.0/22', 'Opera VPN', 1000)['status'] == 'allowed'
    assert net_allow.add(store, '77.111.244.0/22', '', 1000)['status'] == 'already_allowed'
    assert net_allow.allowed(store, '77.111.247.200') == '77.111.244.0/22'
    assert net_allow.allowed(store, '198.51.100.9') == '198.51.100.9'
    assert net_allow.allowed(store, '77.111.248.1') is None and net_allow.allowed(store, 'x') is None
    assert net_allow.remove(store, '77.111.244.0/22', 1000)['status'] == 'removed'
    assert net_allow.allowed(store, '77.111.247.200') is None


def test_central_block_path_skips_an_allowed_range(store):
    from satsuma import network_control
    net_allow.add(store, '77.111.244.0/22', 'Opera VPN', 1000)
    worker = SimpleNamespace(store=store, _guard=lambda *a: None, _protected_ip=lambda *a: None, config={})
    result = network_control.block(worker, '77.111.245.3', 'no_ptr_connection_flood')
    assert result == {'status': 'operator_allowlisted', 'ip': '77.111.245.3', 'allowed_by': '77.111.244.0/22'}


def test_a_manual_block_may_not_contradict_an_allowed_range(store):
    from satsuma import net_blocks
    net_allow.add(store, '77.111.244.0/22', '', 1000)
    with pytest.raises(ValueError, match='izin verilen aralıkla çakışıyor: 77.111.244.0/22'):
        net_blocks.add(store, '77.111.0.0/16', '', 1000, runner=lambda *a, **k: None, gateways=[], addresses=[])


def test_blocked_addresses_inside_a_new_range_are_found():
    blocked = [{'ip': '77.111.245.3'}, {'ip': '203.0.113.1'}, 'bad']
    assert net_allow.blocked_inside(blocked, ipaddress.ip_network('77.111.244.0/22')) == ['77.111.245.3']


def test_guard_rules_respect_an_allowed_range(store, tmp_path):
    import satsuma_guard
    guard = satsuma_guard.Guard.__new__(satsuma_guard.Guard)
    guard.core_store = store
    net_allow.add(store, '77.111.244.0/22', 'Opera VPN', 1000)
    assert guard.operator_allowed('77.111.246.1') == '77.111.244.0/22'
    written = []
    guard.write = lambda event, **fields: written.append((event, fields))
    outcome = guard.block('77.111.246.1', 'no_ptr_connection_flood')
    assert outcome['status'] == 'operator_allowlisted' and written[0][1]['allowed_by'] == '77.111.244.0/22'
    # A block made before the range was allowed is lifted on the next poll.
    import sqlite3
    guard.db = sqlite3.connect(':memory:')
    guard.db.execute('CREATE TABLE blocks(ip TEXT PRIMARY KEY, ts TEXT, reason TEXT)')
    guard.db.execute("INSERT INTO blocks VALUES('77.111.244.20','t','no_ptr_connection_flood'),('203.0.113.5','t','otx')")
    lifted = []
    guard.nft = SimpleNamespace(contains=lambda ip: True, unblock=lifted.append)
    assert guard.release_allowed() == ['77.111.244.20'] and lifted == ['77.111.244.20']
    assert [r[0] for r in guard.db.execute('SELECT ip FROM blocks')] == ['203.0.113.5']


def test_operator_asks_the_password_again_to_allow_a_range():
    from satsuma.operator_service import weakens
    assert weakens('allow_network', {'network': '77.111.244.0/22'})
    assert not weakens('unallow_network', {'network': '77.111.244.0/22'})


# -- firewall table watch

class System:
    """nft tables and systemd units, in memory."""
    def __init__(self, tables, active, rebuild=True):
        self.tables, self.active, self.rebuild, self.calls = set(tables), set(active), rebuild, []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if args[:4] == [watch.NFT, '-j', 'list', 'tables']:
            rows = [{'table': {'family': 'inet', 'name': n}} for n in sorted(self.tables)]
            return subprocess.CompletedProcess(args, 0, json.dumps({'nftables': rows}), '')
        if args[1:3] == ['is-active', '--quiet']:
            return subprocess.CompletedProcess(args, 0 if args[3] in self.active else 3, '', '')
        if args[1] == 'restart':
            if self.rebuild:
                for group, (owner, owned, units) in watch.GROUPS.items():
                    if units[0] in args[2:]:
                        self.tables.update(owned)
            return subprocess.CompletedProcess(args, 0, '', '')
        raise AssertionError(args)


ALL = {'satsuma_core', 'satsuma_netblock', 'satsuma_dns_ns', 'satsuma_otx_guard', 'firewalld'}
RUNNING = {'satsuma-network.service', 'satsuma-dns-netns.service', 'satsuma-suricata-otx-guard.service'}


def test_nothing_happens_when_every_table_is_there(tmp_path):
    system, records = System(ALL, RUNNING), []
    report = watch.check(runner=system, record=records.append, state=tmp_path / 'w.json')
    assert report['missing'] == {} and records == [] and not any(c[1] == 'restart' for c in system.calls)


def test_the_field_case_is_repaired_and_recorded(tmp_path):
    # 2026-11-19: only "table inet firewalld" was left.
    system, records = System({'firewalld'}, RUNNING), []
    report = watch.check(runner=system, record=records.append, state=tmp_path / 'w.json')
    assert set(report['missing']) == {'network', 'dns', 'guard'}
    assert [r['status'] for r in report['repaired']] == ['restored'] * 3
    assert ['restart', 'satsuma-dns-netns.service', 'satsuma-core-dns.service'] in [c[1:] for c in system.calls]
    assert system.tables == ALL
    assert {r['action'] for r in records} == {'firewall.restore'} and records[0]['missing_tables'] == ['satsuma_core', 'satsuma_netblock']


def test_a_service_stopped_on_purpose_is_left_alone(tmp_path):
    system = System({'firewalld', 'satsuma_core', 'satsuma_netblock'}, {'satsuma-network.service'})
    report = watch.check(runner=system, state=tmp_path / 'w.json')
    assert report['missing'] == {} and not any(c[1] == 'restart' for c in system.calls)


def test_three_repairs_in_thirty_minutes_then_only_reports(tmp_path):
    state, clock = tmp_path / 'w.json', [1000.0]
    system = System({'firewalld'}, {'satsuma-dns-netns.service'}, rebuild=False)
    statuses = []
    for _ in range(5):
        system.tables = {'firewalld'}
        report = watch.check(runner=system, record=lambda r: statuses.append(r['status']), state=state, clock=lambda: clock[0])
        clock[0] += 60
    assert statuses == ['restore_failed'] * 3 + ['budget_exhausted'] * 2
    clock[0] += watch.WINDOW
    watch.check(runner=system, record=lambda r: statuses.append(r['status']), state=state, clock=lambda: clock[0])
    assert statuses[-1] == 'restore_failed'
    assert oct(state.stat().st_mode & 0o777) == '0o600'


def test_units_are_packaged_and_enabled():
    root = Path(__file__).parents[1]
    assert 'OnUnitActiveSec=1min' in (root / 'systemd/satsuma-firewall-watch.timer').read_text()
    assert '-m satsuma.firewall_watch' in (root / 'systemd/satsuma-firewall-watch.service').read_text()
    spec = (root / 'packaging/satsuma-core.spec').read_text()
    assert spec.count('satsuma-firewall-watch') >= 7
    enable = next(line for line in spec.splitlines() if line.startswith(' systemctl enable ') and 'dns-refresh.timer' in line)
    assert 'satsuma-firewall-watch.timer' in enable


def test_restore_and_allow_read_as_sentences():
    from satsuma.record_catalog import render
    line = render('actions', {'action': 'firewall.restore', 'status': 'restored', 'missing_tables': ['satsuma_dns_ns'],
                              'units': ['satsuma-dns-netns.service']}, 1.0)
    assert line['text'] == 'Güvenlik duvarı tablosu silinmişti: satsuma_dns_ns' and line['chip'] == 'Geri kuruldu'
    allow = render('actions', {'action': 'network_range_allow', 'network': '77.111.244.0/22', 'reason': 'Opera VPN'}, 1.0)
    assert allow['text'] == 'Aralığa izin verildi: 77.111.244.0/22'
