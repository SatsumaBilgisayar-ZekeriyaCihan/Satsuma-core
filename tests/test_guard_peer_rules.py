"""Guard wiring of the fixed rules: no-PTR flood block, alert verification gate.

Bekçide değişmez kuralların bağlanması: PTR'siz sel engeli, uyarı doğrulama kapısı.
"""
import importlib.util
import json
import os
from pathlib import Path
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location(
    'peer_rules_guard', Path(__file__).resolve().parents[1] / 'integrations/satsuma_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

ATTACKER = '45.33.32.10'


def service(verdict=None, block_status='set_membership_confirmed'):
    svc = object.__new__(guard.Guard)
    svc.cfg = {**guard.DEFAULT, 'fast_block': True, 'otx_enabled': False}
    svc.own_ips = {'192.168.1.10'}
    svc.egress_eligible = lambda src, dst: src in svc.own_ips
    svc.eligible = lambda *a: True
    svc.flow_checker = svc.reply_checker = lambda *a: True
    svc.write = Mock()
    svc.block = Mock(return_value={'status': block_status})
    svc.otx_check = Mock(return_value=False)
    svc.core_store = None
    svc.watch_logged = {}
    if verdict is not None:
        svc.alert_verifier = lambda alert: {'verdict': verdict, 'dns_backed': True,
                                            'dns_domains': ['example.org'],
                                            'processes': [{'pid': 7, 'exe': '/usr/bin/x', 'parent_exe': '/usr/bin/bash'}]}
    return svc


def alert():
    return {'source_ip': '192.168.1.10', 'dest_ip': ATTACKER, 'priority': 1, 'rule_id': '1:2000001:1',
            'signature': 'ET MALWARE test', 'source_port': 40000, 'dest_port': 443, 'protocol': 'TCP'}


def test_alert_backed_by_a_live_process_blocks_and_carries_the_evidence():
    svc = service('verified_live_process')
    svc.on_alert(alert())
    svc.block.assert_called_once()
    verification = svc.block.call_args.kwargs['verification']
    assert verification['verdict'] == 'verified_live_process'
    assert verification['processes'][0]['exe'] == '/usr/bin/x' and verification['dns_domains'] == ['example.org']


def test_forged_looking_alert_never_blocks_and_never_asks_otx():
    for verdict in ('unverified_possible_forgery', 'flow_without_live_process'):
        svc = service(verdict)
        svc.cfg['otx_enabled'] = True
        svc.on_alert(alert())
        svc.block.assert_not_called()
        svc.otx_check.assert_not_called()
        last = svc.write.call_args
        assert last.args[0] == 'would_block' and last.kwargs['reason'] == 'alert_not_backed_by_live_process'
        assert last.kwargs['verification']['verdict'] == verdict


def test_forwarded_lan_flows_keep_the_conntrack_check_only():
    svc = service('unverified_possible_forgery')
    svc.egress_eligible = lambda src, dst: False
    svc.own_ips = set()
    forwarded = {**alert(), 'source_ip': ATTACKER, 'dest_ip': '192.168.1.50'}
    svc.on_alert(forwarded)
    svc.block.assert_called_once()


def test_no_ptr_flood_decision_blocks_then_destroys_only_its_connections():
    svc = service()
    decision = {'ip': '203.0.113.9', 'rule': 'no_ptr_connection_flood', 'ptr': 'NO_PTR', 'threshold': 5,
                'connections_in_visit': 6, 'connections': [('10.0.0.2', 40000, 443), ('10.0.0.2', 40001, 443)],
                'processes': [{'pid': 7, 'exe': '/usr/bin/x', 'parent_exe': '/usr/bin/bash'}],
                'memory_verification': [{'pid': 7, 'live': True}]}
    svc.peers = Mock(poll=Mock(return_value=[decision]), watchlist=Mock(return_value={'203.0.113.9': 6}))
    with patch('satsuma.connection_kill.kill_connection',
               return_value={'terminated': True, 'verified': True}) as kill:
        svc.check_peers()
    assert svc.block.call_args.args[:2] == ('203.0.113.9', 'no_ptr_connection_flood')
    assert svc.block.call_args.kwargs['processes'][0]['exe'] == '/usr/bin/x'
    assert [c.args[:4] for c in kill.call_args_list] == [('10.0.0.2', 40000, '203.0.113.9', 443),
                                                         ('10.0.0.2', 40001, '203.0.113.9', 443)]


def test_connections_are_not_destroyed_when_the_block_was_refused():
    for status in ('operator_allowlisted', 'integrity_observe_only', 'observe_only'):
        svc = service(block_status=status)
        decision = {'ip': '203.0.113.9', 'rule': 'r', 'ptr': 'NO_PTR', 'threshold': 5, 'connections_in_visit': 6,
                    'connections': [('10.0.0.2', 40000, 443)], 'processes': [], 'memory_verification': []}
        svc.peers = Mock(poll=Mock(return_value=[decision]), watchlist=Mock(return_value={}))
        with patch('satsuma.connection_kill.kill_connection') as kill:
            svc.check_peers()
        kill.assert_not_called()


def test_watchlist_is_published_for_the_dashboard_when_it_changes():
    svc = service()
    svc.core_store = Mock()
    svc.peers = Mock(poll=Mock(return_value=[]), watchlist=Mock(return_value={'203.0.113.9': 3}))
    svc.check_peers()
    svc.check_peers()  # unchanged: published once
    svc.core_store.set.assert_called_once()
    key, value = svc.core_store.set.call_args.args
    assert key == 'ptr_watchlist' and value['peers'] == {'203.0.113.9': 3} and value['threshold'] == 5


def test_peer_poll_setting_validates(tmp_path):
    path = tmp_path / 'guard.json'
    for bad in (0, 61, 'x'):
        path.write_text(json.dumps({'peer_poll_seconds': bad}))
        os.chmod(path, 0o600)
        try:
            guard.get_config(str(path))
        except (ValueError, PermissionError):
            continue
        raise AssertionError(bad)
