"""A verified Suricata attack alert ends the connection and stops the local program behind it.

Only a program that started the connection itself, only top-priority alerts,
and only through the authorization gate. The kill worker is replaced; the gate,
the exemptions and the evidence store are real.

Doğrulanmış bir Suricata saldırı uyarısı bağlantıyı bitirir ve arkasındaki yerel
programı durdurur. Yalnızca bağlantıyı kendi başlatan program, yalnızca en yüksek
öncelikli uyarılar ve yalnızca yetkilendirme kapısından geçerek. Öldürme işçisi
taklit edilir; kapı, muafiyetler ve kanıt deposu gerçektir.
"""
import importlib.util
import subprocess
import time
from pathlib import Path
from unittest.mock import Mock

import pytest

from satsuma import alert_verify, enforcement, peer_watch
from satsuma.process_identity import capture_process_identity
from satsuma.store import Store

spec = importlib.util.spec_from_file_location(
    'process_stop_guard', Path(__file__).resolve().parents[1] / 'integrations/satsuma_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

CONFIG = dict(response_enabled=True, destructive_response_enabled=True,
              destructive_allowed_actions=['process_kill'], auto_action_process_enabled=True)


class FakeResponse:
    def __init__(self):
        self.calls = []

    def terminate_process(self, pid, reason, evidence=None, context=None):
        self.calls.append({'pid': pid, 'reason': reason, 'evidence': evidence, 'context': context})
        return {'status': 'terminated', 'signal_sent': True, 'exit_verified': True}


@pytest.fixture
def env(tmp_path):
    store = Store(tmp_path / 'data', test=True)
    child = subprocess.Popen(['sleep', '60'])
    time.sleep(0.2)
    identity = capture_process_identity(child.pid)
    svc = object.__new__(guard.Guard)
    svc.cfg = {**guard.DEFAULT, 'mode': 'block'}
    svc.core_store = store
    svc.own_ips = {'192.168.1.10'}
    svc.write = Mock()
    svc.process_config = lambda: dict(CONFIG)
    yield svc, child, identity, store
    child.kill()
    child.wait(timeout=5)
    store.close()


def alert(priority=1):
    return {'source_ip': '192.168.1.10', 'dest_ip': '203.0.113.9', 'source_port': 40000, 'dest_port': 443,
            'priority': priority, 'signature': 'ET MALWARE test', 'rule_id': '1:2000001:1', 'detection_id': 'abc'}


def verification(identity, **over):
    base = {'verdict': 'verified_live_process', 'initiated_locally': True, 'local_port': 40000,
            'processes': [{'pid': identity['pid'], 'exe': identity['exe'], 'starttime': identity['starttime'],
                           'parent_exe': '/usr/bin/bash'}]}
    return {**base, **over}


def test_a_verified_top_priority_alert_stops_the_program_that_started_the_flow(env):
    svc, child, identity, store = env
    fake = FakeResponse()
    outcome = svc.stop_process(alert(), verification(identity), process_response=fake)
    assert outcome['status'] == 'terminated'
    assert len(fake.calls) == 1 and fake.calls[0]['pid'] == child.pid
    assert fake.calls[0]['evidence']['starttime'] == identity['starttime']
    event = svc.write.call_args
    assert event.args[0] == 'process_stop' and event.kwargs['exit_verified'] is True
    assert event.kwargs['pid'] == child.pid and event.kwargs['detection_id'] == 'abc'


@pytest.mark.parametrize('case', ['priority_two', 'served_not_started', 'two_holders', 'no_live_process',
                                  'observe_mode', 'switched_off', 'no_start_time'])
def test_every_missing_condition_leaves_the_program_alone(env, case):
    svc, child, identity, store = env
    fake, event, proof = FakeResponse(), alert(), verification(identity)
    if case == 'priority_two':
        event = alert(2)
    elif case == 'served_not_started':
        proof = verification(identity, initiated_locally=False)
    elif case == 'two_holders':
        proof = verification(identity, processes=proof['processes'] * 2)
    elif case == 'no_live_process':
        proof = verification(identity, verdict='flow_without_live_process')
    elif case == 'observe_mode':
        svc.cfg['mode'] = 'observe'
    elif case == 'switched_off':
        svc.cfg['process_stop_max_priority'] = 0
    elif case == 'no_start_time':
        proof['processes'][0]['starttime'] = None
    assert svc.stop_process(event, proof, process_response=fake) is None
    assert fake.calls == [] and child.poll() is None


def test_the_limit_can_be_raised_to_priority_two(env):
    svc, child, identity, store = env
    svc.cfg['process_stop_max_priority'] = 2
    fake = FakeResponse()
    assert svc.stop_process(alert(2), verification(identity), process_response=fake)['status'] == 'terminated'


def test_protected_programs_are_never_stopped_even_with_perfect_evidence(env, monkeypatch):
    svc, child, identity, store = env
    monkeypatch.setattr(enforcement, 'exempt', lambda pid, exe, finding=None: 'protected_program:teamviewer')
    fake = FakeResponse()
    outcome = svc.stop_process(alert(), verification(identity), process_response=fake)
    assert outcome['status'] == 'exempt' and fake.calls == []


INSTALLED = dict(response_enabled=False, destructive_response_enabled=False, destructive_allowed_actions=[],
                 auto_action_process_enabled=False)   # policy.json as installed


def test_the_authorization_gate_still_applies(env):
    svc, child, identity, store = env
    svc.process_config = lambda: dict(INSTALLED)
    enforcement.set_policy(store, False)          # the operator switched blocking off
    fake = FakeResponse()
    svc.stop_process(alert(), verification(identity), process_response=fake)
    assert fake.calls == []
    last = svc.write.call_args
    assert last.args[0] == 'process_stop' and last.kwargs['signal_sent'] is False and last.kwargs['reasons']


def test_with_the_default_policy_the_installed_config_is_opened_for_this_stop(env):
    svc, child, identity, store = env
    svc.process_config = lambda: dict(INSTALLED)
    fake = FakeResponse()
    assert svc.stop_process(alert(), verification(identity), process_response=fake)['status'] == 'terminated'
    assert len(fake.calls) == 1


def make_alert_service(block_status, verdict='verified_live_process'):
    svc = object.__new__(guard.Guard)
    svc.cfg = {**guard.DEFAULT, 'mode': 'block', 'fast_block': True, 'otx_enabled': False}
    svc.own_ips = {'192.168.1.10'}
    svc.egress_eligible = lambda src, dst: src in svc.own_ips
    svc.eligible = lambda *a: True
    svc.flow_checker = svc.reply_checker = lambda *a: True
    svc.write, svc.otx_check = Mock(), Mock(return_value=False)
    svc.block = Mock(return_value={'status': block_status})
    svc.alert_verifier = lambda a: {'verdict': verdict, 'initiated_locally': True,
                                    'processes': [{'pid': 1234, 'exe': '/x', 'starttime': 5}]}
    svc.cut_flow, svc.stop_process = Mock(), Mock()
    return svc


def full_alert():
    return {'source_ip': '192.168.1.10', 'dest_ip': '45.33.32.10', 'priority': 1, 'rule_id': '1:2000001:1',
            'signature': 'ET MALWARE x', 'source_port': 40000, 'dest_port': 443, 'protocol': 'TCP'}


def test_alert_path_blocks_then_cuts_the_flow_then_stops_the_program():
    svc = make_alert_service('set_membership_confirmed')
    order = Mock()
    order.attach_mock(svc.block, 'block')
    order.attach_mock(svc.cut_flow, 'cut')
    order.attach_mock(svc.stop_process, 'stop')
    svc.on_alert(full_alert())
    assert [c[0] for c in order.mock_calls] == ['block', 'cut', 'stop']


def test_flow_is_not_cut_when_the_block_was_refused_but_the_stop_policy_still_decides():
    svc = make_alert_service('operator_allowlisted')
    svc.on_alert(full_alert())
    svc.cut_flow.assert_not_called()
    svc.stop_process.assert_called_once()


def test_nothing_happens_for_an_alert_without_a_live_process():
    svc = make_alert_service('set_membership_confirmed', verdict='unverified_possible_forgery')
    svc.on_alert(full_alert())
    svc.block.assert_not_called()
    svc.cut_flow.assert_not_called()
    svc.stop_process.assert_not_called()


def test_cut_flow_destroys_only_the_alerts_connection_and_records_the_result():
    svc = object.__new__(guard.Guard)
    svc.own_ips, svc.write = {'192.168.1.10'}, Mock()
    killer = Mock(return_value={'terminated': True, 'verified': True, 'reason': None})
    svc.cut_flow(full_alert(), killer=killer)
    killer.assert_called_once_with('192.168.1.10', 40000, '45.33.32.10', 443, 'tcp')
    assert svc.write.call_args.kwargs['terminated'] is True and svc.write.call_args.kwargs['ip'] == '45.33.32.10'


def _hex4(ip, port):
    return ''.join(f'{int(part):02X}' for part in reversed(ip.split('.'))) + f':{port:04X}'


@pytest.fixture
def fake_proc(tmp_path):
    """A /proc with one program: it started a connection to 203.0.113.9 and serves one on port 8080."""
    rows = [(('10.0.0.2', 40000), ('203.0.113.9', 443), '01', 5001),
            (('0.0.0.0', 8080), ('0.0.0.0', 0), '0A', 5002),
            (('10.0.0.2', 8080), ('198.51.100.7', 51000), '01', 5003)]
    net = tmp_path / 'net'
    net.mkdir()
    (net / 'tcp').write_text('  sl  local_address rem_address   st\n' + ''.join(
        f'  {i}: {_hex4(*l)} {_hex4(*r)} {st} 00000000:00000000 00:00000000 00000000     0        0 {ino} 1 0\n'
        for i, (l, r, st, ino) in enumerate(rows)))
    pid = tmp_path / '4242'
    (pid / 'fd').mkdir(parents=True)
    for fd, ino in ((3, 5001), (4, 5003)):
        (pid / 'fd' / str(fd)).symlink_to(f'socket:[{ino}]')
    (pid / 'exe').symlink_to('/usr/bin/prog')
    fields = ['S', '1'] + ['0'] * 17 + ['777'] + ['0'] * 10          # ppid 1, starttime 777
    (pid / 'stat').write_text('4242 (prog) ' + ' '.join(fields) + '\n')
    return str(tmp_path)


def _verify(proc, src, sport, dst, dport, protocol='TCP'):
    alert = {'source_ip': src, 'source_port': sport, 'dest_ip': dst, 'dest_port': dport, 'protocol': protocol}
    return alert_verify.verify_alert(alert, proc=proc, verifier=lambda pid: {'pid': pid, 'live': True})


def test_a_connection_the_program_started_is_initiated_locally(fake_proc):
    for args in (('10.0.0.2', 40000, '203.0.113.9', 443), ('203.0.113.9', 443, '10.0.0.2', 40000)):
        report = _verify(fake_proc, *args)
        assert report['verdict'] == 'verified_live_process' and report['initiated_locally'] is True
        assert report['local_port'] == 40000
        assert [(p['pid'], p['exe'], p['starttime']) for p in report['processes']] == [(4242, '/usr/bin/prog', 777)]


def test_a_connection_the_program_only_serves_is_never_initiated_locally(fake_proc):
    report = _verify(fake_proc, '198.51.100.7', 51000, '10.0.0.2', 8080)
    assert report['verdict'] == 'verified_live_process'          # the program is real and live ...
    assert report['initiated_locally'] is False and report['local_port'] == 8080   # ... but it serves this one


def test_udp_alerts_are_never_treated_as_started_locally(fake_proc):
    assert _verify(fake_proc, '10.0.0.2', 40000, '203.0.113.9', 443, 'UDP')['initiated_locally'] is False


def test_a_flow_that_is_not_there_is_still_possible_forgery(fake_proc):
    report = _verify(fake_proc, '10.0.0.2', 40001, '203.0.113.9', 443)
    assert report['verdict'] == 'unverified_possible_forgery' and report['initiated_locally'] is False


def test_the_new_setting_validates(tmp_path):
    import json
    import os
    path = tmp_path / 'g.json'
    for bad in (-1, 4, 'x'):
        path.write_text(json.dumps({'process_stop_max_priority': bad}))
        os.chmod(path, 0o600)
        with pytest.raises((ValueError, PermissionError)):
            guard.get_config(str(path))
    path.write_text(json.dumps({'process_stop_max_priority': 0}))
    os.chmod(path, 0o600)
    assert guard.get_config(str(path))['process_stop_max_priority'] == 0
