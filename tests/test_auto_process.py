"""Exercise real signals only against disposable child processes."""
import signal
import subprocess
import time
import sys
from copy import deepcopy

import pytest

from satsuma.auto_action import AutoActionEngine, effective_config
from satsuma.auto_process import corroborate
from satsuma.process_identity import capture_process_identity
from satsuma.store import Store
from satsuma.presentation import action_view


@pytest.fixture
def setup(tmp_path):
    store = Store(tmp_path / 'data', test=True)
    child = subprocess.Popen(['sleep', '60'])
    config = dict(response_enabled=True, destructive_response_enabled=True,
                  destructive_allowed_actions=['process_kill'], auto_action_process_enabled=True)
    identity = capture_process_identity(child.pid)
    assert identity
    finding = dict(finding_id='test', rule_id='test-rule', classification='confirmed',
                   independent_sources=['sys_proc', 'audit'], actions=['log_only'],
                   event={**identity, 'timestamp': time.time(), 'source': 'sys_proc'})
    yield store, child, config, finding
    if child.poll() is None:
        child.terminate()
    child.wait(timeout=5)
    store.close()


def test_log_only_rule_reaches_real_process_termination(setup):
    store, child, config, finding = setup
    result = AutoActionEngine(store, config).process(finding)['process_response']
    assert result['signal_sent'] is True
    assert result['exit_verified'] is True
    assert action_view(result)['outcome'] == 'Süreç sonlandırıldı; çıkışı doğrulandı'
    assert action_view(result)['target'] == 'PID ' + str(child.pid)
    assert child.wait(timeout=5) == -signal.SIGTERM


def test_authorization_and_signal_are_not_presented_as_verified_exit():
    assert 'sonuç bir sonraki kayıtta' in action_view({'status': 'process_termination_authorized'})['outcome']
    assert 'çıkış doğrulanmadı' in action_view({'status': 'termination_pending', 'signal_sent': True})['outcome']
    assert 'çıkışı doğrulandı' not in action_view({'status': 'terminated'})['outcome']


@pytest.mark.parametrize('change', ['indicator', 'stale', 'wrong_start',
                                   'wrong_exe', 'missing_identity', 'disabled'])
def test_unverified_or_protected_context_never_signals(setup, change):
    store, child, config, finding = setup
    if change == 'indicator': finding['classification'] = 'indicator'
    if change == 'stale': finding['event']['timestamp'] -= 600
    if change == 'wrong_start': finding['event']['starttime'] += 1
    if change == 'wrong_exe': finding['event']['exe'] = '/nonexistent/executable'
    if change == 'missing_identity':
        # Without the user's blocking policy a missing start time is never filled in.
        finding['event'].pop('starttime')
        store.set('enforcement_policy', {'enabled': False})
    if change == 'disabled':
        config['auto_action_process_enabled'] = False
        store.set('enforcement_policy', {'enabled': False})  # the user switched blocking off
    result = AutoActionEngine(store, config).process(finding)['process_response']
    assert result['signal_sent'] is False
    assert child.poll() is None


@pytest.mark.parametrize('change', ['one_sensor', 'integrity'])
def test_full_protection_acts_on_one_sensor_and_an_integrity_warning(setup, change):
    # 2.2.9: one detection is enough, and an integrity warning is reported
    # instead of turning the response into observe-only.
    store, child, config, finding = setup
    if change == 'one_sensor': finding['independent_sources'] = ['sys_proc']
    if change == 'integrity': store.set('integrity_runtime', {'status': 'UNTRUSTED'})
    result = AutoActionEngine(store, config).process(finding)['process_response']
    assert result['signal_sent'] is True
    assert child.wait(timeout=5) == -signal.SIGTERM


def test_sensor_metadata_identity_and_corroboration_reach_termination(setup):
    store, child, config, finding = setup
    identity = finding['event']
    first = {**finding, 'classification': 'suspicious', 'severity': 'high',
             'event': {'timestamp': time.time(), 'source': 'sys_proc', 'metadata': {
                 'extensions': {'host.pid': child.pid, 'host.starttime': identity['starttime'],
                                'host.exe': identity['exe']}}}}
    second = deepcopy(first)
    second.update(rule_id='second-rule')
    second['event']['source'] = 'audit'
    confirmed = corroborate([first, second])
    assert len(confirmed) == 1
    result = AutoActionEngine(store, config).process(confirmed[0])['process_response']
    assert result['signal_sent'] is True
    assert child.wait(timeout=5) == -signal.SIGTERM


@pytest.mark.parametrize('change', ['same_sensor', 'pid_reuse', 'indicator', 'stale', 'same_rule'])
def test_unrelated_or_benign_findings_do_not_confirm(setup, change):
    _, _, _, first = setup
    first.update(classification='suspicious', severity='high')
    second = deepcopy(first)
    second['rule_id'] = 'second-rule'
    second['event']['source'] = 'audit'
    if change == 'same_sensor': second['event']['source'] = 'sys_proc'
    if change == 'pid_reuse': second['event']['starttime'] += 1
    if change == 'indicator': second['classification'] = 'indicator'
    if change == 'stale': second['event']['timestamp'] -= 600
    if change == 'same_rule': second['rule_id'] = first['rule_id']
    assert corroborate([first, second]) == []


def test_network_policy_preserves_explicit_process_authorization(setup):
    store, _, config, _ = setup
    store.set('auto_action_policy', {'network_enabled': True})
    effective = effective_config(store, config)
    assert set(effective['destructive_allowed_actions']) == {'network_isolate', 'process_kill'}


def test_network_enable_does_not_override_disabled_process_response(setup):
    store, child, config, finding = setup
    config['response_enabled'] = False
    store.set('enforcement_policy', {'enabled': False})
    store.set('auto_action_policy', {'network_enabled': True})
    result = AutoActionEngine(store, config).process(finding)['process_response']
    assert result['signal_sent'] is False
    assert child.poll() is None


def test_sigterm_resistant_process_is_killed_and_exit_verified(setup):
    store, _, config, finding = setup
    child = subprocess.Popen([sys.executable, '-c',
        'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); '
        'print("ready",flush=True); time.sleep(60)'], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'ready'
        finding['event'] = {**capture_process_identity(child.pid), 'timestamp': time.time()}
        result = AutoActionEngine(store, config).process(finding)['process_response']
        assert result['exit_verified'] is True
        assert result['result']['escalated'] is True
        assert child.wait(timeout=5) == -signal.SIGKILL
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=5)
        child.stdout.close()


def test_brain_confirms_and_terminates_without_yaml_kill_action(setup):
    from run_satsuma_teams import _automatic_actions
    store, child, config, finding = setup
    finding.update(classification='suspicious', severity='high')
    other = deepcopy(finding)
    other['rule_id'] = 'independent-audit-rule'
    other['event']['source'] = 'audit'
    processed, _, _ = _automatic_actions(store, config, [finding, other])
    assert processed == 3
    assert child.wait(timeout=5) == -signal.SIGTERM
