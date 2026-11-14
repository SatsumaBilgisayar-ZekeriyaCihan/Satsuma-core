"""Automatic blocking: one fresh high-severity match stops its own process.

User request 2026-10-25: the rules must be active, not only reported. Real
signals go only to disposable child processes.

Otomatik engelleme: tek bir taze yüksek önemli eşleşme kendi işlemini durdurur.
"""
import json
import subprocess
import time
from types import SimpleNamespace as NS

import pytest

from satsuma import enforcement
from satsuma.auto_action import AutoActionEngine
from satsuma.process_identity import capture_process_identity
from satsuma.store import Store
from test_k7_lowering_protection import Auth, PASSWORD, changes

# policy.json as installed: response stays off; only the user's policy opens it.
INSTALLED = dict(response_enabled=False, destructive_response_enabled=False, destructive_allowed_actions=[],
                 auto_action_process_enabled=False)


@pytest.fixture
def child_store(tmp_path):
    store = Store(tmp_path / 'data', test=True)
    child = subprocess.Popen(['sleep', '60'])
    yield store, child
    if child.poll() is None:
        child.terminate()
    child.wait(timeout=5)
    store.close()


def finding_for(child, classification='suspicious', severity='high', source='sys_proc', with_start=True):
    identity = capture_process_identity(child.pid)
    event = {**identity, 'timestamp': time.time(), 'source': source}
    if not with_start:
        event.pop('starttime')
    return dict(finding_id='f-%s-%s' % (classification, severity), rule_id='SATSUMA-TEST-001',
                classification=classification, severity=severity, event=event)


def result_of(store, finding):
    return AutoActionEngine(store, dict(INSTALLED)).process(finding)['process_response']


def test_default_policy_stops_the_process_on_one_sensor(child_store):
    store, child = child_store
    result = result_of(store, finding_for(child))
    assert result['signal_sent'] is True and child.wait(timeout=5) < 0
    shown = [json.loads(b) for (b,) in store.db.execute("SELECT body FROM records WHERE kind='findings'")]
    assert any(f.get('automatic_action') == 'process_terminated' and 'Satsuma bir programı durdurdu' in f['title'] for f in shown)


@pytest.mark.parametrize('classification,severity', [('indicator', 'high'), ('indicator', 'medium'), ('indicator', 'low')])
def test_weaker_rules_only_report(child_store, classification, severity):
    store, child = child_store
    assert result_of(store, finding_for(child, classification, severity))['signal_sent'] is False
    assert child.poll() is None


@pytest.mark.parametrize('classification,severity', [('suspicious', 'medium'), ('suspicious', 'low'), ('likely', 'medium')])
def test_full_protection_stops_every_attack_rule_severity(child_store, classification, severity):
    store, child = child_store
    assert result_of(store, finding_for(child, classification, severity))['signal_sent'] is True
    assert child.wait(timeout=5) < 0


def test_attack_tool_indicator_is_stopped(child_store):
    store, child = child_store
    finding = {**finding_for(child, 'indicator', 'medium'), 'rule_id': 'SATSUMA-EXEC-002'}
    assert result_of(store, finding)['signal_sent'] is True
    assert child.wait(timeout=5) < 0


def test_switched_off_policy_stops_nothing(child_store):
    store, child = child_store
    enforcement.set_policy(store, False)
    assert result_of(store, finding_for(child, 'likely', 'critical'))['signal_sent'] is False
    assert child.poll() is None


def test_stale_event_stops_nothing(child_store):
    store, child = child_store
    finding = finding_for(child)
    finding['event']['timestamp'] -= 600
    assert result_of(store, finding)['signal_sent'] is False and child.poll() is None


def test_audit_event_without_start_time_is_matched_to_the_live_process(child_store):
    store, child = child_store
    result = result_of(store, finding_for(child, source='audit', with_start=False))
    assert result['signal_sent'] is True and child.wait(timeout=5) < 0


def test_a_leftover_pause_value_no_longer_stops_protection(child_store):
    store, child = child_store
    store.set('operator_pause', True)  # written by a version before 2.2.16
    assert result_of(store, finding_for(child))['signal_sent'] is True and child.wait(timeout=5) < 0


def test_no_program_is_exempt_by_name_or_unit(tmp_path, monkeypatch):
    # 2.2.38 (owner, 2026-11-13): code sent through TeamViewer or AnyDesk, or hidden
    # inside the desktop or Satsuma itself, is stopped like any other.
    from satsuma import trusted_process
    monkeypatch.setattr(trusted_process, 'trusted_path', lambda value: True)
    proc = tmp_path / '42'
    proc.mkdir()
    (proc / 'cgroup').write_text('0::/user.slice/user-1000.slice/app.slice/app.scope\n')
    def live(path):
        (proc / 'exe').unlink(missing_ok=True)
        (proc / 'exe').symlink_to(path)
    for path in ('/opt/teamviewer/tv_bin/teamviewer', '/usr/bin/anydesk', '/usr/bin/gnome-shell',
                 '/usr/sbin/clamd', '/usr/lib/systemd/systemd-journald', '/usr/bin/dnf5'):
        live(path)
        assert enforcement.exempt(42, path, proc_root=tmp_path) is None, path
    for unit in ('satsuma-teams.service', 'satsuma-core.service', 'teamviewerd.service'):
        (proc / 'cgroup').write_text('0::/system.slice/' + unit + '\n')
        assert enforcement.exempt(42, '/usr/bin/python3', proc_root=tmp_path) is None, unit
    assert not hasattr(enforcement, 'EXEMPT_EXECUTABLES')


def test_only_pid_1_and_the_owners_dashboard_command_are_not_signalled(tmp_path):
    proc = tmp_path / '42'
    proc.mkdir()
    (proc / 'cgroup').write_text('0::/user.slice/user-1000.slice/app.slice/app.scope\n')
    assert enforcement.exempt(1, '/usr/lib/systemd/systemd', proc_root=tmp_path) == 'init_cannot_be_stopped'
    # A dashboard origin counts only from the real operator service unit.
    assert enforcement.exempt(42, '/usr/bin/curl', {'origin': 'satsuma_operator'}, proc_root=tmp_path) is None
    (proc / 'cgroup').write_text('0::/system.slice/satsuma-operator.service\n')
    assert enforcement.exempt(42, '/usr/bin/curl', {'origin': 'satsuma_operator'}, proc_root=tmp_path) == 'satsuma_dashboard_action'
    assert enforcement.exempt(42, '/usr/bin/curl', proc_root=tmp_path) is None


def test_turning_blocking_off_needs_the_password_turning_it_on_does_not(tmp_path):
    from satsuma.operator_service import OperatorController
    store = Store(tmp_path / 'data', test=True)
    try:
        c = OperatorController(store, auth=Auth(), runner=lambda *a, **k: NS(returncode=0, stdout='', stderr=''),
                               boot_provider=lambda: {'response_unlocked': True})
        token = c.dispatch(1000, 'login', {'password': PASSWORD})['token']
        with pytest.raises(PermissionError, match='K7'):
            c.dispatch(1000, 'enforcement', {'enabled': False, 'token': token})
        c.dispatch(1000, 'enforcement', {'enabled': False, 'token': token, 'password': PASSWORD})
        assert enforcement.policy(store)['enabled'] is False
        c.dispatch(1000, 'enforcement', {'enabled': True, 'token': token})
        assert enforcement.policy(store)['enabled'] is True
        assert c.dispatch(1000, 'status', {'token': token})['enforcement']['enabled'] is True
    finally:
        store.close()
