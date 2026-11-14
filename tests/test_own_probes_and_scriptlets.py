"""Satsuma's own probes and RPM scriptlets do not flood findings (2.2.27).

Field export 2026-11-04: 5,200 discovery findings a day came from Satsuma's
own read-only checks, and every upgrade raised service-stop/persistence
findings with kill authorizations for its own systemctl calls.

Satsuma'nın kendi yoklamaları ve RPM betikleri bulgu seli üretmez.
"""
import pytest

from satsuma import kernel_guard
from satsuma.smart_rules import SmartRuleEngine


def hits(cmd, uid='0', exe='/usr/bin/systemctl'):
    engine = SmartRuleEngine()
    return {f['rule_id'] for f in engine.match({'source': 'sys_proc', 'cmd': cmd, 'exe': exe, 'uid': uid, 'id': 'x'})}


@pytest.mark.parametrize('cmd,rule', [
    ('/usr/sbin/ip -j address show dev lo', 'SATSUMA-DISC-002'),
    ('/usr/bin/systemctl list-units --all --plain --no-legend --no-pager', 'SATSUMA-DISC-006'),
    ('systemctl list-units --type=service --no-pager --no-legend --plain', 'SATSUMA-DISC-006'),
])
def test_own_probe_as_root_is_not_a_discovery_finding(cmd, rule):
    assert rule not in hits(cmd, exe=cmd.split()[0])


@pytest.mark.parametrize('cmd,uid,rule', [
    ('/usr/sbin/ip -j address show dev lo', '1000', 'SATSUMA-DISC-002'),
    ('ip address show', '0', 'SATSUMA-DISC-002'),
    ('systemctl list-units --type=timer', '0', 'SATSUMA-DISC-006'),
])
def test_other_discovery_is_still_recorded(cmd, uid, rule):
    assert rule in hits(cmd, uid=uid, exe=cmd.split()[0])


@pytest.mark.parametrize('cmd,rule', [
    ('systemctl stop satsuma-rescue.service', 'SATSUMA-IMP-004'),
    ('systemctl enable satsuma-core-otx.service', 'SATSUMA-PERSIST-001'),
    ('systemctl start satsuma-self-health.timer', 'SATSUMA-PERSIST-001'),
])
@pytest.mark.parametrize('pm', [True, False])
def test_scriptlet_on_satsuma_units_is_skipped_only_while_rpm_runs(monkeypatch, cmd, rule, pm):
    monkeypatch.setattr(kernel_guard, 'package_manager_running', lambda *a, **k: pm)
    assert (rule in hits(cmd)) is (not pm)


def test_scriptlet_touching_other_units_is_still_caught(monkeypatch):
    monkeypatch.setattr(kernel_guard, 'package_manager_running', lambda *a, **k: True)
    assert 'SATSUMA-PERSIST-001' in hits('systemctl enable evil.service')
    assert 'SATSUMA-IMP-004' in hits('systemctl stop sshd')


def test_upgrade_scriptlet_evaluated_after_dnf_finished_is_still_own(monkeypatch):
    """Field 2026-11-04: 'systemctl stop satsuma-core.service' judged long after dnf ended."""
    monkeypatch.setattr(kernel_guard, 'package_manager_running', lambda *a, **k: False)
    monkeypatch.setattr(SmartRuleEngine, '_satsuma_install_time', classmethod(lambda cls: 1_000_000.0))
    engine = SmartRuleEngine()
    near = {'source': 'sys_proc', 'cmd': 'systemctl stop satsuma-core.service', 'exe': '/usr/bin/systemctl',
            'uid': '0', 'id': 'x', 'timestamp': 1_000_000.0 + 120}
    far = {**near, 'timestamp': 1_000_000.0 + 7200}
    assert 'SATSUMA-EVASION-002' not in {f['rule_id'] for f in engine.match(near)}
    assert 'SATSUMA-EVASION-002' in {f['rule_id'] for f in engine.match(far)}
    other = {**near, 'cmd': 'systemctl stop auditd'}
    assert 'SATSUMA-EVASION-002' in {f['rule_id'] for f in engine.match(other)}
