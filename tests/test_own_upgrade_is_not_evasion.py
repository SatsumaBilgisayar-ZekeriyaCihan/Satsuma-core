"""Satsuma's own upgrade does not raise "security tool disabled" (2.2.23).

Satsuma'nın kendi güncellemesi "güvenlik aracı devre dışı" bulgusu üretmez.
"""
import pytest

from satsuma import kernel_guard
from satsuma.smart_rules import SmartRuleEngine


def hits(cmd):
    engine = SmartRuleEngine()
    return [f['rule_id'] for f in engine.match({'source': 'sys_proc', 'cmd': cmd, 'exe': '/usr/bin/systemctl', 'id': 'x'})]


@pytest.mark.parametrize('pm', [True, False])
def test_stopping_satsuma_units_during_rpm_is_skipped_only_while_rpm_runs(monkeypatch, pm):
    monkeypatch.setattr(kernel_guard, 'package_manager_running', lambda *a, **k: pm)
    found = 'SATSUMA-EVASION-002' in hits('systemctl stop satsuma-mitm-watch.timer')
    assert found is (not pm)


def test_stopping_other_security_tools_is_always_caught(monkeypatch):
    monkeypatch.setattr(kernel_guard, 'package_manager_running', lambda *a, **k: True)
    assert 'SATSUMA-EVASION-002' in hits('systemctl stop auditd')
    assert 'SATSUMA-EVASION-002' in hits('systemctl stop satsuma-network.service suricata')
