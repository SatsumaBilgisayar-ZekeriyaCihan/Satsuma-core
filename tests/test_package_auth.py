"""2.2.58: package/deployment changes need the admin password; polkit rule writes are caught."""
from pathlib import Path

from satsuma import enforcement, remediation
from satsuma.smart_rules import SmartRuleEngine

ROOT = Path(__file__).resolve().parents[1]
ENGINE = SmartRuleEngine()


def test_polkit_rule_is_shipped_and_read_first():
    rule = ROOT / 'packaging/root/usr/share/polkit-1/rules.d/10-satsuma-package-auth.rules'
    text = rule.read_text()
    assert 'polkit.Result.AUTH_ADMIN' in text and 'repo-refresh' in text and 'subject.user == "root"' in text
    assert rule.name < 'org.projectatomic.rpmostree1.rules'
    assert '/usr/share/polkit-1/rules.d/10-satsuma-package-auth.rules' in (ROOT / 'packaging/satsuma-core.spec').read_text()


def test_polkit_rule_write_is_caught_and_undone():
    hit = {f['rule_id'] for f in ENGINE.match({'source': 'audit', 'action': 'file_access', 'operation': 'write',
                                                 'file_path': '/etc/polkit-1/rules.d/00-x.rules', 'cmd': 'tee x',
                                                 'exe': '/usr/bin/tee'})}
    assert 'SATSUMA-GAP-074' in hit
    plan = remediation.plan({'rule_id': 'SATSUMA-GAP-074', 'event': {'file_path': '/etc/polkit-1/rules.d/00-x.rules'}})
    assert plan[0]['action'] == 'quarantine_file'
    assert remediation.allowed(plan[0], real=lambda p: p) == (True, '')


def test_removing_satsuma_or_rolling_back_raises_the_alarm_only():
    rules = lambda cmd: {f['rule_id'] for f in ENGINE.match({'source': 'sys_proc', 'action': 'new_process',
                                                             'cmd': cmd, 'exe': '/usr/bin/rpm-ostree'})}
    for cmd in ('rpm-ostree uninstall satsuma-core', 'rpm-ostree rollback', 'rpm-ostree cleanup -r',
                'rpm-ostree override remove suricata'):
        assert 'SATSUMA-GAP-075' in rules(cmd)
    for cmd in ('rpm-ostree install htop', 'rpm-ostree upgrade', 'rpm-ostree status'):
        assert 'SATSUMA-GAP-075' not in rules(cmd)
    assert 'SATSUMA-GAP-075' in enforcement.ALARM_ONLY
