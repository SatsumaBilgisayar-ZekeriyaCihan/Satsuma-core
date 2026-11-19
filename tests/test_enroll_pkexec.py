"""2.2.57: the dashboard's own desktop enrollment is not a suspicious pkexec (field 18.11 18:22)."""
from satsuma.smart_rules import SmartRuleEngine

ENGINE = SmartRuleEngine()


def rules(cmd):
    return {f['rule_id'] for f in ENGINE.match({'source': 'sys_proc', 'action': 'new_process', 'uid': 1000,
                                                'exe': '/usr/bin/pkexec', 'cmd': cmd})}


def test_own_enrollment_is_quiet():
    assert not rules('/usr/bin/pkexec /usr/bin/satsuma-enroll-desktop --user satsumabilgisayar --password-stdin')


def test_anything_else_still_matches():
    assert rules('pkexec /usr/bin/satsuma-enroll-desktop --user bob /bin/sh')
    assert rules('pkexec /tmp/satsuma-enroll-desktop --user bob')
    assert 'SATSUMA-POLKIT-001' in rules('pkexec --user root /bin/bash')
    assert rules('pkexec /usr/bin/foo --user bob') == {'SATSUMA-PRIV-003'}
