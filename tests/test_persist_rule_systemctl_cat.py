"""SATSUMA-PERSIST-001 does not treat "systemctl cat" as writing a unit (2.2.27).

Field 2026-11-04: Satsuma's own "systemctl cat satsuma-*.timer" checks
matched the cp/mv/tee/cat pattern.

"systemctl cat" birim dosyası yazmak sayılmaz; cp/mv/tee/cat komutları yine yakalanır.
"""
import pytest

from satsuma.smart_rules import SmartRuleEngine


def hit(cmd, exe):
    return 'SATSUMA-PERSIST-001' in {f['rule_id'] for f in SmartRuleEngine().match(
        {'source': 'sys_proc', 'cmd': cmd, 'exe': exe, 'uid': '0', 'id': 'x'})}


def test_systemctl_cat_is_not_unit_creation():
    assert not hit('systemctl cat satsuma-mitm-watch.timer', '/usr/bin/systemctl')


@pytest.mark.parametrize('cmd,exe', [
    ('cp evil.service /etc/systemd/system/evil.service', '/usr/bin/cp'),
    ('/usr/bin/tee /etc/systemd/system/x.timer', '/usr/bin/tee'),
    ('sudo mv /tmp/a.service /etc/systemd/system/a.service', '/usr/bin/sudo'),
    ('systemctl enable evil.service', '/usr/bin/systemctl'),
])
def test_unit_writes_and_enables_still_match(cmd, exe):
    assert hit(cmd, exe)
