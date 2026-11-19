"""2.2.61 (owner, 2026-11-20): report-only rules that may stop, without stopping the machine."""
import pytest

from satsuma import ai_guard, enforcement as en, strict_mode as sm
from satsuma.smart_rules import SmartRuleEngine

ENGINE = SmartRuleEngine()


def stops(cmd, engine=ENGINE):
    exe = '/usr/bin/' + cmd.split()[0].rsplit('/', 1)[-1].lstrip('-')
    return {f['rule_id'] for f in engine.match({'source': 'sys_proc', 'action': 'new_process', 'cmd': cmd,
                                                 'exe': exe, 'pid': 5}) if en.eligible(f)}


def test_every_report_only_rule_is_decided():
    ids = {r['_id'] for r in ENGINE.rules}
    assert not (sm.STRICT_STOP | set(sm.EXCLUDED)) - ids
    assert not sm.STRICT_STOP & set(sm.EXCLUDED)
    for rule in ENGINE.rules:
        finding = {'rule_id': rule['_id'], 'classification': rule.get('classification'), 'severity': rule.get('severity')}
        log_only = any(isinstance(a, dict) and a.get('always') == 'log_only' for a in rule.get('actions', []))
        if log_only or not en.eligible(finding):
            assert rule['_id'] in sm.STRICT_STOP or rule['_id'] in sm.EXCLUDED, rule['_id']


@pytest.mark.parametrize('cmd,rule', [('scrot /tmp/a.png', 'SATSUMA-COLL-002'), ('xclip -o', 'SATSUMA-COLL-004'),
                                      ('find / -perm -4000', 'SATSUMA-SUID-001'), ('shred -u x', 'SATSUMA-EVAS-020'),
                                      ('rpm-ostree uninstall satsuma-core', 'SATSUMA-GAP-036')])
def test_strict_rules_stop(cmd, rule):
    assert rule in stops(cmd)


def test_everyday_commands_and_the_owners_upgrade_do_not_stop():
    for cmd in [*ai_guard.CORPUS, 'sudo -i', 'git push', 'modprobe -q -- snd-pcm',
                'rpm-ostree uninstall satsuma-core --install /var/home/u/satsuma-core-2.2.61-1.fc44.x86_64.rpm']:
        strict_hits = {r for r in stops(cmd) if r in sm.STRICT_STOP}
        assert not strict_hits, (cmd, strict_hits)


def test_owners_chattr_stays_an_alarm_and_mode_can_be_switched_off():
    assert not en.eligible({'rule_id': 'SATSUMA-GAP-025', 'classification': 'suspicious', 'severity': 'high',
                            'owner_strict': True})
    engine = SmartRuleEngine()
    engine.strict_mode = False
    assert 'SATSUMA-COLL-002' not in stops('scrot /tmp/a.png', engine)

    class Store(dict):
        def get(self, k, d=None): return super().get(k, d)
    assert sm.enabled(Store()) and not sm.enabled(Store(strict_mode={'enabled': False}))
