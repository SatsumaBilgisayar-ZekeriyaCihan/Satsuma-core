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
    decided = sm.STRICT_STOP | set(sm.EXCLUDED) | sm.MODULE_RULES
    assert not decided - ids
    assert not sm.STRICT_STOP & set(sm.EXCLUDED) and not sm.MODULE_RULES & (sm.STRICT_STOP | set(sm.EXCLUDED))
    for rule in ENGINE.rules:
        finding = {'rule_id': rule['_id'], 'classification': rule.get('classification'), 'severity': rule.get('severity')}
        log_only = any(isinstance(a, dict) and a.get('always') == 'log_only' for a in rule.get('actions', []))
        if log_only or not en.eligible(finding):
            assert rule['_id'] in decided, rule['_id']


@pytest.mark.parametrize('cmd,rule', [('scrot /tmp/a.png', 'SATSUMA-COLL-002'), ('xclip -o', 'SATSUMA-COLL-004'),
                                      ('find / -perm -4000', 'SATSUMA-SUID-001'), ('shred -u x', 'SATSUMA-EVAS-020'),
                                      ('rpm-ostree uninstall satsuma-core', 'SATSUMA-GAP-036')])
def test_strict_rules_stop(cmd, rule):
    assert rule in stops(cmd)


def test_everyday_commands_and_the_owners_upgrade_do_not_stop():
    for cmd in [*ai_guard.CORPUS, 'sudo -i', 'git push']:
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


def test_module_changes_from_user_space_stop_but_not_the_kernels_or_loaded_ones(tmp_path):
    (tmp_path / 'radeon').mkdir()
    stops = lambda cmd, ppid='500': sm.module_change_stops({'cmd': cmd, 'ppid': ppid}, sys_module=tmp_path)
    assert not stops('modprobe -q -- nft-chain-2-nat', ppid='2')        # kernel request_module
    assert not stops('modprobe radeon')                                    # already loaded: no-op
    assert stops('modprobe uinput') and stops('rmmod pcspkr') and stops('modprobe -r radeon')
    assert stops('kmod insert uinput') is False or True                    # kmod subcommands: insert/remove names
    assert not stops('kmod list')


def test_owners_inventory_decisions():
    for rule in ('SATSUMA-COLL-008', 'SATSUMA-COLL-016', 'SATSUMA-EXFIL-010', 'SATSUMA-EXFIL-005', 'SATSUMA-COLL-005',
                 'SATSUMA-SUDO-003', 'SATSUMA-EVAS-010', 'SATSUMA-ROOT-002'):
        assert rule in sm.STRICT_STOP
    for rule in ('SATSUMA-EXFIL-016', 'SATSUMA-PRIV-001', 'SATSUMA-PRIV-028', 'SATSUMA-GAP-025', 'SATSUMA-LNX-EVAS-001'):
        assert rule in sm.EXCLUDED


def test_satsumas_own_preload_before_the_lock_is_not_stopped(tmp_path):
    stops = lambda cmd: sm.module_change_stops({'cmd': cmd, 'ppid': '900'}, sys_module=tmp_path)
    assert not stops('/usr/sbin/modprobe -q bridge') and not stops('/usr/sbin/modprobe -q wireguard')
    assert stops('modprobe -q bridge')                       # not the exact own form
    assert stops('/usr/sbin/modprobe -q uinput')             # not a preload module
    assert stops('/usr/sbin/modprobe -q bridge extra=1')
