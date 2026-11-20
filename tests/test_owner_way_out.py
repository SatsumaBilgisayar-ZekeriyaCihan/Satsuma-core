"""2.2.64 (field 2026-11-20): the owner was locked out of his own computer. Never again."""
from pathlib import Path
from types import SimpleNamespace

from satsuma import enforcement, strict_mode
from satsuma.smart_rules import SmartRuleEngine

ROOT = Path(__file__).resolve().parents[1]
WAY_OUT = ('rpm-ostree uninstall satsuma-core', 'rpm-ostree remove satsuma-core', 'rpm-ostree override remove satsuma-core',
           'rpm-ostree rollback', 'rpm-ostree reset', 'rpm-ostree override reset --all', 'rpm-ostree cancel',
           'rpm-ostree uninstall satsuma-core --install /var/home/u/satsuma-core-2.2.64-1.fc44.x86_64.rpm',
           'rpm -e satsuma-core', 'dnf remove satsuma-core', 'rpm-ostree kargs --append=satsuma.off')


def test_the_owners_way_out_is_never_stopped_in_any_mode():
    for strict in (False, True):
        engine = SmartRuleEngine()
        engine.strict_mode = strict
        for cmd in WAY_OUT:
            exe = '/usr/bin/' + cmd.split()[0]
            for finding in engine.match({'source': 'sys_proc', 'action': 'exec', 'cmd': cmd, 'exe': exe,
                                         'uid': 0, 'pid': 5000, 'ppid': 4000}):
                assert not enforcement.eligible(finding), (strict, cmd, finding['rule_id'])
    assert 'SATSUMA-GAP-036' in strict_mode.EXCLUDED and 'SATSUMA-GAP-075' in strict_mode.EXCLUDED


def test_every_unit_honours_the_satsuma_off_switch():
    for unit in (ROOT / 'systemd').iterdir():
        assert 'ConditionKernelCommandLine=!satsuma.off' in unit.read_text(), unit.name


def test_no_automatic_rpm_ostree_transaction():
    assert 'sync_initramfs' not in (ROOT / 'satsuma/module_lock.py').read_text().split('2.2.64')[0].split('def run')[-1]
    assert 'sync_initramfs()' not in (ROOT / 'satsuma/module_lock.py').read_text()


def test_banned_programs_stop_and_snap_firefox_does_not():
    engine = SmartRuleEngine()
    hit = lambda cmd: [f['rule_id'] for f in engine.match({'source': 'sys_proc', 'action': 'exec', 'cmd': cmd,
                       'exe': '/usr/bin/x', 'uid': 0, 'pid': 5000, 'ppid': 4000}) if enforcement.eligible(f)]
    assert 'SATSUMA-GAP-076' in hit('/usr/bin/s-nail -s rkhunter root')
    assert 'SATSUMA-GAP-077' in hit('/usr/sbin/avahi-daemon -s') and 'SATSUMA-GAP-077' in hit('/usr/lib64/firefox/firefox')
    assert not hit('/snap/firefox/7000/usr/lib/firefox/firefox') and not hit('grep avahi /etc/hosts')


def test_previous_boot_with_the_switch_is_a_finding(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location('teams_off', ROOT / 'run_satsuma_teams.py')
    teams = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(teams)
    recorded = []
    monkeypatch.setattr('satsuma.finding_store.record_finding', lambda store, f, src: recorded.append(f))

    class Mem:
        def __init__(self): self.d = {}
        def get(self, k, default=None): return self.d.get(k, default)
        def set(self, k, v): self.d[k] = v
    boot = tmp_path / 'boot_id'
    boot.write_text('abc\n')
    run = lambda *a, **k: SimpleNamespace(stdout='Command line: BOOT_IMAGE=x root=UUID=1 rhgb satsuma.off\n')
    store = Mem()
    assert teams._previous_boot_was_off(store, run, boot) == 'SATSUMA-OFF-001'
    assert teams._previous_boot_was_off(store, run, boot) is None            # once per boot
    quiet = lambda *a, **k: SimpleNamespace(stdout='Command line: BOOT_IMAGE=x rhgb satsuma.offline=1\n')
    boot.write_text('def\n')
    assert teams._previous_boot_was_off(Mem(), quiet, boot) is None


def test_clamd_is_woken_and_asked_again_before_clamscan():
    from satsuma import security_scan as s
    calls = []
    control = lambda cmd, **kw: calls.append(cmd) or SimpleNamespace(returncode=0)
    results = iter([{'status': 'OK', 'findings': 0}])
    import unittest.mock as m
    with m.patch.object(s, '_result', lambda tool, cmd, **kw: next(results)):
        out = s._retry_clamd(['/usr/bin/clamdscan', '--fdpass', '/etc'], {'status': 'ERROR', 'error': 'Communication error'},
                             runner=None, now=None, control=control)
    assert out['status'] == 'OK' and calls[0] == ['/usr/bin/systemctl', 'start', 'clamd@scan.service']
