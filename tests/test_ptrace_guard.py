"""ptrace_scope 3 blinds the RAM scanner: it is an alarm, and its persistent source is undone.

Real files in a temporary sysctl tree; nothing on this machine is touched.

ptrace_scope 3 RAM tarayıcısını kör eder: alarm verilir, kalıcı kaynağı geri alınır.
Geçici bir sysctl ağacında gerçek dosyalar; bu makinede hiçbir şeye dokunulmaz.
"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from satsuma import kernel_guard as kg
from satsuma import kernel_profile as kp
from satsuma import ptrace_guard as pg


@pytest.fixture
def tree(tmp_path):
    etc, usr = tmp_path / 'etc/sysctl.d', tmp_path / 'usr/lib/sysctl.d'
    etc.mkdir(parents=True)
    usr.mkdir(parents=True)
    own = usr / '90-satsuma-memory.conf'
    own.write_text('kernel.yama.ptrace_scope = 2\nkernel.kptr_restrict = 2\n')
    # Fedora's own file: 0, sorts before Satsuma's and is overridden by it.
    (usr / '10-default-yama-scope.conf').write_text('kernel.yama.ptrace_scope = 0\n')
    cmdline = tmp_path / 'cmdline'
    cmdline.write_text('BOOT_IMAGE=/vmlinuz ro rhgb quiet\n')
    legacy = tmp_path / 'etc/sysctl.conf'
    return SimpleNamespace(root=tmp_path, etc=etc, usr=usr, own=own, cmdline=cmdline, legacy=legacy,
                           paths={'dirs': (etc, usr), 'legacy': (legacy,), 'own': own, 'cmdline': str(cmdline)})


def test_a_clean_fedora_tree_has_no_source(tree):
    assert pg.sources(**tree.paths) == []


def test_a_later_file_setting_three_is_a_source_and_only_its_line_is_commented_out(tree):
    attack = tree.etc / '99-hardening.conf'
    attack.write_text('net.ipv4.ip_forward = 0\nkernel.yama.ptrace_scope = 3\nvm.swappiness = 10\n')
    found = pg.sources(**tree.paths)
    assert [(f['path'], f['line'], f['value']) for f in found] == [(str(attack), 2, '3')]
    results = pg.neutralize(found, evidence=tree.root / 'evidence', clock=lambda: 1000)
    assert results[0]['neutralized'] is True
    lines = attack.read_text().splitlines()
    assert lines[0] == 'net.ipv4.ip_forward = 0' and lines[2] == 'vm.swappiness = 10'
    assert lines[1].startswith('# satsuma 2.2.37') and lines[1].endswith('kernel.yama.ptrace_scope = 3')
    # The whole original is kept as evidence, readable only by root.
    copy = Path(results[0]['evidence'])
    assert copy.read_text().splitlines()[1] == 'kernel.yama.ptrace_scope = 3'
    assert copy.stat().st_mode & 0o777 == 0o600
    assert pg.sources(**tree.paths) == []


def test_three_is_a_source_even_in_a_file_that_sorts_first(tree):
    early = tree.etc / '00-early.conf'
    early.write_text('kernel/yama/ptrace_scope=3\n')
    assert [f['path'] for f in pg.sources(**tree.paths)] == [str(early)]


def test_a_weaker_value_counts_only_where_it_wins_over_satsuma(tree):
    (tree.etc / '50-before.conf').write_text('kernel.yama.ptrace_scope = 1\n')
    later = tree.etc / '95-after.conf'
    later.write_text('kernel.yama.ptrace_scope = 1\n')
    assert [f['path'] for f in pg.sources(**tree.paths)] == [str(later)]


def test_a_file_named_like_satsumas_is_moved_to_evidence_not_deleted(tree):
    shadow = tree.etc / '90-satsuma-memory.conf'
    shadow.write_text('kernel.kptr_restrict = 0\n')
    found = pg.sources(**tree.paths)
    assert found == [{'kind': 'shadowing_file', 'path': str(shadow), 'shadows': str(tree.own)}]
    result = pg.neutralize(found, evidence=tree.root / 'evidence', clock=lambda: 5)
    assert result[0]['neutralized'] and not shadow.exists()
    assert Path(result[0]['evidence']).read_text() == 'kernel.kptr_restrict = 0\n'


def test_legacy_sysctl_conf_and_its_fedora_link_are_one_source(tree):
    tree.legacy.write_text('kernel.yama.ptrace_scope=3\n')
    (tree.etc / '99-sysctl.conf').symlink_to(tree.legacy)
    found = pg.sources(**tree.paths)
    assert len(found) == 1
    results = pg.neutralize(found, evidence=tree.root / 'evidence', clock=lambda: 7)
    assert results[0]['neutralized'] and tree.legacy.read_text().startswith('# satsuma 2.2.37')
    assert (tree.etc / '99-sysctl.conf').is_symlink()


def test_a_boot_argument_of_three_is_reported_for_the_boot_unit(tree):
    tree.cmdline.write_text('ro sysctl.kernel.yama.ptrace_scope=3 quiet\n')
    entries = {'/boot/vmlinuz-6.18': {'ro', 'sysctl.kernel.yama.ptrace_scope=3'}}
    found = pg.sources(entries=entries, **tree.paths)
    assert pg.boot_arguments(found) == ['sysctl.kernel.yama.ptrace_scope=3']
    result = pg.neutralize(found, evidence=tree.root / 'evidence')
    assert result[0]['needs_boot_unit'] and result[0]['neutralized'] is False


class Grubby:
    def __init__(self, entries):
        self.entries = entries
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[1] == '--info=ALL':
            out = ''.join(f'index=0\nkernel="{k}"\nargs="{" ".join(sorted(v))}"\n' for k, v in self.entries.items())
            return SimpleNamespace(returncode=0, stdout=out, stderr='')
        option, _, words = argv[2].partition('=')
        for line in self.entries.values():
            (line.difference_update if option == '--remove-args' else line.update)(words.split())
        return SimpleNamespace(returncode=0, stdout='', stderr='')


def test_the_boot_unit_removes_the_argument_from_every_kernel(tmp_path):
    bad = 'sysctl.kernel.yama.ptrace_scope=3'
    grubby = Grubby({'/boot/a': set(kp.CMDLINE) | {bad}, '/boot/b': {'ro', bad}})
    modules = tmp_path / 'modules'
    modules.write_text('ext4 2 1 - Live 0x0\n')
    result = kp.apply_boot(grubby, modules)
    assert result['removed_ptrace_args'] == [bad]
    assert all(bad not in words and set(kp.CMDLINE) <= words for words in grubby.entries.values())


def proc_tree(tmp_path):
    root = tmp_path / 'sys'
    for name in ('all', 'default', 'lo'):
        (root / 'net/ipv4/conf' / name).mkdir(parents=True)
    for key, value in kg.table(root).items():
        (root / key).parent.mkdir(parents=True, exist_ok=True)
        (root / key).write_text(value + '\n')
    return root


def test_guard_no_longer_accepts_three_and_undoes_its_source(tree, tmp_path, monkeypatch):
    root = proc_tree(tmp_path)
    (root / pg.KEY).write_text('3\n')
    attack = tree.etc / '99-x.conf'
    attack.write_text('kernel.yama.ptrace_scope = 3\n')
    real_restore = kg.restore

    def restore(items, root_, listdir):
        # The real kernel answers EINVAL when 3 would be lowered.
        kept = [i for i in items if i['key'] == pg.KEY]
        result = real_restore([i for i in items if i['key'] != pg.KEY], root_, listdir)
        result['failed'] += [{**i, 'error': 'Invalid argument'} for i in kept]
        return result

    monkeypatch.setattr(kg, 'restore', restore)
    calls = []
    guard = kg.Guard(root=root, runner=lambda argv, **k: calls.append(argv) or SimpleNamespace(returncode=0, stdout=''),
                     clock=lambda: 100.0, wall=lambda: 1.0, state_dir=tmp_path / 'state', pm_running=lambda: False,
                     can_write=True, echo=lambda *_: None, ptrace_paths=tree.paths,
                     ptrace_evidence=tmp_path / 'evidence')
    assert kg.drift(root) == [{'key': pg.KEY, 'expected': '2', 'actual': '3'}]
    guard.check_settings()
    kinds = [event['kind'] for event in guard.events]
    assert 'ram_scanner_blinded' in kinds and 'ram_scanner_blinding_source' in kinds
    assert attack.read_text().startswith('# satsuma 2.2.37')
    assert guard.ptrace['status'] == 'SOURCE_FOUND' and guard.ptrace['reboot_needed'] is True
    state = guard.save_state(kg.read_settings(root))
    assert state['ptrace_scope']['sources'][0]['neutralized'] is True
    assert json.loads((tmp_path / 'state/state.json').read_text())['ptrace_scope']['status'] == 'SOURCE_FOUND'


def test_guard_starts_the_boot_unit_for_a_boot_argument(tree, tmp_path):
    tree.cmdline.write_text('ro sysctl.kernel.yama.ptrace_scope=3\n')
    calls = []
    guard = kg.Guard(root=proc_tree(tmp_path), runner=lambda argv, **k: calls.append(argv) or SimpleNamespace(returncode=0),
                     clock=lambda: 100.0, wall=lambda: 1.0, state_dir=tmp_path / 'state', pm_running=lambda: False,
                     can_write=True, echo=lambda *_: None, ptrace_paths=tree.paths,
                     ptrace_evidence=tmp_path / 'evidence')
    guard.check_ptrace_sources()
    assert ['/usr/bin/systemctl', 'start', '--no-block', '--', kg.PROFILE_UNIT] in calls
    assert guard.ptrace['sources'][0]['boot_unit_started'] is True


def test_the_unit_may_write_only_the_sysctl_paths():
    unit = Path(__file__).resolve().parents[1].joinpath('systemd/satsuma-kernel-guard.service').read_text()
    line = next(l for l in unit.splitlines() if l.startswith('ReadWritePaths='))
    assert line.split('=', 1)[1].split() == ['-/etc/sysctl.d', '-/etc/sysctl.conf', '-/run/sysctl.d',
                                             '-/usr/local/lib/sysctl.d', '-/usr/lib/sysctl.d']
    assert 'ProtectSystem=strict' in unit




def test_the_guard_checks_ptrace_and_its_sources_at_start_and_then_once_a_minute(tree, tmp_path):
    now = [0.0]
    calls = []
    guard = kg.Guard(root=proc_tree(tmp_path), runner=lambda argv, **k: calls.append(argv) or SimpleNamespace(returncode=0, stdout=''),
                     clock=lambda: now[0], wall=lambda: 1.0, state_dir=tmp_path / 'state', pm_running=lambda: False,
                     can_write=True, echo=lambda *_: None, uptime=lambda: 0, ptrace_paths=tree.paths,
                     ptrace_evidence=tmp_path / 'evidence', mount_reader=lambda: {})
    sweeps = []
    real = guard.sweep_ptrace
    guard.sweep_ptrace = lambda: sweeps.append(now[0]) or real()
    for second in range(0, 181):
        now[0] = float(second)
        guard.cycle()
    assert sweeps == [0.0, 60.0, 120.0, 180.0]
    assert guard.ptrace['status'] == 'OK'
    # A source dropped between two checks is undone at the next minute.
    attack = tree.etc / '99-late.conf'
    attack.write_text('kernel.yama.ptrace_scope = 3\n')
    now[0] = 240.0
    guard.cycle()
    assert attack.read_text().startswith('# satsuma 2.2.37') and guard.ptrace['status'] == 'SOURCE_FOUND'
