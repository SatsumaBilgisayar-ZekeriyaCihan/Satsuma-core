"""Strictest kernel profile: its pattern, the boot command line and the guard putting it back.

En sıkı çekirdek profili: deseni, açılış komut satırı ve bekçinin geri koyması.
"""
import json
from pathlib import Path
from types import SimpleNamespace

from satsuma import kernel_guard as kg
from satsuma import kernel_profile as kp

ROOT = Path(__file__).resolve().parents[1]


def test_ptrace_stays_two_and_strict_keys_join_the_guard_table(tmp_path):
    table = kg.table(tmp_path)
    assert table['kernel/yama/ptrace_scope'] == '2'
    assert all(table[k] == v for k, v in kp.STRICT.items())
    assert 'kernel/modules_disabled' not in table   # applied late, never at boot
    assert all(kg._KEY.fullmatch(k) for k in kp.STRICT)


def test_stricter_values_are_accepted_weaker_are_restored(tmp_path):
    assert kg._acceptable('kernel/unprivileged_bpf_disabled', '2', '1')
    assert not kg._acceptable('kernel/unprivileged_bpf_disabled', '0', '1')
    assert not kg._acceptable('kernel/perf_event_paranoid', '2', '3')
    path = tmp_path / 'user/max_user_namespaces'
    path.parent.mkdir(parents=True)
    path.write_text('63000\n')
    result = kg.restore([{'key': 'user/max_user_namespaces', 'expected': '0', 'actual': '63000'}], tmp_path)
    assert result['failed'] == [] and path.read_text() == '0\n'


def test_shipped_sysctl_file_is_the_generated_profile():
    shipped = (ROOT / 'packaging/root' / kp.SYSCTL_FILE).read_text()
    assert shipped == kp.sysctl_text() and 'modules_disabled' not in shipped.split('\n', 3)[3]
    assert '/usr/lib/sysctl.d/93-satsuma-strict.conf' in (ROOT / 'packaging/satsuma-core.spec').read_text()


def test_pattern_is_saved_and_a_changed_pattern_is_rewritten(tmp_path):
    path = tmp_path / 'profile.json'
    assert kp.save_pattern(path) == 'saved'
    assert kp.save_pattern(path) == 'unchanged'
    weakened = json.loads(path.read_text())
    weakened['sysctl']['user/max_user_namespaces'] = '63000'
    path.write_text(json.dumps(weakened))
    assert kp.save_pattern(path) == 'rewritten'
    assert json.loads(path.read_text()) == kp.pattern()


def test_unsigned_module_holds_back_lockdown_only(tmp_path):
    modules = tmp_path / 'modules'
    modules.write_text('nvidia 1 0 - Live 0x0 (POE)\next4 2 1 - Live 0x0\n')
    assert kp.unsigned_modules(modules) == ['nvidia']
    assert kp.wanted_args(['nvidia']) == [a for a in kp.CMDLINE if a != kp.LOCKDOWN]
    assert kp.wanted_args([]) == list(kp.CMDLINE)


class Grubby:
    def __init__(self, args):
        self.entries = {'/boot/vmlinuz-6.17': set(args), '/boot/vmlinuz-6.18': {'ro', 'rhgb'}}
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[0].endswith('grubby') and argv[1] == '--info=ALL':
            out = ''.join(f'index=0\nkernel="{k}"\nargs="{" ".join(sorted(v))}"\n' for k, v in self.entries.items())
            return SimpleNamespace(returncode=0, stdout=out, stderr='')
        if argv[0].endswith('grubby') and argv[1] == '--update-kernel=ALL':
            for words in self.entries.values():
                words.update(argv[2].split('=', 1)[1].split())
        return SimpleNamespace(returncode=0, stdout='', stderr='')


def test_a_new_kernel_gets_the_profile_words(tmp_path):
    grubby = Grubby(kp.CMDLINE)
    modules = tmp_path / 'modules'
    modules.write_text('ext4 2 1 - Live 0x0\n')
    result = kp.apply_boot(grubby, modules)
    assert result['updated_kernels'] == ['/boot/vmlinuz-6.18']
    assert all(set(kp.CMDLINE) <= words for words in grubby.entries.values())
    assert kp.apply_boot(grubby, modules)['updated_kernels'] == []


def make_guard(tmp_path, runner, uptime, modules_disabled='0'):
    root = tmp_path / 'sys'
    (root / 'kernel').mkdir(parents=True)
    (root / 'kernel/modules_disabled').write_text(modules_disabled + '\n')
    modules = tmp_path / 'modules'
    modules.write_text('ext4 2 1 - Live 0x0\n')
    return kg.Guard(root=root, runner=runner, clock=lambda: 0.0, wall=lambda: 1.0, state_dir=tmp_path / 'state',
                    pm_running=lambda: False, can_write=True, echo=lambda *_: None, uptime=lambda: uptime,
                    modules_path=modules)


def test_guard_restarts_module_lock_after_boot_and_puts_boot_words_back(tmp_path):
    grubby = Grubby(kp.CMDLINE)
    guard = make_guard(tmp_path, grubby, uptime=600)
    guard.check_boot()
    started = [c[-1] for c in grubby.calls if c[0].endswith('systemctl')]
    assert started == [kp.MODULE_LOCK_UNIT, kg.PROFILE_UNIT]
    assert guard.boot['status'] == 'CHANGED' and '/boot/vmlinuz-6.18' in guard.boot['missing']
    assert json.loads((tmp_path / 'state/profile.json').read_text()) == kp.pattern()


def test_guard_waits_for_boot_to_settle_before_locking_modules(tmp_path):
    grubby = Grubby(kp.CMDLINE)
    grubby.entries['/boot/vmlinuz-6.18'] = set(kp.CMDLINE)
    guard = make_guard(tmp_path, grubby, uptime=30)
    guard.check_boot()
    assert not [c for c in grubby.calls if c[0].endswith('systemctl')] and guard.boot['status'] == 'OK'
