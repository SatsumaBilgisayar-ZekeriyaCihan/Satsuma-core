from copy import deepcopy
from pathlib import Path
import pytest

from satsuma import memory_access, memory_hardening


class Backup:
    def __init__(self):
        self.value = None
        self.writes = 0
    def read(self):
        if self.value is None:
            raise FileNotFoundError()
        return deepcopy(self.value)
    def replace(self, value):
        self.value = deepcopy(value)
        self.writes += 1


@pytest.fixture
def system(tmp_path):
    for name in memory_access.POLICY:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('0\n' if name != 'kernel/core_pattern' else 'core.%p\n')
    mounts = {'/dev': {'fstype': 'devtmpfs', 'options': {'rw', 'nosuid'}},
              '/dev/shm': {'fstype': 'tmpfs', 'options': {'rw', 'nosuid', 'nodev'}}}
    before = deepcopy(mounts)
    backup = Backup()
    calls = []
    def run(args, **kwargs):
        assert backup.value is not None, 'policy changed before backup'
        calls.append(args)
        options = set(args[2].split(',')) - {'remount'}
        for restrictive, permissive in [('noexec', 'exec'), ('nosuid', 'suid'), ('nodev', 'dev')]:
            if permissive in options:
                options.remove(permissive)
                options.discard(restrictive)
        mounts[args[-1]]['options'] = options
    yield tmp_path, mounts, before, backup, run, calls


def test_apply_repeat_restore_preserves_original_policy(system):
    root, mounts, before, backup, run, _ = system
    assert memory_hardening.apply(backup, root, lambda: mounts, run)['ok']
    assert memory_access.check(root)['ok']
    assert memory_hardening.apply(backup, root, lambda: mounts, run)['ok']
    assert backup.writes == 1
    assert memory_hardening.restore(backup, root, lambda: mounts, run)['ok']
    assert mounts == before
    assert (root / 'kernel/core_pattern').read_text().strip() == 'core.%p'
    assert (root / 'kernel/yama/ptrace_scope').read_text().strip() == '0'


def test_apply_failure_rolls_back_partial_mutation(system, monkeypatch):
    root, mounts, before, backup, run, _ = system
    def failure(root):
        (root / 'kernel/core_pattern').write_text('|/usr/bin/false\n')
        raise PermissionError('simulated later sysctl failure')
    monkeypatch.setattr(memory_access, 'harden', failure)
    with pytest.raises(RuntimeError, match='original policy restored'):
        memory_hardening.apply(backup, root, lambda: mounts, run)
    assert mounts == before
    assert (root / 'kernel/core_pattern').read_text().strip() == 'core.%p'


def test_invalid_backup_cannot_supply_arbitrary_sysctl_target(system):
    root, mounts, _, backup, run, calls = system
    backup.value = {'schema': 1, 'sysctls': {'../../bad': '1'}, 'mounts': {}}
    with pytest.raises(ValueError):
        memory_hardening.restore(backup, root, lambda: mounts, run)
    assert calls == []


def test_missing_required_sysctl_causes_no_mutation(system):
    root, mounts, before, backup, run, calls = system
    (root / 'kernel/yama/ptrace_scope').unlink()
    with pytest.raises(FileNotFoundError):
        memory_hardening.apply(backup, root, lambda: mounts, run)
    assert calls == [] and backup.writes == 0
    assert mounts == before


def test_hardening_runs_after_systemd_sysctl_restores_defaults():
    # Field log 2026-10-25: systemd-sysctl started after this unit and reset
    # ptrace_scope/suid_dumpable/core_pattern, so early-guard locked response.
    unit = (Path(__file__).parents[1] / 'systemd/satsuma-memory-hardening.service').read_text()
    after = {name for line in unit.splitlines() if line.startswith('After=') for name in line[6:].split()}
    before = {name for line in unit.splitlines() if line.startswith('Before=') for name in line[7:].split()}
    assert 'systemd-sysctl.service' in after
    assert 'systemd-sysctl.service' not in before
    assert 'satsuma-early-guard.service' in before


def test_sysctl_d_file_keeps_the_same_values_across_systemd_sysctl_runs():
    # systemd-sysctl reruns on systemd updates and "sysctl --system"; the
    # values must come from its own configuration, not only from our unit.
    from satsuma import memory_access
    root = Path(__file__).parents[1]
    conf = (root / 'packaging/root/usr/lib/sysctl.d/90-satsuma-memory.conf').read_text()
    values = dict(line.split(' = ', 1) for line in conf.splitlines() if line and not line.startswith('#'))
    assert values == {name.replace('/', '.'): value for name, value in memory_access.POLICY.items()}
    assert '/usr/lib/sysctl.d/90-satsuma-memory.conf' in (root / 'packaging/satsuma-core.spec').read_text()
