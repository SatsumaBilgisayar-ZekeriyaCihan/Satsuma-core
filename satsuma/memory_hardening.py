"""Apply boot controls after retaining the pre-install policy for rollback."""
import subprocess
from pathlib import Path

from . import memory_access, memory_mounts
from .protected_storage import RootDataStore


def apply(backup=None, sys_root=Path('/proc/sys'), mount_reader=memory_mounts.mount_table,
          runner=subprocess.run):
    if backup is None:
        backup = RootDataStore('memory-hardening/initial.json')
    try:
        original = backup.read()
    except FileNotFoundError:
        mounts = mount_reader()
        # Fail before mutation when prerequisites are missing.
        for target, (fstype, _) in memory_mounts.POLICY.items():
            if mounts.get(target, {}).get('fstype') != fstype:
                raise RuntimeError('Unexpected memory mount type: ' + target)
        original = {'schema': 1, 'sysctls': {
            name: (sys_root / name).read_text().strip() for name in memory_access.POLICY},
            'mounts': {target: {'fstype': mounts[target]['fstype'],
                               'options': sorted(mounts[target]['options'])}
                       for target in memory_mounts.POLICY}}
        backup.replace(original)
    validate_backup(original)
    try:
        mounts = memory_mounts.harden(reader=mount_reader, runner=runner)
        access = memory_access.harden(root=sys_root)
    except Exception as exc:
        try:
            restore(backup=backup, sys_root=sys_root, mount_reader=mount_reader, runner=runner)
        except Exception as rollback_error:
            raise RuntimeError('Memory hardening failed; rollback also failed: '
                               + str(rollback_error)) from exc
        raise RuntimeError('Memory hardening failed; original policy restored') from exc
    return {'ok': True, 'mounts': mounts, 'access': access,
            'rollback_saved': True}


def validate_backup(value):
    if (not isinstance(value, dict) or value.get('schema') != 1
            or set(value.get('sysctls', {})) != set(memory_access.POLICY)
            or set(value.get('mounts', {})) != set(memory_mounts.POLICY)):
        raise ValueError('Invalid memory-hardening backup')
    for name, item in value['sysctls'].items():
        if not isinstance(item, str) or '\n' in item or len(item) > 4096:
            raise ValueError('Invalid saved sysctl')
    for name, row in value['mounts'].items():
        if (row.get('fstype') != memory_mounts.POLICY[name][0]
                or not isinstance(row.get('options'), list)
                or not row['options']
                or any(not isinstance(x, str) or not x or ',' in x or '\n' in x
                       for x in row['options'])):
            raise ValueError('Invalid saved mount policy')


def restore(backup=None, sys_root=Path('/proc/sys'), mount_reader=memory_mounts.mount_table,
            runner=subprocess.run):
    if backup is None:
        backup = RootDataStore('memory-hardening/initial.json')
    original = backup.read()
    validate_backup(original)
    mounts = mount_reader()
    for target, row in original['mounts'].items():
        if mounts.get(target, {}).get('fstype') != row['fstype']:
            raise RuntimeError('Mount type changed; refusing rollback: ' + target)
    # Fail on an unreadable control or irreversible Yama scope BEFORE any
    # remount changes protection. Recheck immediately before each write too.
    # Okunamayan kontrol veya geri alınamaz Yama durumunu remount öncesi reddet.
    current_values = {name: (sys_root / name).read_text().strip()
                      for name in original['sysctls']}
    if (current_values.get('kernel/yama/ptrace_scope') == '3'
            and original['sysctls'].get('kernel/yama/ptrace_scope') != '3'):
        raise RuntimeError('ptrace_scope=3 cannot be relaxed until reboot')
    for target, row in original['mounts'].items():
        flags = set(row['options'])
        # Remount flags may preserve old restrictive flags if their inverses
        # are absent. Explicitly restore each modified flag's old state.
        for flag, inverse in (('noexec', 'exec'), ('nosuid', 'suid'), ('nodev', 'dev')):
            if flag not in flags:
                flags.add(inverse)
        runner(['/usr/bin/mount', '-o', 'remount,' + ','.join(sorted(flags)), target],
               check=True, capture_output=True, text=True, timeout=15)
    for name, value in original['sysctls'].items():
        path = sys_root / name
        current = path.read_text().strip()
        if name == 'kernel/yama/ptrace_scope' and current == '3' and value != '3':
            raise RuntimeError('ptrace_scope=3 cannot be relaxed until reboot')
        if current != value:
            path.write_text(value + '\n')
    actual = mount_reader()
    for target, row in original['mounts'].items():
        for flag in ('noexec', 'nosuid', 'nodev'):
            if (flag in actual[target]['options']) != (flag in row['options']):
                raise RuntimeError('Mount rollback readback failed: ' + target)
    if any((sys_root / name).read_text().strip() != value
           for name, value in original['sysctls'].items()):
        raise RuntimeError('Sysctl rollback readback failed')
    return {'ok': True, 'status': 'ORIGINAL_MEMORY_POLICY_RESTORED'}
