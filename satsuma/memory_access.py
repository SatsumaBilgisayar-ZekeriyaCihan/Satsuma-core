"""Early-boot limits on cross-process memory access and memory disclosure."""
import ctypes
from pathlib import Path

POLICY = {'kernel/yama/ptrace_scope': '2', 'kernel/kptr_restrict': '2',
          'kernel/dmesg_restrict': '1', 'fs/suid_dumpable': '0',
          'kernel/core_pattern': '|/usr/bin/false'}


def check(root=Path('/proc/sys')):
    rows = {}
    for name, expected in POLICY.items():
        try:
            actual = (root / name).read_text().strip()
            ok = actual == expected or (name == 'kernel/yama/ptrace_scope' and actual == '3')
            rows[name] = {'ok': ok, 'actual': actual, 'required': expected}
        except OSError as exc:
            rows[name] = {'ok': False, 'error': type(exc).__name__}
    return {'ok': all(row['ok'] for row in rows.values()), 'controls': rows}


def harden(root=Path('/proc/sys')):
    # Inspect availability first; no silently skipped controls or weakening of
    # a pre-existing ptrace_scope=3 policy.
    values = {name: (root / name).read_text().strip() for name in POLICY}
    for name, expected in POLICY.items():
        if name == 'kernel/yama/ptrace_scope' and values[name] == '3':
            continue
        if values[name] != expected:
            (root / name).write_text(expected + '\n')
    result = check(root)
    if not result['ok']:
        raise RuntimeError('Memory access policy readback failed')
    return result


def protect_self():
    """Make the Satsuma daemon non-dumpable; do not alter other processes."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise OSError(ctypes.get_errno(), 'Cannot disable process dumpability')
    if libc.prctl(3, 0, 0, 0, 0) != 0:  # PR_GET_DUMPABLE
        raise RuntimeError('Process remains dumpable')
