"""Early-boot execution restrictions for device and shared-memory mounts."""
from pathlib import Path
import subprocess

POLICY = {'/dev': ('devtmpfs', {'nosuid', 'noexec'}),
          '/dev/shm': ('tmpfs', {'nosuid', 'nodev', 'noexec'})}


def mount_table(path=Path('/proc/self/mountinfo')):
    result = {}
    for line in path.read_text().splitlines():
        fields = line.split()
        separator = fields.index('-')
        target = fields[4].replace('\\040', ' ').replace('\\134', '\\')
        result[target] = {'fstype': fields[separator + 1],
                          'options': set(fields[5].split(','))}
    return result


def check(reader=mount_table):
    mounts = reader()
    rows = {}
    for target, (fstype, required) in POLICY.items():
        observed = mounts.get(target, {})
        options = observed.get('options', set())
        rows[target] = {'ok': observed.get('fstype') == fstype and required <= options,
                        'fstype': observed.get('fstype'),
                        'missing_options': sorted(required - options)}
    return {'ok': all(row['ok'] for row in rows.values()), 'mounts': rows}


def harden(reader=mount_table, runner=subprocess.run):
    mounts = reader()
    # Validate both destinations before making any changes. /dev must retain
    # device operation: nodev is deliberately never added to devtmpfs.
    for target, (fstype, _) in POLICY.items():
        if mounts.get(target, {}).get('fstype') != fstype:
            raise RuntimeError('Unexpected memory mount type: ' + target)
    for target, (_, required) in POLICY.items():
        options = mounts[target]['options']
        if not required <= options:
            runner(['/usr/bin/mount', '-o', 'remount,' + ','.join(sorted(options | required)),
                    target], check=True, capture_output=True, text=True, timeout=15)
    result = check(reader)
    if not result['ok']:
        raise RuntimeError('Memory mount hardening readback failed: ' + str(result))
    return result
