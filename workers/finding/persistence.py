"""Read-only slow persistence surface inventory, explicitly non-authoritative.

Neither the existence of a sysfs node nor a D-Bus object proves physical
hardware exists. This module only yields candidates for later corroboration.
"""
from __future__ import annotations
import hashlib
import json
import os
import stat
from pathlib import Path

UNIT_DIRS = ('/etc/systemd/system', '/usr/lib/systemd/system', '/run/systemd/system')
UDEV_DIRS = ('/etc/udev/rules.d', '/usr/lib/udev/rules.d', '/run/udev/rules.d')
MAX_ENTRIES = 4096


def _files(paths, suffixes):
    entries = []
    incomplete = False
    for root in paths:
        path = Path(root)
        if not path.is_dir():
            continue
        try:
            for item in path.iterdir():
                if item.suffix not in suffixes:
                    continue
                if len(entries) >= MAX_ENTRIES:
                    incomplete = True
                    break
                try:
                    info = item.lstat()
                    # No file contents, symlink traversal, command lines or secrets.
                    entries.append({'path': str(item), 'uid': info.st_uid,
                                    'mode': stat.S_IMODE(info.st_mode),
                                    'type': 'symlink' if stat.S_ISLNK(info.st_mode) else
                                            'file' if stat.S_ISREG(info.st_mode) else 'other',
                                    'writable_by_nonowner': bool(info.st_mode & 0o022)})
                except OSError:
                    incomplete = True
        except OSError:
            incomplete = True
    return entries, incomplete


def inventory(unit_dirs=UNIT_DIRS, udev_dirs=UDEV_DIRS):
    units, u_missing = _files(unit_dirs, ('.service', '.socket', '.timer', '.path'))
    udev, d_missing = _files(udev_dirs, ('.rules',))
    entries = sorted(units + udev, key=lambda item: item['path'])
    fingerprint = hashlib.sha256(json.dumps(entries, sort_keys=True).encode()).hexdigest()
    return {'status': 'INCOMPLETE' if u_missing or d_missing else 'INVENTORIED',
            'trust': 'local_filesystem_unverified', 'enforcement': False,
            'entries': len(entries), 'fingerprint': fingerprint,
            'world_or_group_writable': [x['path'] for x in entries if x['writable_by_nonowner']][:128],
            'note': 'Inventory is not malware attribution or proof of physical devices'}
