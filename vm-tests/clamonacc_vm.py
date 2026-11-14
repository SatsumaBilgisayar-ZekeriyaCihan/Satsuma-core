#!/usr/bin/python3
"""Explicitly enabled Fedora VM *test* for ClamAV on-access prevention.

Not a production installer. No package installation and no changes to SELinux,
networking, sysctls or other Satsuma service definitions.
"""
import argparse
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess

from vm_environment import require_vm

CONFIG = Path('/etc/clamd.d/scan.conf')
UNIT = Path('/etc/systemd/system/satsuma-clamonacc-vm.service')
BACKUP = Path('/var/lib/satsuma-core/vm-clamonacc-backup')
MARK_START = '# SATSUMA_VM_ONACCESS_START'
MARK_END = '# SATSUMA_VM_ONACCESS_END'
SERVICE = '''[Unit]
Description=Satsuma VM ClamAV on-access blocking test (test directory only)
Requires=clamd@scan.service
After=clamd@scan.service
ConditionPathExists=/var/tmp/satsuma-av-vm-test

[Service]
Type=simple
User=root
ExecStart=/usr/sbin/clamonacc --foreground --config-file=/etc/clamd.d/scan.conf --fdpass
Restart=on-failure
RestartSec=5
UMask=0077
LimitCORE=0
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/tmp/satsuma-av-vm-test
RestrictAddressFamilies=AF_UNIX
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_DAC_READ_SEARCH

[Install]
WantedBy=multi-user.target
'''
# A narrow, non-critical directory allows verifying actual blocking without
# risking a full desktop or system lock. No OnAccessMountPath /.
WATCH = Path('/var/tmp/satsuma-av-vm-test')

def cmd(*args):
    subprocess.run(args, check=True)

def regular_root_file(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1:
        raise RuntimeError('Unsafe configuration file; refusing: ' + str(path))

def parse(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'): continue
        pieces = line.split(None, 1)
        values.setdefault(pieces[0], []).append(pieces[1] if len(pieces) > 1 else '')
    return values

def render(text, username):
    if MARK_START in text or MARK_END in text:
        raise RuntimeError('Already configured for VM; do not install twice')
    vals = parse(text)
    if 'TCPSocket' in vals or 'TCPAddr' in vals or not vals.get('LocalSocket'):
        raise RuntimeError('Expected Unix-socket-only clamd@scan config')
    if any(k.startswith('OnAccess') for k in vals):
        raise RuntimeError('Existing OnAccess settings: review manually to avoid overriding')
    if vals.get('User', [username])[0] != username:
        raise RuntimeError('clamd service user mismatch')
    lines = [MARK_START, 'OnAccessIncludePath '+str(WATCH),
             'OnAccessPrevention yes', 'OnAccessExcludeUname '+username,
             'OnAccessMaxFileSize 5M', MARK_END]
    return text.rstrip() + '\n\n' + '\n'.join(lines) + '\n'

def preflight():
    # Refuse on physical hosts and containers before any filesystem or service change.
    require_vm()
    if os.geteuid() != 0: raise RuntimeError('Must run as root in isolated Fedora VM')
    regular_root_file(CONFIG)
    for exe in ('/usr/sbin/clamonacc', '/usr/sbin/clamd', '/usr/bin/systemctl'):
        if not Path(exe).is_file(): raise RuntimeError('Missing executable: '+exe)
    if UNIT.exists() or UNIT.is_symlink(): raise RuntimeError('Existing service file: refusing overwrite')
    if BACKUP.exists() or BACKUP.is_symlink(): raise RuntimeError('Existing backup: refusing overwrite')
    if WATCH.exists() or WATCH.is_symlink():
        info = WATCH.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError('Unsafe test directory')

def install():
    preflight()
    old = CONFIG.read_text()
    user = parse(old).get('User', ['clamscan'])[0]
    pwd.getpwnam(user)
    new = render(old, user)
    # No mutation if all preflight checks failed.
    BACKUP.mkdir(mode=0o700, parents=True)
    (BACKUP/'scan.conf').write_bytes(CONFIG.read_bytes())
    os.chmod(BACKUP/'scan.conf', 0o600)
    (BACKUP/'previous-enabled').write_text('yes' if subprocess.run(
        ['/usr/bin/systemctl', 'is-enabled', '--quiet', 'clamd@scan.service'],
        check=False).returncode == 0 else 'no')
    WATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = CONFIG.with_name('scan.conf.satsuma-vm-new')
    if tmp.exists() or tmp.is_symlink(): raise RuntimeError('Temporary target exists')
    try:
        with tmp.open('x') as f: f.write(new)
        os.chmod(tmp, 0o600)
        os.replace(tmp, CONFIG)
        UNIT.write_text(SERVICE)
        os.chmod(UNIT, 0o644)
        cmd('/usr/bin/systemctl', 'daemon-reload')
        cmd('/usr/bin/systemctl', 'restart', 'clamd@scan.service')
        cmd('/usr/bin/systemctl', 'enable', '--now', UNIT.name)
    except Exception:
        print('INSTALL FAILED: run rollback to restore original configuration', flush=True)
        raise
    print('ACTIVE VM TEST: OnAccessPrevention yes, scope:', WATCH)

def rollback():
    if os.geteuid() != 0: raise RuntimeError('Must run as root')
    regular_root_file(CONFIG)
    if not BACKUP.is_dir() or not (BACKUP/'scan.conf').exists():
        raise RuntimeError('No backup; refusing to alter config')
    if MARK_START not in CONFIG.read_text():
        raise RuntimeError('Configuration changed externally; manual merge needed')
    cmd('/usr/bin/systemctl', 'disable', '--now', UNIT.name)
    regular_root_file(BACKUP/'scan.conf')
    original = (BACKUP/'scan.conf').read_bytes()
    tmp = CONFIG.with_name('scan.conf.satsuma-vm-restore')
    with tmp.open('xb') as f: f.write(original)
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG)
    if UNIT.exists(): UNIT.unlink()
    cmd('/usr/bin/systemctl', 'daemon-reload')
    cmd('/usr/bin/systemctl', 'restart', 'clamd@scan.service')
    # Keep evidence and test-directory files. Do not delete operator data.
    print('Original clamd configuration restored; test directory and backup retained')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['install', 'rollback'])
    args = parser.parse_args()
    if args.action == 'install': install()
    else: rollback()
