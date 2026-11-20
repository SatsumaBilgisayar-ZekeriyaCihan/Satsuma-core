"""Permanent hidepid for /proc, switched by the owner (satsuma-admin hidepid ac|kapat|durum).

With hidepid=invisible a user sees only their own processes in /proc: a program running as the
owner cannot list or read root's or other users' processes. Field 2026-11-20: the owner set it at
run time and it was gone after the reboot; the scan then reported 1456 "hidden" processes because
unhide could no longer see the owner's processes from the scan service.

Switching it on writes:
- /etc/fstab: proc /proc proc nosuid,nodev,noexec,hidepid=invisible,gid=<satsuma-proc> 0 0
- drop-ins giving the services that must see every process the satsuma-proc group: polkit
  (password prompts), systemd-logind (sessions), rtkit-daemon (audio priority), NetworkManager,
  cosmic-greeter (log-in screen) and Satsuma's scan (unhide).
It takes effect at the next reboot, so nothing running loses sight of a process half way.
Red Hat warns that hidepid is not fully compatible with systemd; the group drop-ins cover the
known cases. If something breaks: sudo satsuma-admin hidepid kapat, then reboot.

hidepid kalıcı: kullanıcı yalnız kendi süreçlerini görür. Bir sonraki açılışta geçerli olur.
"""
import grp
import os
import re
from pathlib import Path

FSTAB = Path('/etc/fstab')
UNIT_ETC = Path('/etc/systemd/system')
GROUP = 'satsuma-proc'
DROPIN = '90-satsuma-proc.conf'
SEES_ALL = ('polkit.service', 'systemd-logind.service', 'rtkit-daemon.service', 'NetworkManager.service',
            'cosmic-greeter.service', 'satsuma-core-security-scan.service', 'satsuma-core-security-scan-now.service')
MARK = '# satsuma hidepid'
_PROC_LINE = re.compile(r'^\s*\S+\s+/proc\s+proc\s')


def fstab_line(gid):
    return f'proc /proc proc nosuid,nodev,noexec,hidepid=invisible,gid={int(gid)} 0 0  {MARK}\n'


def configured(fstab=FSTAB):
    try:
        return any(MARK in line for line in Path(fstab).read_text().splitlines())
    except OSError:
        return False


def active(mounts=Path('/proc/self/mountinfo')):
    try:
        for line in Path(mounts).read_text().splitlines():
            fields = line.split()
            if len(fields) > 4 and fields[4] == '/proc' and ' - proc ' in line:
                return 'hidepid=' in line and 'hidepid=0' not in line and 'hidepid=off' not in line
    except OSError:
        pass
    return False


def _write(path, text, mode=0o644):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.satsuma-tmp')
    tmp.write_text(text)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def enable(fstab=FSTAB, unit_etc=UNIT_ETC, group_lookup=grp.getgrnam):
    gid = group_lookup(GROUP).gr_gid
    try:
        lines = Path(fstab).read_text().splitlines(True)
    except FileNotFoundError:
        lines = []
    kept = [line for line in lines if MARK not in line and not _PROC_LINE.match(line)]
    _write(fstab, ''.join(kept) + fstab_line(gid))
    text = ('# Satsuma: sees every process while /proc uses hidepid (satsuma-admin hidepid).\n'
            f'[Service]\nSupplementaryGroups={GROUP}\n')
    for unit in SEES_ALL:
        _write(Path(unit_etc) / (unit + '.d') / DROPIN, text)
    return {'gid': gid, 'units': list(SEES_ALL)}


def disable(fstab=FSTAB, unit_etc=UNIT_ETC):
    try:
        lines = Path(fstab).read_text().splitlines(True)
    except FileNotFoundError:
        lines = []
    _write(fstab, ''.join(line for line in lines if MARK not in line))
    for unit in SEES_ALL:
        try:
            (Path(unit_etc) / (unit + '.d') / DROPIN).unlink()
        except FileNotFoundError:
            pass
