"""Recover only verified current Satsuma vendor-unit masks during installation."""
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

sys.path.insert(0,'/opt/satsuma-core')
UNITS = ('satsuma-image.service', 'satsuma-boot-lockdown.service', 'satsuma-kernel-guard.service', 'satsuma-exec-guard.service', 'satsuma-memory-hardening.service', 'satsuma-core-gateway.service', 'satsuma-core-sentinel.service', 'satsuma-app-control.service', 'satsuma-containment.service', 'satsuma-core-audit.service', 'satsuma-core-dns-refresh.service', 'satsuma-core-dns-refresh.timer', 'satsuma-core-dns.service', 'satsuma-core-finding.service', 'satsuma-core-otx.service', 'satsuma-core-security-scan.service', 'satsuma-core-security-scan.timer', 'satsuma-core-subnet.service', 'satsuma-core.service', 'satsuma-early-guard.service', 'satsuma-guardian.service', 'satsuma-integrity-check.timer', 'satsuma-network-identity.service', 'satsuma-network-modes.service', 'satsuma-network.service', 'satsuma-operator.service', 'satsuma-reader.service', 'satsuma-rescue.service', 'satsuma-self-health.service', 'satsuma-self-health.timer', 'satsuma-suricata-ips.service', 'satsuma-suricata-otx-guard.service', 'satsuma-teams.service', 'satsuma-udev.service', 'satsuma-quarantine-rollback.service', 'satsuma-quarantine-confirm.service', 'satsuma-quarantine-confirm.timer', 'satsuma-privd.service', 'satsuma-mitm-watch.service', 'satsuma-mitm-watch.timer')


def inventory(runner=subprocess.run):
    result=runner(['/usr/bin/rpm','-q','--qf','[%{FILENAMES}\t%{FILEDIGESTS}\n]','satsuma-core'],capture_output=True,text=True,timeout=20)
    if result.returncode:raise RuntimeError('Cannot verify installed service payload')
    return dict(line.split('\t',1) for line in result.stdout.splitlines() if '\t' in line)


def recover(vendor=Path('/usr/lib/systemd/system'),overrides=None,digests=None,writer=None,ownership=True):
    if overrides is None:overrides=[Path('/etc/systemd/system'),Path('/run/systemd/system')]
    if digests is None:digests=inventory()
    if writer is None:
        from satsuma.protected_storage import RootDataStore
        writer=RootDataStore('service-recovery/masks.jsonl').append
    restored=[]
    for unit in UNITS:
        source=vendor/unit
        info=source.lstat()
        if not stat.S_ISREG(info.st_mode) or (ownership and info.st_uid!=0) or info.st_mode & 0o022:
            raise PermissionError('Untrusted vendor service: '+unit)
        expected=digests.get(str(source))
        if not expected or hashlib.sha256(source.read_bytes()).hexdigest()!=expected:
            raise RuntimeError('Service differs from installed RPM digest: '+unit)
        for directory in overrides:
            if not directory.exists():continue
            parent=directory.lstat()
            if not stat.S_ISDIR(parent.st_mode) or (ownership and parent.st_uid!=0) or parent.st_mode & 0o022:
                raise PermissionError('Untrusted service override directory')
            target=directory/unit
            try:masked=target.lstat()
            except FileNotFoundError:continue
            if stat.S_ISLNK(masked.st_mode) and os.readlink(target)=='/dev/null':
                if ownership and masked.st_uid!=0:raise PermissionError('Untrusted mask owner: '+unit)
                writer({'unit':unit,'path':str(target),'previous_target':'/dev/null','time':time.time(),
                        'vendor_sha256':expected,'reason':'explicit_installation_recovery'})
                # Retain evidence before removal; never delete a real override or unknown unit.
                current=target.lstat()
                if (current.st_dev,current.st_ino)!=(masked.st_dev,masked.st_ino):raise RuntimeError('Mask changed during recovery')
                target.unlink();restored.append(str(target))
    return {'status':'CURRENT_PACKAGE_MASKS_RECOVERED','restored':restored,'unknown_units_changed':False}


if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('Root required')
    print(json.dumps(recover()))
