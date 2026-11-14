"""Refuse an IPS binary without NFQ support or a usable detection rule set.

Before the check, Satsuma's own Suricata configuration is generated from
the system suricata.yaml (satsuma.suricata_config, 2.2.30) and checked; the
IPS runs with it.

NFQ desteği ya da kullanılabilir kural seti olmayan IPS reddedilir. Kontrolden
önce sistemdeki suricata.yaml'dan Satsuma'nın kendi Suricata yapılandırması
üretilir ve denenir (satsuma.suricata_config, 2.2.30); IPS onunla çalışır.
"""
import re
import os
import stat
from pathlib import Path
import subprocess
import sys

BINARY='/usr/bin/suricata'
CONFIG='/etc/suricata/suricata.yaml'
FLAGS=['--set','stream.inline=yes','--set','stream.bypass=no',
       '--set','nfq.mode=accept','--set','nfq.fail-open=no']


def verify(runner=subprocess.run, binary=BINARY, config=CONFIG):
    if runner is subprocess.run:
        path=Path(binary).resolve(strict=True)
        for entry in (path, *path.parents):
            info=entry.lstat()
            if info.st_uid!=0 or info.st_mode & 0o022:
                raise RuntimeError('Unsafe Suricata executable path: '+str(entry))
        if not stat.S_ISREG(path.stat().st_mode) or path.stat().st_nlink!=1:
            raise RuntimeError('Suricata must be a protected regular executable')
    version=runner([binary,'-V'],capture_output=True,text=True,timeout=15,check=True)
    match=re.search(r'Suricata version (\d+)\.',version.stdout+getattr(version,'stderr',''))
    if not match or int(match.group(1))<7:
        raise RuntimeError('Suricata version 7 or newer required')
    build=runner([binary,'--build-info'],capture_output=True,text=True,timeout=15,check=True)
    if not re.search(r'NFQueue support:\s+yes\b',build.stdout):
        raise RuntimeError('Suricata binary has no NFQUEUE support')
    tested=runner([binary,'-T','-v','--init-errors-fatal','-c',config,*FLAGS],
                  capture_output=True,text=True,timeout=90)
    output=tested.stdout+tested.stderr
    if tested.returncode or not re.search(r'\b[1-9][0-9]* rules successfully loaded\b',output):
        raise RuntimeError('Suricata rule validation failed or no detection rules were loaded: '+output[-3000:])
    return {'status':'configuration_checked','host_cleanliness_verified':False}


def prepare():
    sys.path.insert(0,'/opt/satsuma-core')
    from satsuma.suricata_config import generate, GENERATED
    generated=generate(test=lambda path:verify(config=str(path)))
    print(generated)
    return verify(config=str(GENERATED))


if __name__=='__main__':
    try:
        print(prepare())
    except Exception as exc:
        print(str(exc),file=sys.stderr)
        raise SystemExit(1)
