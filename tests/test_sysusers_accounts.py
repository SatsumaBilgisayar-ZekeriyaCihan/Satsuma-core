"""Real account creation is confined to a disposable --root directory."""
from pathlib import Path
import shutil
import subprocess
import pytest

ROOT=Path(__file__).parents[1]
CONFIG=ROOT/'packaging/root/usr/lib/sysusers.d/satsuma-core.conf'


def test_rpm_embeds_the_installed_sysusers_configuration_exactly():
    spec=(ROOT/'packaging/satsuma-core.spec').read_text()
    embedded=spec.split("<<'SATSUMA_SYSUSERS'\n",1)[1].split('SATSUMA_SYSUSERS\n',1)[0]
    assert embedded==CONFIG.read_text()
    assert 'Requires(pre): /usr/bin/systemd-sysusers' in spec


@pytest.mark.parametrize('existing',[False,True])
def test_real_sysusers_creates_required_accounts_idempotently_and_preserves_existing_ids(tmp_path,existing):
    binary=shutil.which('systemd-sysusers')
    if not binary:pytest.fail('systemd-sysusers required for the account integration test')
    etc=tmp_path/'etc';etc.mkdir()
    passwd='root:x:0:0:root:/root:/bin/sh\n'
    groups='root:x:0:\n'
    if existing:
        passwd+='satsuma-core:x:872:873:Existing Core:/var/lib/satsuma-core:/usr/sbin/nologin\n'
        groups+='satsuma-core:x:873:\n'
    (etc/'passwd').write_text(passwd);(etc/'group').write_text(groups)
    args=[binary,'--root='+str(tmp_path),'--replace=/usr/lib/sysusers.d/satsuma-core.conf','-']
    subprocess.run(args,input=CONFIG.read_text(),text=True,capture_output=True,check=True)
    users={line.split(':')[0]:line.split(':') for line in (etc/'passwd').read_text().splitlines()}
    groups={line.split(':')[0]:line.split(':') for line in (etc/'group').read_text().splitlines()}
    assert {'satsuma-dns','satsuma-core'}<=users.keys()
    assert {'satsuma-dns','satsuma-core','satsuma-reader'}<=groups.keys()
    assert users['satsuma-dns'][3]==groups['satsuma-dns'][2]
    if existing:assert users['satsuma-core'][2:4]==['872','873']
    before={p.name:p.read_bytes() for p in etc.iterdir() if p.name in ('passwd','group')}
    private={p.name:(p.stat().st_mode,p.stat().st_size,p.stat().st_mtime_ns,p.stat().st_ino)
        for p in etc.iterdir() if p.name in ('shadow','gshadow')}
    subprocess.run(args,input=CONFIG.read_text(),text=True,capture_output=True,check=True)
    assert before=={name:(etc/name).read_bytes() for name in before}
    assert private=={name:((etc/name).stat().st_mode,(etc/name).stat().st_size,
        (etc/name).stat().st_mtime_ns,(etc/name).stat().st_ino) for name in private}


def test_account_creation_failure_aborts_before_payload_preparation(tmp_path):
    pre=(ROOT/'packaging/satsuma-core.spec').read_text().split('%pre\n',1)[1].split('%preun\n',1)[0]
    # Retain the real precheck and account control flow; replace the following
    # directory/service mutations with a sentinel in this disposable test.
    pre=pre.split('# Runs before RPM extracts the payload.',1)[0]+'echo payload-stage >> "$TEST_LOG"\n'
    python=tmp_path/'python';sysusers=tmp_path/'sysusers'
    python.write_text('#!/bin/sh\ncat >/dev/null\necho precheck >> "$TEST_LOG"\n')
    sysusers.write_text('#!/bin/sh\ncat >/dev/null\necho accounts >> "$TEST_LOG"\necho "Permission denied" >&2\nexit 1\n')
    python.chmod(0o755);sysusers.chmod(0o755)
    pre=pre.replace('/usr/bin/python3',str(python)).replace('/usr/bin/systemd-sysusers',str(sysusers))
    log=tmp_path/'calls'
    result=subprocess.run(['/bin/bash','-c',pre],env={'PATH':'/usr/bin:/bin','TEST_LOG':str(log)},capture_output=True,text=True)
    assert result.returncode!=0
    assert 'SATSUMA_ACCOUNT_SETUP_FAILED' in result.stderr
    assert log.read_text().splitlines()==['precheck','accounts']
