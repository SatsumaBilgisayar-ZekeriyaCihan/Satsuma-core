"""RPM payload validation and automatic application verification."""
import fcntl
import hashlib
import hmac
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

# Used with python -I -B, independently of the caller's cwd and environment.
ROOT = Path('/opt/satsuma-core')
sys.path.insert(0, str(ROOT))


def verify_payload(root=Path('/usr/lib/satsuma-core/payload'), runner=subprocess.run):
    """Trust only RPM-listed files with their RPM-recorded content and modes."""
    query = runner(
        ['/usr/bin/rpm', '-q', '--qf',
         '[%{FILENAMES}\t%{FILEMODES:octal}\t%{FILEDIGESTS}\n]', 'satsuma-core'],
        capture_output=True, text=True, check=True, timeout=60,
    )
    expected = {}
    for line in query.stdout.splitlines():
        name, mode, digest = line.split('\t')
        path = Path(name)
        if path == root or root in path.parents:
            expected[path] = (int(mode, 8), digest)
    actual = {root, *(p for p in root.rglob('*')
                     if '__pycache__' not in p.relative_to(root).parts and p.suffix not in ('.pyc', '.pyo'))}
    if not expected or actual != set(expected):
        extra = sorted(str(p) for p in actual - set(expected))
        missing = sorted(str(p) for p in set(expected) - actual)
        raise RuntimeError(f'RPM file inventory mismatch: extra={extra[:20]}, missing={missing[:20]}')
    for path, (mode, digest) in expected.items():
        info = path.lstat()
        if (info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022
                or info.st_mode != mode or path.is_symlink()):
            raise PermissionError('Unsafe RPM file: ' + str(path))
        if stat.S_ISREG(mode):
            if info.st_nlink != 1 or len(digest) != 64:
                raise PermissionError('Unsafe RPM digest/file: ' + str(path))
            if not hmac.compare_digest(hashlib.sha256(path.read_bytes()).hexdigest(), digest):
                raise RuntimeError('RPM content mismatch: ' + str(path))
        elif not stat.S_ISDIR(mode):
            raise PermissionError('Unexpected RPM file type: ' + str(path))
    return len(expected)


def provision():
    from installer.integrity import verify
    return {'status':'APPLICATION_VERIFIED','files':verify()}


def ensure_local_group(name, etc_group='/etc/group', etc_gshadow='/etc/gshadow', lib_group='/usr/lib/group',
                       lock='/etc/.pwd.lock'):
    """Copy a group kept only in /usr/lib/group into /etc/group before usermod edits it.

    2.2.41 (owner, Fedora Atomic 2026-11-18: the panel asked for a password and
    closed): rpm-ostree keeps the groups packages create in /usr/lib/group
    (nss-altfiles); shadow-utils' usermod edits only /etc/group and fails with
    "group does not exist", so desktop enrollment failed. The line is appended
    under the same lock shadow-utils takes, in place (the files keep their
    SELinux labels). Returns 'present', 'copied' or 'absent'.
    Atomic'te paket grupları /usr/lib/group'tadır; usermod yalnızca /etc/group'u
    düzenler. Satır usermod'dan önce /etc/group'a kopyalanır.
    """
    import fcntl
    def has(path):
        try:
            return any(line.split(':',1)[0]==name for line in Path(path).read_text().splitlines())
        except FileNotFoundError:
            return False
    if has(etc_group):
        return 'present'
    try:
        line=next((l for l in Path(lib_group).read_text().splitlines() if l.split(':',1)[0]==name),None)
    except FileNotFoundError:
        line=None
    if line is None:
        return 'absent'
    fd=os.open(lock,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.lockf(fd,fcntl.LOCK_EX)
        for path,entry in ((etc_group,line),(etc_gshadow,name+':!::')):
            if path==etc_gshadow and not Path(path).exists():
                continue
            if has(path):
                continue
            with open(path,'r+') as stream:
                text=stream.read()
                stream.write(('' if not text or text.endswith('\n') else '\n')+entry+'\n')
                stream.flush();os.fsync(stream.fileno())
    finally:
        os.close(fd)
    return 'copied'


def enroll_user(user, runner=subprocess.run):
    import pwd
    if pwd.getpwnam(user).pw_uid==0:raise ValueError('A normal desktop user is required')
    provision()
    ensure_local_group('satsuma-reader')
    runner(['/usr/sbin/usermod','-a','-G','satsuma-reader',user],check=True,timeout=60)
    provision()


def main():
    if os.geteuid() != 0:
        raise PermissionError('Boot setup requires root')
    if sys.argv[1:] == ['--verify-payload']:
        print('RPM inventory verified:', verify_payload())
    elif sys.argv[1:] == ['--memory-encryption-status']:
        import json
        from satsuma.hardware_memory import inspect
        print(json.dumps(inspect(), ensure_ascii=False, indent=2))
    elif sys.argv[1:] == ['--check-memory']:
        import json
        from satsuma.memory_access import check as check_access
        from satsuma.memory_mounts import check as check_mounts
        result = {'access': check_access(), 'mounts': check_mounts()}
        result['ok'] = all(row['ok'] for row in result.values())
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result['ok'] else 1
    elif sys.argv[1:] == ['--harden-memory']:
        from satsuma.memory_hardening import apply
        print(apply())
    elif sys.argv[1:] == ['--ipv6-off']:
        from satsuma.ipv6_off import apply
        print(apply())
    elif sys.argv[1:] == ['--restore-memory']:
        from satsuma.memory_hardening import restore
        print(restore())
    elif sys.argv[1:] == ['--guard']:
        from satsuma.early_guard import main as guard
        return guard()
    elif len(sys.argv) == 3 and sys.argv[1] == '--enroll-user':
        os.umask(0o077)
        enroll_user(sys.argv[2])
    elif not sys.argv[1:]:
        # Keep verification output private.
        os.umask(0o077)
        print(provision()['status'])
    else:
        raise ValueError('Unknown boot setup option')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print('SATSUMA BOOT SETUP FAILED: '+str(exc), file=sys.stderr)
        raise SystemExit(1)
