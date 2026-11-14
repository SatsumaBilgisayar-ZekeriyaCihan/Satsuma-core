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


def enroll_user(user, runner=subprocess.run):
    import pwd
    if pwd.getpwnam(user).pw_uid==0:raise ValueError('A normal desktop user is required')
    provision()
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
