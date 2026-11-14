"""Verified post-exec Python entry identity for App Control.

The fanotify exec permission event precedes execve: its /proc/<pid>/cmdline
can still describe the *previous* image. This resolver MUST NOT run there.
Only use it after a process has started, and treat a script as verified only
when its descriptor and the process identity remain stable.
"""
import hashlib
import os
from pathlib import Path

MAX_SCRIPT_BYTES = 8 * 1024 * 1024


def _python_executable(path):
    return Path(path).name.lower().startswith(('python', 'pypy'))


def resolve(proc, executable, *, max_bytes=MAX_SCRIPT_BYTES):
    """Return minimal non-secret script identity or an explicit unknown reason.

    Source, not command line, is hashed. Never serialize -c source/arguments.
    An -m module is reported as unverified: import resolution can differ.
    """
    if not _python_executable(executable):
        return None
    try:
        before = (proc.pid, proc.create_time(), proc.exe(), proc.cwd())
        argv = proc.cmdline()
        if not argv:
            return {'status': 'unverified', 'reason': 'missing_cmdline'}
        args = argv[1:]
        i = 0
        while i < len(args):
            arg = args[i]
            if arg in ('-c', '-m'):
                return {'status': 'unverified', 'reason': 'command_or_module'}
            if arg in ('-W', '-X'):
                i += 2
                continue
            if arg.startswith(('-W', '-X')) or arg in ('-B', '-E', '-I', '-O', '-OO', '-s', '-S', '-u', '-v', '-q', '-x', '-P'):
                i += 1
                continue
            if arg == '--':
                i += 1
                break
            if arg.startswith('-'):
                return {'status': 'unverified', 'reason': 'unknown_option'}
            break
        if i >= len(args) or args[i] in ('-', ''):
            return {'status': 'unverified', 'reason': 'stdin_or_interactive'}
        target = args[i]
        if '\x00' in target:
            return {'status': 'unverified', 'reason': 'invalid_path'}
        target = os.path.normpath(target if os.path.isabs(target) else os.path.join(before[3], target))
        if not target.startswith('/'):
            return {'status': 'unverified', 'reason': 'invalid_path'}
        # /proc/PID/root addresses the target process mount namespace.
        # O_NOFOLLOW rejects final-component symlinks; limits bound the work.
        fd = os.open('/proc/%d/root%s' % (proc.pid, target), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            st1 = os.fstat(fd)
            import stat
            if not stat.S_ISREG(st1.st_mode) or st1.st_size > max_bytes:
                return {'status': 'unverified', 'reason': 'not_small_regular_file'}
            digest = hashlib.sha256()
            total = 0
            while True:
                part = os.read(fd, 65536)
                if not part: break
                total += len(part)
                if total > max_bytes:
                    return {'status': 'unverified', 'reason': 'size_limit'}
                digest.update(part)
            st2 = os.fstat(fd)
            identity = (st1.st_dev, st1.st_ino, st1.st_size, st1.st_mtime_ns, st1.st_ctime_ns)
            if identity != (st2.st_dev, st2.st_ino, st2.st_size, st2.st_mtime_ns, st2.st_ctime_ns):
                return {'status': 'unverified', 'reason': 'script_changed'}
        finally:
            os.close(fd)
        if (proc.pid, proc.create_time(), proc.exe(), proc.cwd()) != before or proc.cmdline() != argv:
            return {'status': 'unverified', 'reason': 'process_changed'}
        return {'status': 'verified', 'path': target, 'sha256': digest.hexdigest(),
                'device': st2.st_dev, 'inode': st2.st_ino}
    except (OSError, ValueError, IndexError, AttributeError):
        return {'status': 'unverified', 'reason': 'unreadable'}
