"""Root-owned application data backend. Integration component, not auto-installed."""
import fcntl
import json
import os
import stat
import uuid
from pathlib import Path

ROOT = Path('/var/lib/satsuma-core')


def check(info, directory=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022:
        raise PermissionError('Storage requires root-owned non-writable-by-others regular paths')
    if not directory and (info.st_mode & 0o077 or info.st_nlink != 1):
        raise PermissionError('Data must be private (0600 or stricter) and have one hard link')


def open_directory(path):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Absolute storage path required')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        check(os.fstat(fd), True)
        for part in path.parts[1:]:
            # 2.2.43: open first, create only when missing; mkdir on an existing folder failed
            # with EEXIST and every /etc step was logged by audit (owner's report 2026-11-18).
            try:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            check(os.fstat(fd), True)
        return fd
    except BaseException:
        os.close(fd)
        raise


class RootDataStore:
    """Append/atomic JSON writes; no home fallback or recursive chmod/chown."""
    def __init__(self, relative):
        path = Path(relative)
        if path.is_absolute() or '..' in path.parts or not path.parts:
            raise ValueError('Relative data path required')
        self.relative = path

    def _directory(self):
        return open_directory(ROOT / self.relative.parent)

    def read(self):
        """Read one private JSON document without following a symlink."""
        directory = self._directory()
        try:
            fd = os.open(self.relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
            with os.fdopen(fd, 'r', encoding='utf-8') as stream:
                check(os.fstat(stream.fileno()))
                return json.load(stream)
        finally:
            os.close(directory)

    def append(self, record):
        encoded = (json.dumps(record, ensure_ascii=False)+'\n').encode('utf-8')
        directory = self._directory()
        try:
            fd = os.open(self.relative.name, os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                         os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
            try:
                check(os.fstat(fd))
                fcntl.flock(fd, fcntl.LOCK_EX)
                with os.fdopen(os.dup(fd), 'ab') as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)
        finally:
            os.close(directory)

    def replace(self, record):
        encoded = json.dumps(record, ensure_ascii=False, indent=2).encode('utf-8')
        directory = self._directory()
        temporary = '.write-' + uuid.uuid4().hex
        try:
            try:
                old = os.stat(self.relative.name, dir_fd=directory, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                check(old)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.relative.name, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
            os.close(directory)

    def read_lines(self):
        directory = self._directory()
        try:
            fd = os.open(self.relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                         dir_fd=directory)
            try:
                check(os.fstat(fd))
                with os.fdopen(os.dup(fd), 'r', encoding='utf-8') as stream:
                    for line in stream:
                        yield json.loads(line)
            finally:
                os.close(fd)
        finally:
            os.close(directory)
