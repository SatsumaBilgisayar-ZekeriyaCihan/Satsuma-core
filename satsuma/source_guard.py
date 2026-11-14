"""Linux EVE source validation. Opens existing files read-only; never creates EVE."""
import os
import stat
from pathlib import Path


def validate_stat(info, writer_uid=0, directory=False, path=None):
    location = str(path) if path is not None else 'EVE path'
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode):
        raise PermissionError('Unexpected EVE path type: ' + location)
    if info.st_uid not in (0, writer_uid):
        raise PermissionError(f'Untrusted EVE owner: {location}; actual UID={info.st_uid}, allowed UID=0 or {writer_uid}')
    if not directory and info.st_nlink != 1:
        raise PermissionError('EVE file must have exactly one hard link')
    if info.st_mode & 0o022:
        raise PermissionError(f'EVE path writable by group or other users: {location}; mode={stat.S_IMODE(info.st_mode):04o}')


def open_eve(path, writer_uid=0):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or not path.is_relative_to('/var/log'):
        raise PermissionError('Live EVE source must be beneath /var/log')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        validate_stat(os.fstat(fd), 0, directory=True, path='/')
        current = Path('/')
        for part in path.parts[1:-1]:
            new_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = new_fd
            current /= part
            validate_stat(os.fstat(fd), writer_uid if current == path.parent else 0,
                          directory=True, path=current)
        file_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            validate_stat(os.fstat(file_fd), writer_uid, path=path)
            return os.fdopen(file_fd, 'rb')
        except BaseException:
            os.close(file_fd)
            raise
    finally:
        os.close(fd)


MANAGED_WRITER = 'managed_suricata'


def resolve_writer_uid(configured=MANAGED_WRITER, provider=None):
    """Resolve the managed service identity; old root-only defaults migrate in memory.

    A nonzero explicit UID stays a pin and must match the verified service.
    """
    if configured != MANAGED_WRITER and (type(configured) is not int or configured<0):
        raise ValueError('Invalid configured EVE writer UID')
    from .ips import read_ready
    status=(provider or read_ready)()
    uid=status.get('writer_uid')
    if status.get('ready') is not True or type(uid) is not int or uid<0:
        raise PermissionError('Suricata writer identity is not verified: '+str(status.get('reason','writer_uid_missing')))
    if configured not in (MANAGED_WRITER,0) and (type(configured) is not int or configured != uid):
        raise PermissionError('Configured EVE writer UID does not match verified Suricata UID')
    return uid
