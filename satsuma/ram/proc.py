"""Read-only process access. No dump files, ptrace calls or policy mutation.

Salt okunur süreç erişimi; döküm dosyası, ptrace çağrısı ya da politika değişikliği yok.

Sınırlı süreç belleği taraması; kapsam ve erişim eksikleri açıkça raporlanır.
"""
import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

MAX_MAPS = 1024 * 1024
PF_KTHREAD = 0x00200000


def kernel_thread(stat_text):
    """True for a kernel thread: it has no user memory and no executable.

    Çekirdek iş parçacığıdır: kullanıcı belleği ve çalıştırılabilir dosyası yoktur.
    """
    tail = stat_text[stat_text.rindex(')') + 1:].split()
    return bool(int(tail[6]) & PF_KTHREAD)

@dataclass(frozen=True)
class Region:
    start: int
    end: int
    perms: str
    offset: int
    device: tuple
    inode: int
    path: str


def parse_maps(text):
    regions = []
    last_end = 0
    for line in text.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            raise ValueError('malformed_maps')
        start, end = [int(x, 16) for x in fields[0].split('-')]
        perms = fields[1]
        if start < last_end or end <= start or not re.fullmatch(r'[r-][w-][x-][ps]', perms):
            raise ValueError('invalid_mapping_range_or_permissions')
        dev = tuple(int(x, 16) for x in fields[3].split(':'))
        if len(dev) != 2:
            raise ValueError('invalid_mapping_device')
        path = fields[5] if len(fields) == 6 else ''
        path = re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m[1], 8)), path)
        regions.append(Region(start, end, perms, int(fields[2], 16), dev, int(fields[4]), path))
        last_end = end
    return regions


class Process:
    def __init__(self, pid, root=Path('/proc')):
        self.pid = int(pid)
        if self.pid <= 0:
            raise ValueError('invalid_pid')
        self.fd = os.open(str(Path(root) / str(self.pid)), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        self.mem = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.mem is not None:
            os.close(self.mem)
        os.close(self.fd)

    def _read(self, name, limit):
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        try:
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                value = stream.read(limit + 1)
            if len(value) > limit:
                raise ValueError(name + '_limit_exceeded')
            return value.decode('utf-8', 'strict')
        finally:
            os.close(fd)

    def kernel_thread(self):
        return kernel_thread(self._read('stat', 16384))

    def snapshot(self):
        raw = self._read('stat', 16384)
        tail = raw[raw.rindex(')') + 1:].split()
        start = int(tail[19])
        exe = os.readlink('exe', dir_fd=self.fd)
        info = os.stat('exe', dir_fd=self.fd)
        maps = self._read('maps', MAX_MAPS)
        identity = (self.pid, start, exe, info.st_dev, info.st_ino)
        return identity, maps

    def read(self, address, size):
        if self.mem is None:
            self.mem = os.open('mem', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
        return os.pread(self.mem, size, address)

    def eligible(self, region):
        if 'r' not in region.perms:
            return False, 'not_readable'
        if region.path in ('[vvar]', '[vvar_vclock]', '[vdso]', '[vsyscall]'):
            return False, 'kernel_special_mapping'
        if region.path.startswith('/dev/') and not region.path.startswith('/dev/shm/'):
            return False, 'device_mapping'
        # Shared anonymous pages are eligible too. File mappings must be bound
        # to a regular mapped inode, never an arbitrary target pathname.
        if region.inode:
            try:
                info = os.stat('map_files/%x-%x' % (region.start, region.end), dir_fd=self.fd)
            except OSError:
                return False, 'backing_type_unverified'
            if not stat.S_ISREG(info.st_mode) or info.st_ino != region.inode or (os.major(info.st_dev), os.minor(info.st_dev)) != region.device:
                return False, 'nonregular_or_changed_backing'
        return True, None


def maps_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()
