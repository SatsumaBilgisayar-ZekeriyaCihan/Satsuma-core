"""SHA-256 blacklist enforced through ClamAV.

satsuma/trust/hash-blacklist.json ships inside the integrity-checked image.
It is installed into ClamAV's database directory as satsuma-blacklist.hsb,
in ClamAV's documented SHA-256 hash-signature format
``HashString:FileSize:MalwareName``. Every ClamAV scan (clamd, clamdscan,
clamscan, on-access) then reports a matching file as
``Satsuma.Blacklist.<group>.<n>``, and Satsuma's existing scan, finding and
quarantine flow takes over. ``check`` tests one file directly, without
following links.

ClamAV üzerinden uygulanan SHA-256 kara listesi.

satsuma/trust/hash-blacklist.json bütünlüğü denetlenen imajın içinde gelir.
ClamAV'ın belgelenmiş SHA-256 özet imzası biçimiyle
(``HashString:FileSize:MalwareName``) ClamAV'ın veritabanı dizinine
satsuma-blacklist.hsb olarak kurulur. Bundan sonra her ClamAV taraması
(clamd, clamdscan, clamscan, erişimde tarama) eşleşen dosyayı
``Satsuma.Blacklist.<grup>.<n>`` olarak bildirir ve Satsuma'nın mevcut
tarama, bulgu ve karantina akışı devreye girer. ``check`` tek bir dosyayı,
bağlantı izlemeden doğrudan sınar.
"""
import hashlib
import grp
import tempfile
import json
import os
import re
import stat
from pathlib import Path

BLACKLIST = Path(__file__).resolve().parent / 'trust' / 'hash-blacklist.json'
CLAMAV_DB = Path('/var/lib/clamav')
HSB_NAME = 'satsuma-blacklist.hsb'
HEX64 = re.compile(r'^[0-9a-f]{64}$')
NAME = re.compile(r'^[A-Za-z0-9]+$')


def load(path=BLACKLIST):
    """{sha256: (size, signature name)}; a malformed list is an error, never empty."""
    data = json.loads(Path(path).read_text())
    table = {}
    for group in data['groups']:
        if not NAME.match(group['name']):
            raise ValueError('invalid group name: ' + group['name'])
        for number, entry in enumerate(group['entries'], 1):
            digest, size = entry['sha256'], entry['size']
            if not HEX64.match(digest) or type(size) is not int or size <= 0:
                raise ValueError('invalid entry: ' + json.dumps(entry))
            table[digest] = (size, f'Satsuma.Blacklist.{group["name"]}.{number}')
    if not table:
        raise ValueError('empty blacklist')
    return table


def render_hsb(table):
    return ''.join(f'{digest}:{size}:{name}\n' for digest, (size, name) in sorted(table.items()))


def install(table=None, database=CLAMAV_DB):
    """Write the .hsb atomically next to ClamAV's own databases."""
    table = load() if table is None else table
    text = render_hsb(table)
    target = Path(database) / HSB_NAME
    gid = grp.getgrnam('clamscan').gr_gid
    uid = os.geteuid()
    try:
        fd = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        fd = None
    if fd is not None:
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != uid or info.st_mode & 0o022):
                raise PermissionError('Unsafe existing ClamAV blacklist')
            if stream.read(len(text.encode()) + 1) == text.encode():
                before = {'uid': info.st_uid, 'gid': info.st_gid, 'mode': oct(stat.S_IMODE(info.st_mode))}
                os.fchown(stream.fileno(), uid, gid)
                os.fchmod(stream.fileno(), 0o640)
                return {'status': 'UNCHANGED' if info.st_gid == gid and stat.S_IMODE(info.st_mode) == 0o640 else 'ACCESS_REPAIRED',
                        'path': str(target), 'entries': len(table), 'previous_metadata': before}
    fd, temporary = tempfile.mkstemp(prefix='.' + HSB_NAME + '.', dir=target.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), 0o640)
            stream.write(text); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return {'status': 'INSTALLED', 'path': str(target), 'entries': len(table)}


def check(path, table=None):
    """The signature name if this regular file is blacklisted, else None."""
    table = load() if table is None else table
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_size not in {size for size, _ in table.values()}:
        return None
    digest = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            digest.update(block)
    hit = table.get(digest.hexdigest())
    return hit[1] if hit and hit[0] == info.st_size else None


def main():
    report = install()
    print(json.dumps(report))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
