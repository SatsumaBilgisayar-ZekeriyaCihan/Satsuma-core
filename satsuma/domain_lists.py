"""Domain name checks; the HaGeZi list download is retired.

Since 2.2.38 (owner, 2026-11-13) no domain list is downloaded: a list someone
can change steers what this machine may resolve, the MITM Satsuma guards
against. update() records that and fetches nothing. domain() and parse() stay
for the names Satsuma still checks.

Alan adı denetimleri; HaGeZi listesi indirme kaldırıldı. 2.2.38'den beri
(sahibi, 2026-11-13) hiçbir alan adı listesi indirilmez: başkasının
değiştirebildiği bir liste bu makinenin neyi çözebileceğini yönlendirir.
update() bunu kaydeder ve hiçbir şey indirmez.
"""
import hashlib
import os
import tempfile
import time
import urllib.request
from pathlib import Path
import re

def domain(value):
    if not isinstance(value, str):
        raise ValueError("Invalid domain")
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels):
        raise ValueError("Invalid domain")
    return value


HAGEZI_URL = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/ultimate-onlydomains.txt'
LIST_PATH = Path('/var/lib/satsuma-core/dns/hagezi.txt')


def parse(text):
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '!')):
            continue
        try:
            name = domain(line)
        except ValueError:
            raise ValueError('Invalid domain list entry') from None
        if '.' not in name or name.endswith(('.local', '.lan', '.home.arpa', '.arpa')):
            continue
        names.add(name)
    if not names:
        raise ValueError('Empty domain list')
    return sorted(names)


RETIRED = 'retired_in_2.2.38'


def update(store, path=LIST_PATH, opener=None, *, url=HAGEZI_URL, state_key='hagezi_list'):
    """Nothing is downloaded any more (2.2.38). Artık hiçbir şey indirilmez."""
    info = {'status': RETIRED, 'source': None, 'count': 0, 'updated_at': time.time()}
    store.set(state_key, info)
    return info


def _download_retired(store, path=LIST_PATH, opener=urllib.request.urlopen, *, url=HAGEZI_URL, state_key='hagezi_list'):
    with opener(url, timeout=30) as reply:
        if reply.geturl() != url:
            raise ValueError('Unexpected domain list redirect')
        raw = reply.read(32 * 1024 * 1024 + 1)
    if len(raw) > 32 * 1024 * 1024:
        raise ValueError('Domain list exceeds size limit')
    names = parse(raw.decode('utf-8'))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(prefix='.list-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write('\n'.join(names) + '\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    info = {'source': url, 'count': len(names), 'sha256': hashlib.sha256(raw).hexdigest(),
            'updated_at': time.time(), 'status': 'updated'}
    store.set(state_key, info)
    return info
