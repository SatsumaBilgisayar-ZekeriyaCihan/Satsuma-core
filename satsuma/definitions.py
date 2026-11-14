"""MITRE ATT&CK and CISA KEV definitions from /var/lib/satsuma-core/tanim (satsuma/definitions-v1).

Reference data only, never detection rules. Files must be root-owned regular
files that nobody else can write; anything else is ignored. A revoked ATT&CK
id resolves to its replacement (MITRE split Defense Evasion in 2026).

/var/lib/satsuma-core/tanim altındaki MITRE ATT&CK ve CISA KEV tanımları.
Yalnızca başvuru verisidir, tespit kuralı değildir. Dosyalar root'a ait ve
başkasının yazamadığı normal dosyalar olmalıdır; diğerleri yok sayılır.
İptal edilmiş bir ATT&CK numarası yeni karşılığına çözülür.
"""
import os
import stat
from pathlib import Path

DIRECTORY = Path('/var/lib/satsuma-core/tanim')
FILES = {'techniques': 'mitre-attack-teknikler.yaml', 'tactics': 'mitre-attack-taktikler.yaml',
         'revoked': 'mitre-attack-iptal-edilenler.yaml', 'kev': 'cisa-kev.yaml'}
MAX_BYTES = 16 * 1024 * 1024
_cache = {}


def _read(path, owner=0):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != owner or st.st_mode & 0o022
                or st.st_nlink != 1 or st.st_size > MAX_BYTES):
            raise PermissionError('untrusted_definition_file')
        key = (str(path), st.st_mtime_ns, st.st_size)
        if key in _cache:
            return _cache[key]
        data = b''
        while len(data) <= MAX_BYTES:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            data += block
    finally:
        os.close(fd)
    import yaml
    parsed = yaml.safe_load(data)
    if not isinstance(parsed, dict) or parsed.get('schema') != 'satsuma/definitions-v1':
        raise ValueError('not_a_definition_file')
    _cache.clear()
    _cache[key] = parsed
    return parsed


def load(name, directory=None, owner=0):
    try:
        return _read(Path(directory or DIRECTORY) / FILES[name], owner)
    except (OSError, ValueError, KeyError):
        return None


def technique(technique_id, directory=None, owner=0):
    """Definition of an ATT&CK technique; a revoked id returns its replacement with revoked_from."""
    if not technique_id:
        return None
    revoked = load('revoked', directory, owner) or {}
    moved = {r['old_id']: r['new_id'] for r in revoked.get('revoked', []) if isinstance(r, dict)}
    wanted = moved.get(technique_id, technique_id)
    data = load('techniques', directory, owner) or {}
    for item in data.get('techniques', []):
        if isinstance(item, dict) and item.get('id') == wanted:
            return dict(item, revoked_from=technique_id) if wanted != technique_id else dict(item)
    return None


def kev(cve, directory=None, owner=0):
    data = load('kev', directory, owner) or {}
    for item in data.get('vulnerabilities', []):
        if isinstance(item, dict) and item.get('cve') == cve:
            return dict(item)
    return None


def status(directory=None, owner=0):
    """Counts of the loaded definition files, for the health view."""
    result = {}
    for name in FILES:
        data = load(name, directory, owner)
        result[name] = data.get('count') if isinstance(data, dict) else None
    return result
