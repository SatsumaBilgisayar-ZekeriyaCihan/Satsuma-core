"""Bounded executable-page integrity checks. Never persist memory contents.

Regions are compared in file-offset order, so which part of a large
program fits the 1 MiB budget is deterministic, and every result says
whether the comparison was complete, how many candidate bytes there were
and which regions were skipped. The maps budget is 1 MiB so that large
programs (browsers, JVMs) are compared instead of reported unverified.

Sınırlı çalıştırılabilir sayfa bütünlüğü denetimi. Bellek içeriği asla
saklanmaz.

Bölgeler dosya ofseti sırasıyla karşılaştırılır; böylece büyük bir
programın hangi kısmının 1 MiB bütçeye sığdığı belirlidir ve her sonuç
karşılaştırmanın tam olup olmadığını, kaç aday bayt olduğunu ve hangi
bölgelerin atlandığını söyler. Harita bütçesi 1 MiB'tır; büyük programlar
(tarayıcılar, JVM'ler) doğrulanamadı denmek yerine karşılaştırılır.
"""
import hashlib
import os
from pathlib import Path

MAP_LIMIT = 1024 * 1024
BYTE_LIMIT = 1024 * 1024


def validate_executable(directory, byte_limit=BYTE_LIMIT):
    """Compare main-image private executable mappings to backing.

    A mismatch verifies a code difference, not malware attribution. JIT and
    anonymous regions have no trusted backing and are never reported clean.
    """
    directory = Path(directory)
    result = {'status': 'UNVERIFIED', 'checked_bytes': 0, 'regions': [], 'complete': False,
              'total_candidate_bytes': 0, 'skipped_regions': [], 'byte_limit': BYTE_LIMIT,
              'scan_order': 'file_offset_then_virtual_address',
              'scope': 'main executable private code only'}
    try:
        before = (directory / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        exe = os.readlink(directory / 'exe')
        with (directory / 'maps').open() as stream:
            maps = stream.read(MAP_LIMIT + 1)
        if len(maps) > MAP_LIMIT:
            return {**result, 'reason': 'mapping_list_truncated'}
        with (directory / 'exe').open('rb') as backing:
            original = os.fstat(backing.fileno())
            candidates = []
            for line in maps.splitlines():
                fields = line.split(None, 5)
                if len(fields) < 5:
                    continue
                perms = fields[1]
                if 'x' not in perms or not perms.endswith('p'):
                    continue
                if int(fields[4]) != original.st_ino:
                    continue
                major, minor = (int(x, 16) for x in fields[3].split(':'))
                if (major, minor) != (os.major(original.st_dev), os.minor(original.st_dev)):
                    continue
                start, end = (int(x, 16) for x in fields[0].split('-'))
                offset = int(fields[2], 16)
                if end <= start or offset >= original.st_size:
                    continue
                candidates.append((start, end, offset))
            if not candidates:
                return {**result, 'reason': 'no_comparable_code_mapping'}
            candidates.sort(key=lambda region: (region[2], region[0]))
            remaining = max(0, min(int(byte_limit), BYTE_LIMIT))
            result['byte_limit'] = remaining
            total = sum(min(end - start, original.st_size - offset)
                        for start, end, offset in candidates)
            result['total_candidate_bytes'] = total
            mismatch = False
            with (directory / 'mem').open('rb', buffering=0) as memory:
                for start, end, offset in candidates:
                    size = min(end - start, original.st_size - offset, remaining)
                    if size <= 0:
                        result['skipped_regions'].append({'address': start, 'bytes': end - start,
                                                          'reason': 'byte_limit_exhausted'})
                        continue
                    actual = os.pread(memory.fileno(), size, start)
                    expected = os.pread(backing.fileno(), size, offset)
                    if len(actual) != size or len(expected) != size:
                        return {**result, 'status': 'UNVERIFIED', 'reason': 'short_code_read'}
                    equal = actual == expected
                    mismatch |= not equal
                    result['regions'].append({'address': start, 'bytes': size, 'matches': equal,
                        'memory_sha256': hashlib.sha256(actual).hexdigest(),
                        'backing_sha256': hashlib.sha256(expected).hexdigest()})
                    result['checked_bytes'] += size
                    remaining -= size
            current = os.fstat(backing.fileno())
        after = (directory / 'stat').read_text().rsplit(')', 1)[1].split()[19]
        if before != after or exe != os.readlink(directory / 'exe'):
            return {**result, 'status': 'UNVERIFIED', 'reason': 'process_identity_changed'}
        with (directory / 'maps').open() as stream:
            if maps != stream.read(MAP_LIMIT + 1):
                return {**result, 'status': 'UNVERIFIED', 'reason': 'mapping_changed'}
        if (original.st_size, original.st_mtime_ns, original.st_ctime_ns) != (
                current.st_size, current.st_mtime_ns, current.st_ctime_ns):
            return {**result, 'status': 'UNVERIFIED', 'reason': 'backing_changed'}
        if not result['checked_bytes']:
            return {**result, 'reason': 'empty_check_budget'}
        return {**result, 'status': 'CODE_MISMATCH' if mismatch else 'CODE_MATCH',
                'complete': result['checked_bytes'] == total,
                'reason': 'executable_bytes_differ' if mismatch else 'checked_code_matches_backing'}
    except PermissionError:
        return {**result, 'status': 'ACCESS_DENIED', 'reason': 'process_memory_access_denied'}
    except (OSError, ValueError, IndexError) as exc:
        return {**result, 'status': 'UNVERIFIED', 'reason': type(exc).__name__}
