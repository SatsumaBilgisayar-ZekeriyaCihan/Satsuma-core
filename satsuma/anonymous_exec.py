"""Executable memory without a trusted file behind it. Observation only.

validate_executable compares a program's code with its file. Code that has
no file at all (anonymous executable mappings, memfd, an executable heap or
stack, a deleted file) cannot be compared, so the integrity check is blind
to it, and shellcode or a reflectively loaded library lives exactly there.
This module lists such regions per process so the user can see that code
exists which nothing can verify. It never returns CODE_MATCH or
CODE_MISMATCH, never produces a rule event and is never consulted by a
termination path: JIT compilers (browsers, Java, .NET) use these mappings
legitimately, so presence is not malware attribution.

Arkasında güvenilir bir dosya olmayan çalıştırılabilir bellek. Yalnızca gözlem.

validate_executable bir programın kodunu dosyasıyla karşılaştırır. Hiç
dosyası olmayan kod (anonim çalıştırılabilir eşlemeler, memfd,
çalıştırılabilir yığın ya da heap, silinmiş dosya) karşılaştırılamaz; bu
yüzden bütünlük denetimi onu görmez, shellcode ya da yansıtmalı yüklenen
kütüphane de tam orada yaşar. Bu modül bu bölgeleri süreç başına listeler;
kullanıcı hiçbir şeyin doğrulayamadığı kodun var olduğunu görür. Asla
CODE_MATCH ya da CODE_MISMATCH döndürmez, kural olayı üretmez ve hiçbir
durdurma yolu ona bakmaz: JIT derleyicileri (tarayıcılar, Java, .NET) bu
eşlemeleri meşru olarak kullanır; varlığı zararlı yazılım kanıtı değildir.
"""
from pathlib import Path

MAP_LIMIT = 1024 * 1024
REGION_CAP = 16
TAGS = ('anonymous_exec', 'memfd_exec', 'deleted_exec')
KERNEL_PSEUDO = ('[vdso]', '[vsyscall]', '[vvar]')


def classify(perms, inode, pathname):
    """Tag for an executable private region without a verifiable file, or None."""
    if 'x' not in perms or not perms.endswith('p'):
        return None
    if pathname in KERNEL_PSEUDO:
        return None
    if pathname.startswith('/memfd:'):
        return 'memfd_exec'
    if pathname.endswith(' (deleted)'):
        return 'deleted_exec'
    if (inode == 0 and not pathname) or (pathname.startswith('[') and pathname.endswith(']')):
        return 'anonymous_exec'
    return None


def inventory(directory, region_cap=REGION_CAP):
    """Status OBSERVED, ACCESS_DENIED or UNVERIFIED; never a code verdict."""
    result = {'status': 'UNVERIFIED', 'counts': dict.fromkeys(TAGS, 0), 'regions': [],
              'region_cap': region_cap, 'truncated': False,
              'scope': 'executable memory without a verifiable file; observation only'}
    try:
        with (Path(directory) / 'maps').open() as stream:
            maps = stream.read(MAP_LIMIT + 1)
    except PermissionError:
        return {**result, 'status': 'ACCESS_DENIED', 'reason': 'process_maps_access_denied'}
    except OSError as exc:
        return {**result, 'reason': type(exc).__name__}
    if len(maps) > MAP_LIMIT:
        return {**result, 'reason': 'mapping_list_truncated'}
    for line in maps.splitlines():
        fields = line.split(None, 5)
        if len(fields) < 5:
            continue
        try:
            start, end = (int(x, 16) for x in fields[0].split('-'))
            inode = int(fields[4])
        except ValueError:
            continue
        pathname = fields[5].strip() if len(fields) > 5 else ''
        tag = classify(fields[1], inode, pathname)
        if tag is None:
            continue
        result['counts'][tag] += 1
        if len(result['regions']) >= region_cap:
            result['truncated'] = True
            continue
        result['regions'].append({'address': start, 'bytes': end - start, 'perms': fields[1],
                                  'tag': tag, 'pathname': pathname or None})
    present = any(result['counts'].values())
    return {**result, 'status': 'OBSERVED',
            'reason': 'unverifiable_executable_memory_present' if present else 'none'}
