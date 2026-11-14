"""Media audit: man pages, SVG, PNG and fonts that carry more than they show.

Daily inside the security scan (and on manual scans), over the system's
icon, pixmap, font and man directories (and the /usr/local ones) plus the
users' own font and icon directories:

- Packaged files are compared with their RPM digests; a changed one is a
  finding. Unchanged packaged files are trusted and not read further.
- Unpackaged or changed files, and everything in the users' directories,
  are read: SVG with scripts, event handlers, javascript: links, external
  references or XML entity definitions; PNG with data after IEND or large
  private chunks; fonts whose file runs past the last table, or a WOFF
  whose header size does not match; man pages with groff requests that run
  commands or write files (.sy, .pi, .pso, .open/.opena) or an .so outside
  the man tree; any file whose content is not what its suffix says.
  Hidden executables, archives or scripts (ELF, PE, ZIP, #!) raise a
  finding to high.
- Files the system generates (icon-theme.cache, fontconfig .uuid,
  fonts.dir, fonts.scale) are not called unpackaged.

Nothing is moved by itself; findings carry a restorable quarantine
proposal.

Medya denetimi: gösterdiğinden fazlasını taşıyan man sayfası, SVG, PNG ve
fontlar. Paketli dosyalar RPM özetiyle karşılaştırılır; değişmemiş paketli
dosyaya güvenilir. Paket dışı ya da değişmiş dosyalar ve kullanıcının
klasörleri okunur: betikli ya da dış bağlantılı SVG, IEND'den sonra veri
taşıyan PNG, son tablodan sonra veri taşıyan font, komut çalıştıran ya da
dosya yazan man sayfası ve uzantısıyla içeriği tutmayan dosya. Gizli
program, arşiv ya da betik bulguyu yüksek yapar. Sistemin ürettiği önbellek
dosyaları paket dışı sayılmaz. Hiçbir şey kendiliğinden taşınmaz.
"""
import bz2
import glob
import gzip
import json
import lzma
import os
import re
import stat
import struct
import subprocess
import time
from pathlib import Path

INTERVAL = 24 * 3600
SYSTEM_DIRS = ('/usr/share/icons', '/usr/share/pixmaps', '/usr/share/fonts', '/usr/share/man',
               '/usr/local/share/icons', '/usr/local/share/fonts', '/usr/local/share/man')
USER_GLOBS = ('/home/*/.local/share/fonts', '/home/*/.fonts', '/home/*/.local/share/icons', '/home/*/.icons',
              '/root/.local/share/fonts', '/root/.fonts')
GENERATED = frozenset(('icon-theme.cache', '.uuid', 'fonts.dir', 'fonts.scale', 'fonts.cache-1', 'index.theme.cache'))
MAX_FILE = 20 * 1024 * 1024
MAX_FILES = 300000
FONT_SUFFIXES = ('.ttf', '.otf', '.ttc', '.woff', '.woff2')
PNG_SIGNATURE = b'\x89PNG\r\n\x1a\n'
PAYLOADS = ((b'\x7fELF', 'ELF programı'), (b'MZ', 'Windows programı'), (b'PK\x03\x04', 'ZIP arşivi'),
            (b'#!', 'betik'), (b'\x1f\x8b', 'gzip arşivi'), (b'7z\xbc\xaf', '7z arşivi'))
SVG_RULES = (
    ('script', re.compile(rb'<\s*script\b', re.I), 'SVG içinde betik'),
    ('event', re.compile(rb'\son[a-z]+\s*=', re.I), 'SVG içinde olay betiği (onload= vb.)'),
    ('javascript', re.compile(rb'javascript\s*:', re.I), 'SVG içinde javascript: bağlantısı'),
    ('external', re.compile(rb'(?:xlink:)?href\s*=\s*[\'"]\s*(?:https?|ftp)://', re.I), 'SVG dış adrese bağlanıyor'),
    ('entity', re.compile(rb'<!ENTITY', re.I), 'SVG içinde XML varlık tanımı (XXE)'),
    ('foreign', re.compile(rb'<\s*foreignObject\b', re.I), 'SVG içine HTML gömülmüş'),
)
MAN_RULES = (
    ('exec', re.compile(rb'^\.\s*(?:sy|pi|pso)\b', re.M), 'Man sayfası komut çalıştırıyor'),
    ('write', re.compile(rb'^\.\s*(?:open|opena)\b', re.M), 'Man sayfası dosyaya yazıyor'),
    ('outside', re.compile(rb'^\.\s*so\s+/(?!usr/share/man/|usr/local/share/man/)', re.M),
     'Man sayfası man klasörü dışından içerik alıyor'),
)


def payload(data):
    """Name of an executable, archive or script at the start of data, or None."""
    for magic, name in PAYLOADS:
        if data.startswith(magic):
            return name
    return None


def kind_of(path):
    name = path.name.lower()
    if name.endswith(('.svg', '.svgz')):
        return 'svg'
    if name.endswith('.png'):
        return 'png'
    if name.endswith(FONT_SUFFIXES):
        return 'font'
    if '/man/' in str(path) and re.search(r'\.\d\w*(?:\.(?:gz|bz2|xz))?$', name):
        return 'man'
    return None


def check_png(data):
    issues = []
    if not data.startswith(PNG_SIGNATURE):
        found = payload(data)
        return [('mismatch', 'high' if found else 'medium', '.png uzantılı ama PNG değil' + (' (' + found + ')' if found else ''))]
    offset = 8
    while offset + 12 <= len(data):
        length, kind = struct.unpack('>I4s', data[offset:offset + 8])
        end = offset + 12 + length
        if end > len(data):
            issues.append(('truncated', 'low', 'PNG bloğu dosyanın dışına taşıyor'))
            break
        if kind[:1].islower() and length > 256 * 1024 and kind not in (b'iTXt', b'zTXt', b'tEXt', b'iCCP', b'eXIf'):
            issues.append(('private_chunk', 'medium', f'Büyük özel PNG bloğu {kind.decode(errors="replace")} ({length} bayt)'))
        offset = end
        if kind == b'IEND':
            trailing = data[offset:]
            if len(trailing) > 16:
                found = payload(trailing)
                issues.append(('trailing', 'high' if found else 'medium',
                               f'Resim bittikten sonra {len(trailing)} bayt veri' + (' (' + found + ')' if found else '')))
            break
    return issues


def check_svg(data):
    raw = gzip.decompress(data) if data[:2] == b'\x1f\x8b' else data
    head = raw.lstrip()[:400].lower()
    if not (head.startswith(b'<?xml') or head.startswith(b'<svg') or head.startswith(b'<!--') or b'<svg' in head):
        found = payload(raw)
        return [('mismatch', 'high' if found else 'medium', '.svg uzantılı ama SVG değil' + (' (' + found + ')' if found else ''))]
    issues = []
    for rule, pattern, title in SVG_RULES:
        if pattern.search(raw):
            severity = 'high' if rule in ('script', 'javascript', 'entity') else 'medium'
            issues.append((rule, severity, title))
    return issues


def check_font(data, name):
    if name.endswith('.woff'):
        if not data.startswith(b'wOFF'):
            return [('mismatch', 'high' if payload(data) else 'medium', '.woff uzantılı ama WOFF değil')]
        declared = struct.unpack('>I', data[8:12])[0] if len(data) >= 12 else 0
        return [('trailing', 'high' if payload(data[declared:]) else 'medium',
                 f'WOFF başlığındaki boyut {declared}, dosya {len(data)} bayt')] if declared and len(data) > declared + 16 else []
    if name.endswith('.woff2'):
        return [] if data.startswith(b'wOF2') else [('mismatch', 'medium', '.woff2 uzantılı ama WOFF2 değil')]
    if data[:4] == b'ttcf':
        return []
    if data[:4] not in (b'\x00\x01\x00\x00', b'OTTO', b'true', b'typ1'):
        found = payload(data)
        return [('mismatch', 'high' if found else 'medium', 'Font uzantılı ama font değil' + (' (' + found + ')' if found else ''))]
    if len(data) < 12:
        return [('truncated', 'low', 'Font başlığı eksik')]
    tables = struct.unpack('>H', data[4:6])[0]
    last = 12 + 16 * tables
    for index in range(tables):
        entry = 12 + 16 * index
        if entry + 16 > len(data):
            return [('truncated', 'low', 'Font tablo dizini eksik')]
        offset, length = struct.unpack('>II', data[entry + 8:entry + 16])
        last = max(last, offset + length)
    # Tables are padded to 4 bytes; anything well past the end is extra.
    trailing = data[(last + 3) & ~3:]
    if len(trailing) > 1024:
        found = payload(trailing)
        return [('trailing', 'high' if found else 'medium',
                 f'Son font tablosundan sonra {len(trailing)} bayt veri' + (' (' + found + ')' if found else ''))]
    return []


def read_man(path, data):
    name = path.name
    try:
        if name.endswith('.gz'):
            return gzip.decompress(data)
        if name.endswith('.bz2'):
            return bz2.decompress(data)
        if name.endswith('.xz'):
            return lzma.decompress(data)
    except (OSError, EOFError, lzma.LZMAError, ValueError):
        return None
    return data


def check_man(path, data):
    text = read_man(path, data)
    if text is None:
        found = payload(data)
        return [('mismatch', 'high' if found else 'medium', 'Sıkıştırılmış man sayfası açılamıyor' + (' (' + found + ')' if found else ''))]
    return [(rule, 'high', title) for rule, pattern, title in MAN_RULES if pattern.search(text)]


def inspect(path, data):
    kind = kind_of(path)
    if kind == 'png':
        return check_png(data)
    if kind == 'svg':
        try:
            return check_svg(data)
        except (OSError, EOFError):
            return [('mismatch', 'medium', '.svgz açılamıyor')]
    if kind == 'font':
        return check_font(data, path.name.lower())
    if kind == 'man':
        return check_man(path, data)
    return []


def files(dirs):
    count = 0
    for root in dirs:
        for directory, subdirs, names in os.walk(root, followlinks=False):
            for name in names:
                path = Path(directory) / name
                try:
                    info = path.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE and kind_of(path):
                    count += 1
                    if count > MAX_FILES:
                        return
                    yield path, info


def audit(owned, system_dirs=SYSTEM_DIRS, user_dirs=None):
    """Findings for changed, unpackaged and suspicious media files."""
    import hashlib
    users = user_dirs if user_dirs is not None else [p for g in USER_GLOBS for p in glob.glob(g)]
    results = []
    for path, info in files(list(system_dirs) + list(users)):
        text = str(path)
        owner = owned.get(text)
        in_user = any(text.startswith(str(u) + '/') for u in users)
        modified = False
        try:
            data = path.read_bytes()
        except OSError:
            continue
        digest = hashlib.sha256(data).hexdigest()
        if owner:
            if owner[1] and owner[2] in ('8', 'SHA256', 'sha256') and digest != owner[1]:
                modified = True
            else:
                continue  # unchanged packaged file: trusted
        issues = inspect(path, data)
        unowned = not owner and not in_user and not text.startswith('/usr/local/') and path.name not in GENERATED
        if not (issues or modified or unowned):
            continue
        results.append({'path': text, 'package': owner[0] if owner else None, 'sha256': digest,
                        'modified': modified, 'unowned': unowned, 'issues': issues})
    return results


def run(store, manual=False, runner=subprocess.run, now=time.time, system_dirs=SYSTEM_DIRS, user_dirs=None):
    state = store.get('media_audit', {}) or {}
    if not manual and now() - state.get('updated_at', 0) < INTERVAL:
        return state
    from .binary_audit import rpm_inventory
    existing = [Path(d) for d in system_dirs if os.path.isdir(d)]
    owned = rpm_inventory(runner, existing) if existing else {}
    items = audit(owned, system_dirs, user_dirs)
    stamp = now()
    for item in items:
        severities = [i[1] for i in item['issues']]
        severity = 'high' if 'high' in severities or item['modified'] else 'medium' if 'medium' in severities else 'low'
        titles = [i[2] for i in item['issues']]
        if item['modified']:
            titles.insert(0, 'Paketindekinden farklı (' + item['package'] + ')')
        if item['unowned']:
            titles.append('Hiçbir pakete ait değil')
        command = 'sudo satsuma-admin karantina al ' + item['path']
        advice = ('SİLMEYİN. Paketi yeniden kurun: sudo dnf reinstall ' + item['package'] if item['modified'] and not item['issues']
                  else 'SİLMEYİN. Tanımıyorsanız karantinaya alın: ' + command + ' (geri almak mümkün).')
        ident = 'SATSUMA-MEDIA:' + item['path'] + ':' + item['sha256']
        body = {'finding_id': ident, 'rule_id': 'SATSUMA-MEDIA', 'timestamp': stamp, 'severity': severity,
                'classification': 'suspicious' if severity == 'high' else 'indicator', 'source': 'media_audit',
                'title': 'Şüpheli ' + (kind_of(Path(item['path'])) or 'medya').upper() + ' dosyası',
                'summary': item['path'] + ' · ' + '; '.join(titles),
                'item': {**item, 'quarantine_proposal': {'path': item['path'], 'sha256': item['sha256'], 'command': command}},
                'advice': advice}
        store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                         (ident, time.time(), json.dumps(body, ensure_ascii=False)))
    store.db.commit()
    state = {'updated_at': stamp,
             'high': [i['path'] for i in items if i['modified'] or any(x[1] == 'high' for x in i['issues'])],
             'other': [i['path'] for i in items if not (i['modified'] or any(x[1] == 'high' for x in i['issues']))],
             'items': items[:200]}
    store.set('media_audit', state)
    return state
