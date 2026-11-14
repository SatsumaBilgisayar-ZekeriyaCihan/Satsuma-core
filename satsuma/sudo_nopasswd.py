"""Passwordless sudo: stop it at run time and report it where it is granted.

The sudo autoblock switch (sudo_autoblock_enabled, on under full protection)
has two parts. At run time a "sudo -n" / "sudo -S" command (rule
SATSUMA-SUDO-004: becoming root without being asked for a password) is
stopped like an attack (satsuma.enforcement). On disk, every NOPASSWD line
in /etc/sudoers and /etc/sudoers.d is reported as a critical finding with
its file and line; the files are never edited, because a wrong edit can
lock the user out of root.

Parolasız sudo: çalışırken durdur, verildiği yerde bildir.

Sudo oto-blok anahtarının (sudo_autoblock_enabled, tam korumada açık) iki
parçası vardır. Çalışırken "sudo -n" / "sudo -S" komutu (SATSUMA-SUDO-004
kuralı: parola sorulmadan root olmak) saldırı gibi durdurulur
(satsuma.enforcement). Diskte /etc/sudoers ve /etc/sudoers.d içindeki her
NOPASSWD satırı dosyası ve satırıyla kritik bulgu olarak bildirilir;
dosyalar asla düzenlenmez, çünkü yanlış bir düzenleme kullanıcıyı root
yetkisinden kesebilir.
"""
import json
import re
import time
from pathlib import Path

RUNTIME_RULES = frozenset(('SATSUMA-SUDO-004',))
SOURCES = (Path('/etc/sudoers'), Path('/etc/sudoers.d'))
NOPASSWD = re.compile(r'(?<![!\w])NOPASSWD\s*:')


def grants(sources=SOURCES):
    """Every active NOPASSWD line: file, line number, text."""
    found = []
    files = []
    for source in sources:
        if source.is_dir():
            files += sorted(p for p in source.iterdir() if p.is_file() and not p.name.startswith('.')
                            and not p.name.endswith('~'))
        elif source.is_file():
            files.append(source)
    for path in files:
        try:
            lines = path.read_text(errors='replace').splitlines()
        except OSError:
            continue
        for number, line in enumerate(lines, 1):
            text = line.split('#', 1)[0] if not line.lstrip().startswith(('#include', '#includedir')) else ''
            if NOPASSWD.search(text):
                found.append({'file': str(path), 'line': number, 'text': line.strip()[:300]})
    return found


def record(store, found, now=time.time):
    """Write one critical finding for the current set of NOPASSWD grants."""
    if not found:
        return None
    ident = 'sudo-nopasswd:' + '|'.join(f"{g['file']}:{g['line']}:{g['text']}" for g in found)[:400]
    finding = {'finding_id': ident, 'rule_id': 'SATSUMA-SUDO-NOPASSWD', 'timestamp': now(),
               'severity': 'critical', 'classification': 'likely', 'source': 'sudo_nopasswd',
               'title': 'Parolasız sudo yetkisi tanımlı',
               'summary': '; '.join(f"{g['file']}:{g['line']} {g['text']}" for g in found)[:900],
               'grants': found,
               'advice': 'Bu satırı siz eklemediyseniz kaldırın: sudo visudo -f <dosya>. '
                         'Parola sorulmadan root olmak saldırganın en sevdiği kapıdır.'}
    store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                     (ident, time.time(), json.dumps(finding, ensure_ascii=False)))
    store.db.commit()
    return finding
