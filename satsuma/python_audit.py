"""Python script audit: what an attacker would do with Python, not style.

Daily inside the security scan (and on every manual scan):

- Packaged Python (/usr/lib/python3*, /usr/lib64/python3*) is compared with
  the digests its RPM recorded; a changed .py file is a critical finding
  (a backdoored standard library runs inside every Python program).
- Unpackaged Python in /usr/local, /opt, /etc, /srv, /root, /home, /tmp,
  /var/tmp and /dev/shm (*.py, *.pyw and executables with a python
  shebang) is read and scored. A single eval, exec or base64 never counts:
  ordinary libraries use them. Points come from combinations an attack
  needs (decode-then-execute, connect-then-shell, bind-then-shell,
  download-then-execute) and from persistence, credential theft and
  keylogging; a script that starts by itself (systemd, cron, XDG
  autostart) gets extra points. 4 points or more is high, 2-3 is medium.
- High scored scripts are looked up on VirusTotal by SHA-256 (never the
  file) when the key exists, at most 4 per run, cached.

Nothing is moved by itself: a finding carries the matched lines and a
quarantine proposal (satsuma-admin karantina al), which can be undone.

Python betiği denetimi: saldırganın Python ile yapacağı işler, üslup değil.

Güvenlik taraması içinde günde bir (ve her elle taramada): paketlenmiş
Python (/usr/lib/python3*) RPM özetleriyle karşılaştırılır, değişmiş .py
dosyası kritik bulgudur. Paket dışı Python dosyaları okunup puanlanır; tek
başına eval, exec ya da base64 asla sayılmaz, puanı saldırının ihtiyaç
duyduğu birleşimler (çözüp çalıştırma, bağlanıp shell, dinleyip shell,
indirip çalıştırma), kalıcılık, kimlik bilgisi hırsızlığı ve tuş kaydı
verir; kendiliğinden başlatılan betik ek puan alır. 4 ve üstü yüksek, 2-3
orta önemlidir. Yüksek puanlılar VirusTotal'a yalnızca SHA-256 ile sorulur.
Hiçbir şey kendiliğinden taşınmaz; bulgu eşleşen satırları ve geri
alınabilir bir karantina önerisini taşır.
"""
import glob
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from pathlib import Path

INTERVAL = 24 * 3600
ROOTS = ('/usr/local', '/opt', '/etc', '/srv', '/root', '/home', '/tmp', '/var/tmp', '/dev/shm')
SKIP_DIRS = frozenset(('node_modules', '.cache', '.git', '__pycache__', '.mozilla', '.var', 'satsuma-core'))
MAX_FILE = 1024 * 1024
MAX_FILES = 50000
PACKAGED_GLOBS = ('/usr/lib/python3*', '/usr/lib64/python3*')

DECODE = r'(?:b64decode|b32decode|b85decode|a85decode|decompress|marshal\.loads|fromhex|codecs\.decode|rot13)'
RULES = (
    ('decode_exec', 3, 'Çözülen veri çalıştırılıyor',
     re.compile(r'\b(?:exec|eval)\s*\(\s*(?:compile\s*\()?[^)\n]{0,80}' + DECODE)),
    ('dynamic_system_import', 1, 'Gizlenmiş sistem modülü yüklemesi',
     re.compile(r'__import__\(\s*[\'"](?:os|subprocess|socket|pty)[\'"]\s*\)\s*\.\s*\w+')),
    ('long_blob', 1, 'Büyük gömülü kodlanmış veri', re.compile(r'[\'"][A-Za-z0-9+/=]{1500,}[\'"]')),
    ('keylogger', 2, 'Klavye olayları dinleniyor', re.compile(r'(?:pynput|/dev/input/event|keyboard\.on_press|evdev\.InputDevice)')),
)
# Pairs that are only an attack together.
COMBOS = (
    ('reverse_shell', 4, 'Ters shell: bağlantı kurup shell çalıştırıyor',
     re.compile(r'\.connect\s*\('), re.compile(r'(?:os\.dup2\s*\(|pty\.spawn\s*\(|[\'"]/bin/(?:ba|z)?sh[\'"])')),
    ('bind_shell', 3, 'Port açıp gelen komutu çalıştırıyor',
     re.compile(r'\.listen\s*\('), re.compile(r'(?:subprocess\.\w+\s*\(|os\.system\s*\(|os\.popen\s*\(|pty\.spawn)')),
    ('download_exec', 3, 'İnternetten alınan içerik çalıştırılıyor',
     re.compile(r'(?:urlopen\s*\(|requests\.get\s*\(|urlretrieve\s*\(|http\.client)'),
     re.compile(r'\b(?:exec|eval)\s*\(')),
    # A path named next to an operation on it; a mere mention (docs, lexers,
    # tests) is not enough.
    ('persistence', 2, 'Kalıcılık yeri yazılıyor',
     re.compile(r'(?:[~/][\w./-]*\.(?:bashrc|bash_profile|zshrc)\b|[~/]\.profile\b|/etc/cron|/var/spool/cron|crontab -|'
                r'/etc/systemd/system|\.config/systemd/user|\.ssh/authorized_keys|\.config/autostart|/etc/rc\.local|'
                r'/etc/ld\.so\.preload)'),
     re.compile(r'(?:open\s*\([^)]*[\'"][aw]\+?[\'"]|\.write\s*\(|write_text\s*\(|shutil\.copy|subprocess\.|os\.system\s*\()')),
    ('credentials', 2, 'Parola ya da anahtar dosyası okunuyor',
     re.compile(r'(?:/etc/shadow|\.ssh/id_|Login Data|cookies\.sqlite|key4\.db|logins\.json|\.gnupg/|'
                r'\.aws/credentials|\.config/gcloud)'),
     re.compile(r'(?:open\s*\(|read_text\s*\(|read_bytes\s*\(|shutil\.copy|sqlite3\.connect)')),
)
AUTOSTART_POINTS = 2
# Both halves of a combination must sit this close; large libraries contain
# a network call and an eval far apart without being an attack.
COMBO_WINDOW = 15


def is_python(path, head):
    return path.suffix in ('.py', '.pyw') or (head.startswith(b'#!') and b'python' in head.split(b'\n', 1)[0])


def score(text):
    """Points and the matched lines (number, rule, text)."""
    # Comment lines never count; they describe, they do not act.
    lines = ['' if line.lstrip().startswith('#') else line for line in text.splitlines()]
    hits = []
    for rule, points, title, pattern in RULES:
        for number, line in enumerate(lines, 1):
            if pattern.search(line):
                hits.append({'rule': rule, 'points': points, 'title': title, 'line': number, 'text': line.strip()[:200]})
                break
    for rule, points, title, first, second in COMBOS:
        firsts = [n for n, line in enumerate(lines, 1) if first.search(line)]
        seconds = [n for n, line in enumerate(lines, 1) if second.search(line)]
        pair = next(((a, b) for a in firsts for b in seconds if abs(a - b) <= COMBO_WINDOW), None)
        if pair:
            line = min(pair)
            hits.append({'rule': rule, 'points': points, 'title': title, 'line': line,
                         'text': lines[line - 1].strip()[:200]})
    return sum(h['points'] for h in hits), hits


def autostart_targets():
    """Script paths named by systemd units, cron entries and XDG autostart."""
    sources = (glob.glob('/etc/systemd/system/**/*.service', recursive=True)
               + glob.glob('/home/*/.config/systemd/user/**/*.service', recursive=True)
               + glob.glob('/root/.config/systemd/user/**/*.service', recursive=True)
               + ['/etc/crontab'] + glob.glob('/etc/cron.d/*') + glob.glob('/var/spool/cron/*')
               + glob.glob('/etc/xdg/autostart/*.desktop') + glob.glob('/home/*/.config/autostart/*.desktop')
               + glob.glob('/root/.config/autostart/*.desktop'))
    found = set()
    for source in sources:
        try:
            text = Path(source).read_text(errors='replace')
        except OSError:
            continue
        found.update(re.findall(r'(/[\w./+-]+\.pyw?)\b', text))
        for line in text.splitlines():
            if 'python' in line:
                found.update(re.findall(r'(/[\w./+-]+)', line.split('python', 1)[1])[:2])
    return found


def unpackaged_files(roots=ROOTS):
    count = 0
    for root in roots:
        for directory, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                path = Path(directory) / name
                try:
                    info = path.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE:
                    continue
                if path.suffix not in ('.py', '.pyw') and not info.st_mode & 0o111:
                    continue
                count += 1
                if count > MAX_FILES:
                    return
                yield path


def audit(owned_python, roots=ROOTS, autostart=None):
    """Modified packaged Python and scored unpackaged scripts."""
    modified = []
    for path, (package, digest, algorithm) in owned_python.items():
        if not path.endswith('.py') or not digest or algorithm not in ('8', 'SHA256', 'sha256'):
            continue
        try:
            with open(path, 'rb') as stream:
                actual = hashlib.sha256(stream.read()).hexdigest()
        except OSError:
            continue
        if actual != digest:
            modified.append({'path': path, 'package': package, 'sha256': actual, 'package_sha256': digest})
    starts = autostart if autostart is not None else autostart_targets()
    scored = []
    for path in unpackaged_files(roots):
        if str(path) in owned_python:
            continue
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if not is_python(path, data[:200]):
            continue
        points, hits = score(data.decode('utf-8', 'replace'))
        if str(path) in starts:
            points += AUTOSTART_POINTS
            hits.append({'rule': 'autostart', 'points': AUTOSTART_POINTS, 'title': 'Kendiliğinden başlatılıyor',
                         'line': 0, 'text': ''})
        if points >= 2:
            scored.append({'path': str(path), 'points': points, 'hits': hits,
                           'sha256': hashlib.sha256(data).hexdigest()})
    return modified, scored


def run(store, manual=False, runner=subprocess.run, key=None, lookup=None, now=time.time, roots=ROOTS,
        autostart=None, packaged_dirs=None):
    state = store.get('python_audit', {}) or {}
    if not manual and now() - state.get('updated_at', 0) < INTERVAL:
        return state
    from .binary_audit import _vt_key, rpm_inventory, virustotal, VT_MALICIOUS, VT_PER_RUN
    dirs = packaged_dirs if packaged_dirs is not None else [Path(p) for g in PACKAGED_GLOBS for p in glob.glob(g)]
    owned = rpm_inventory(runner, dirs) if dirs else {}
    modified, scored = audit(owned, roots, autostart)
    key = key if key is not None else _vt_key()
    lookup = lookup or virustotal
    cache = store.get('binary_audit_vt_cache', {}) or {}
    asked = 0
    for item in scored:
        if item['points'] < 4:
            continue
        verdict = cache.get(item['sha256'])
        if verdict is None and key and asked < VT_PER_RUN:
            asked += 1
            try:
                verdict = lookup(item['sha256'], key)
                cache[item['sha256']] = verdict
            except Exception as exc:
                verdict = {'error': str(exc)[:200]}
        if verdict:
            item['virustotal'] = verdict
            if verdict.get('malicious', 0) >= VT_MALICIOUS:
                item['points'] += 4
    store.set('binary_audit_vt_cache', cache)
    stamp = now()
    for item in modified:
        ident = 'SATSUMA-PY-MODIFIED:' + item['path'] + ':' + item['sha256']
        body = {'finding_id': ident, 'rule_id': 'SATSUMA-PY-MODIFIED', 'timestamp': stamp, 'severity': 'critical',
                'classification': 'likely', 'source': 'python_audit',
                'title': 'Paketli Python dosyası paketindekinden farklı', 'summary': item['path'] + ' · paket: ' + item['package'],
                'item': item, 'advice': 'SİLMEYİN. Paketi yeniden kurun: sudo dnf reinstall ' + item['package']}
        store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                         (ident, time.time(), json.dumps(body, ensure_ascii=False)))
    for item in scored:
        high = item['points'] >= 4
        ident = 'SATSUMA-PY-SCRIPT:' + item['path'] + ':' + item['sha256']
        command = 'sudo satsuma-admin karantina al ' + item['path']
        body = {'finding_id': ident, 'rule_id': 'SATSUMA-PY-SCRIPT', 'timestamp': stamp,
                'severity': 'high' if high else 'medium', 'classification': 'suspicious' if high else 'indicator',
                'source': 'python_audit', 'title': 'Şüpheli Python betiği (' + str(item['points']) + ' puan)',
                'summary': item['path'] + ' · ' + ', '.join(h['title'] for h in item['hits']),
                'item': {**item, 'quarantine_proposal': {'path': item['path'], 'sha256': item['sha256'], 'command': command}},
                'advice': 'SİLMEYİN. Betiği siz yazmadıysanız ya da tanımıyorsanız karantinaya alın: ' + command
                          + ' (geri almak mümkün).'}
        store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                         (ident, time.time(), json.dumps(body, ensure_ascii=False)))
    store.db.commit()
    state = {'updated_at': stamp, 'packaged_checked': sum(1 for p in owned if p.endswith('.py')),
             'modified': [i['path'] for i in modified],
             'high': [i['path'] for i in scored if i['points'] >= 4],
             'medium': [i['path'] for i in scored if 2 <= i['points'] < 4],
             'virustotal': 'key_present' if key else 'no_key',
             'items': scored[:200]}
    store.set('python_audit', state)
    return state
