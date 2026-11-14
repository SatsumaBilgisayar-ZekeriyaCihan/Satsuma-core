"""systemd audit: what starts on this machine, how, and whether it changed.

Daily inside the security scan (and on manual scans); read-only, no unit is
stopped or edited:

- boot timing: systemd-analyze time, blame and critical-chain, and the
  failed units (also the input of satsuma.boot_correlator);
- packaged systemd files (/usr/lib/systemd: units, generators and
  systemd's own programs) against their RPM digests; a changed one is
  critical;
- units added locally: /etc/systemd/system units and drop-ins, user units
  (~/.config/systemd/user) and extra generators. The first audit is the
  baseline; a unit that appears later is high. A unit that starts from
  /tmp, /dev/shm, /var/tmp or a hidden directory, runs "-c" commands, or
  sets LD_PRELOAD / LD_LIBRARY_PATH is flagged whatever its age;
- systemd-analyze verify and security for the local units (distribution
  units are summarised, not reported one by one).

Satsuma's own units (satsuma-*) are left out.

systemd denetimi: bu makinede ne, nasıl başlıyor ve değişti mi. Güvenlik
taraması içinde günde bir; salt okunur. Açılış süreleri ve başarısız
servisler (satsuma.boot_correlator'ın girdisi), /usr/lib/systemd
dosyalarının RPM özetleriyle karşılaştırması (değişen kritik), yerel olarak
eklenen servisler, ek ayar dosyaları, kullanıcı servisleri ve
generator'lar (ilk denetim temel; sonradan eklenen yüksek; /tmp, gizli
klasör, -c ya da LD_PRELOAD kullanan her zaman işaretlenir) ve yerel
servisler için systemd-analyze verify ve security. Satsuma'nın kendi
servisleri dışarıda bırakılır.
"""
import glob
import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

INTERVAL = 24 * 3600
LOCAL_GLOBS = ('/etc/systemd/system/*.service', '/etc/systemd/system/*.timer', '/etc/systemd/system/*.socket',
               '/etc/systemd/system/*.path', '/etc/systemd/system/*.d/*.conf',
               '/etc/systemd/user/*.service', '/home/*/.config/systemd/user/*.service',
               '/home/*/.config/systemd/user/*.timer', '/root/.config/systemd/user/*.service')
GENERATOR_GLOBS = ('/etc/systemd/system-generators/*', '/usr/local/lib/systemd/system-generators/*',
                   '/etc/systemd/user-generators/*', '/usr/local/lib/systemd/user-generators/*')
SUSPICIOUS = (
    ('temp_path', re.compile(r'^Exec\w*=.*?(?:/tmp/|/dev/shm/|/var/tmp/)', re.M), 'Geçici klasörden çalışıyor'),
    ('hidden_path', re.compile(r'^Exec\w*=.*?/\.[\w-]+/', re.M), 'Gizli klasörden çalışıyor'),
    ('shell_c', re.compile(r'^Exec\w*=.*?\b(?:sh|bash|python3?|perl)\s+-c\b', re.M), 'Komut satırından kod çalıştırıyor (-c)'),
    ('preload', re.compile(r'^Environment\w*=.*?\bLD_(?:PRELOAD|LIBRARY_PATH)=', re.M), 'Kütüphane enjeksiyonu (LD_PRELOAD)'),
    ('download', re.compile(r'^Exec\w*=.*?\b(?:curl|wget)\b', re.M), 'Açılışta internetten indiriyor'),
)


def _run(runner, args, timeout=60):
    try:
        result = runner(args, capture_output=True, text=True, timeout=timeout)
        return result.stdout if result.returncode == 0 else ''
    except (OSError, subprocess.SubprocessError):
        return ''


def parse_blame(text, limit=15):
    rows = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            rows.append({'time': ' '.join(parts[:-1]), 'unit': parts[-1]})
    return rows[:limit]


def boot_timing(runner=subprocess.run):
    failed = [line.split()[0] for line in _run(runner, ['systemctl', '--failed', '--plain', '--no-legend']).splitlines()
              if line.split()]
    return {'time': _run(runner, ['systemd-analyze', 'time']).strip()[:500],
            'blame': parse_blame(_run(runner, ['systemd-analyze', 'blame', '--no-pager'])),
            'critical_chain': _run(runner, ['systemd-analyze', 'critical-chain', '--no-pager']).strip()[:4000],
            'failed': failed}


def local_units(globs=LOCAL_GLOBS):
    found = []
    for pattern in globs:
        for name in glob.glob(pattern):
            path = Path(name)
            if path.is_symlink() or not path.is_file() or Path(name).name.startswith('satsuma-'):
                continue
            if '/satsuma-' in name:
                continue
            try:
                text = path.read_text(errors='replace')
            except OSError:
                continue
            flags = [{'rule': rule, 'title': title, 'line': m.group(0)[:200]}
                     for rule, pattern_, title in SUSPICIOUS for m in [pattern_.search(text)] if m]
            found.append({'path': name, 'sha256': hashlib.sha256(text.encode()).hexdigest(),
                          'exec': re.findall(r'^Exec\w*=(.*)$', text, re.M)[:5], 'flags': flags})
    return found


def generators(globs=GENERATOR_GLOBS):
    return sorted(name for pattern in globs for name in glob.glob(pattern) if Path(name).is_file())


def verify(paths, runner=subprocess.run):
    problems = {}
    for path in paths:
        if not path.endswith(('.service', '.timer', '.socket', '.path')) or '/home/' in path or '/user/' in path:
            continue
        try:
            result = runner(['systemd-analyze', 'verify', path], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            continue
        output = (result.stderr or '').strip()
        if result.returncode != 0 and output:
            problems[path] = output[:500]
    return problems


def security(runner=subprocess.run):
    """Exposure per loaded service: {unit: (score, rating)}."""
    scores = {}
    for line in _run(runner, ['systemd-analyze', 'security', '--no-pager'], timeout=120).splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3:
            try:
                scores[parts[0]] = (float(parts[1]), parts[2])
            except ValueError:
                continue
    return scores


def _finding(store, ident, severity, classification, title, summary, advice, extra, stamp):
    body = {'finding_id': ident, 'rule_id': ident.split(':', 1)[0], 'timestamp': stamp, 'severity': severity,
            'classification': classification, 'source': 'systemd_audit', 'title': title, 'summary': summary,
            'advice': advice, **extra}
    store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                     (ident, time.time(), json.dumps(body, ensure_ascii=False)))


def run(store, manual=False, runner=subprocess.run, now=time.time, local_globs=LOCAL_GLOBS,
        generator_globs=GENERATOR_GLOBS, packaged_dirs=None):
    state = store.get('systemd_audit', {}) or {}
    if not manual and now() - state.get('updated_at', 0) < INTERVAL:
        return state
    stamp = now()
    timing = boot_timing(runner)
    from .binary_audit import rpm_inventory
    dirs = packaged_dirs if packaged_dirs is not None else [Path('/usr/lib/systemd')]
    owned = rpm_inventory(runner, dirs) if dirs else {}
    modified = []
    for path, (package, digest, algorithm) in owned.items():
        if not digest or algorithm not in ('8', 'SHA256', 'sha256') or '/satsuma-' in path:
            continue
        try:
            with open(path, 'rb') as stream:
                actual = hashlib.sha256(stream.read()).hexdigest()
        except OSError:
            continue
        if actual != digest:
            modified.append({'path': path, 'package': package, 'sha256': actual})
    units = local_units(local_globs)
    gens = generators(generator_globs)
    baseline = store.get('systemd_audit_baseline', None)
    first = baseline is None
    known = set(baseline or [])
    for item in modified:
        _finding(store, f"SATSUMA-SYSTEMD-MODIFIED:{item['path']}:{item['sha256']}", 'critical', 'likely',
                 'systemd dosyası paketindekinden farklı', item['path'] + ' · paket: ' + item['package'],
                 'SİLMEYİN. Paketi yeniden kurun: sudo dnf reinstall ' + item['package'], {'item': item}, stamp)
    for unit in units:
        identity = unit['path'] + ':' + unit['sha256']
        if not first and identity not in known:
            _finding(store, f"SATSUMA-SYSTEMD-NEWUNIT:{identity}", 'high', 'suspicious',
                     'Yeni ya da değişmiş yerel systemd birimi', unit['path'] + ' · ' + '; '.join(unit['exec'][:2]),
                     'Siz eklemediyseniz inceleyin; durdurmak için: sudo systemctl disable --now <birim>',
                     {'unit': unit}, stamp)
        if unit['flags']:
            _finding(store, f"SATSUMA-SYSTEMD-FLAG:{identity}", 'high', 'suspicious',
                     'Şüpheli systemd birimi: ' + ', '.join(f['title'] for f in unit['flags']),
                     unit['path'] + ' · ' + unit['flags'][0]['line'],
                     'Siz eklemediyseniz inceleyin; durdurmak için: sudo systemctl disable --now <birim>',
                     {'unit': unit}, stamp)
    for name in gens:
        if first or name not in known:
            _finding(store, f"SATSUMA-SYSTEMD-GENERATOR:{name}", 'high' if not first else 'medium', 'suspicious',
                     'Ek systemd generator', name, 'Generator açılışta birim üretir; siz eklemediyseniz inceleyin.',
                     {}, stamp)
    problems = verify([u['path'] for u in units], runner)
    for path, text in problems.items():
        _finding(store, f"SATSUMA-SYSTEMD-VERIFY:{path}:{hashlib.sha256(text.encode()).hexdigest()[:16]}", 'low',
                 'indicator', 'systemd biriminde hata', path + ' · ' + text[:300], 'Birim dosyasını düzeltin.', {}, stamp)
    exposure = security(runner)
    store.db.commit()
    store.set('systemd_audit_baseline', sorted({u['path'] + ':' + u['sha256'] for u in units} | set(gens) | known))
    state = {'updated_at': stamp, 'timing': timing, 'modified': [m['path'] for m in modified],
             'local_units': [u['path'] for u in units],
             'new_units': [] if first else [u['path'] for u in units if u['path'] + ':' + u['sha256'] not in known],
             'flagged_units': [u['path'] for u in units if u['flags']], 'generators': gens,
             'verify_errors': problems,
             'exposure': {'unsafe': sum(1 for s, r in exposure.values() if r == 'UNSAFE'), 'total': len(exposure),
                          'worst': sorted(((s, u) for u, (s, r) in exposure.items()), reverse=True)[:10]}}
    store.set('systemd_audit', state)
    return state
