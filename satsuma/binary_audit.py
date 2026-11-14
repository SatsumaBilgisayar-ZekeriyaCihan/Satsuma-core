"""System program audit: what in /usr/bin and /usr/sbin should not be there.

On Fedora /bin and /sbin point into /usr. Every program in /usr/bin,
/usr/sbin, /usr/local/bin and /usr/local/sbin is checked against the RPM
database once a day (or on a manual scan):

- unowned: no installed package owns it (what an intruder usually drops);
- modified: its SHA-256 differs from the digest its package recorded;
- attack tool: a known offensive or traffic-interception tool is installed
  (reported with the package it came from; removing it is the user's call).

Unowned and modified programs are looked up on VirusTotal by SHA-256 only
(never the file) when /etc/satsuma-core/virustotal.key exists, at most 4 per
run (the free API allows 4 a minute), with results cached. Such a program is
quarantined when VirusTotal counts it malicious by at least 3 engines or
ClamAV detected it; a program that is only unowned or modified is reported,
because moving a real system program can leave the machine unbootable.

2.2.14: package entries recorded under /usr/sbin are matched to the file
under its real name in /usr/bin (before this, real sbin programs were shown
as unowned and one was deleted by hand, leaving a VM unbootable); more than
50 unowned programs is treated as a broken query and writes no findings;
every finding says not to delete and how to repair instead.

2.2.15: unpackaged programs under /usr/local (where they belong) are their
own, informational kind; programs that booting or the quarantine rollback
need (ESSENTIAL_PACKAGES, ESSENTIAL_NAMES) are never quarantined, only
reinstalled; every other suspicious program gets a quarantine proposal the
user applies (satsuma-admin karantina al, or the scanners page), and a boot
that does not complete afterwards puts it back.

Sistem programı denetimi: /usr/bin ve /usr/sbin'de olmaması gereken ne var.

Fedora'da /bin ve /sbin /usr'ye bağlıdır. /usr/bin, /usr/sbin,
/usr/local/bin ve /usr/local/sbin'deki her program günde bir kez (ya da elle
taramada) RPM veritabanıyla karşılaştırılır: hiçbir paketin sahiplenmediği
(saldırganın genellikle bıraktığı), paketinin kaydettiği SHA-256'dan farklı
(değiştirilmiş) ve bilinen saldırı ya da trafik dinleme aracı olanlar
bildirilir. Sahipsiz ve değiştirilmiş programlar, /etc/satsuma-core/
virustotal.key varsa, VirusTotal'a yalnızca SHA-256 ile sorulur (dosya asla
gönderilmez), çalışma başına en fazla 4 tane. VirusTotal'da en az 3 motor
zararlı diyorsa ya da ClamAV bulduysa program karantinaya alınır; yalnızca
sahipsiz ya da değiştirilmiş olan bildirilir, çünkü gerçek bir sistem
programını taşımak makineyi açılmaz hâle getirebilir.

2.2.14: /usr/sbin altında kayıtlı paket girdileri dosyanın /usr/bin'deki
gerçek adıyla eşleştirilir (öncesinde gerçek sbin programları paketsiz
görünüyordu, biri elle silindi ve bir sanal makine açılmaz oldu); 50'den
fazla paketsiz program bozuk sorgu sayılır ve bulgu yazılmaz; her bulgu
silinmemesini ve bunun yerine ne yapılacağını söyler.

2.2.15: /usr/local altındaki paket dışı programlar (yerleri orası) ayrı ve
bilgi düzeyinde; açılışın ya da karantina geri almanın ihtiyaç duyduğu
programlar asla karantinaya alınmaz, yalnızca yeniden kurulur; diğer her
şüpheli program için kullanıcının uygulayacağı bir karantina önerisi çıkar
(satsuma-admin karantina al ya da tarayıcılar sayfası) ve sonrasında açılış
tamamlanmazsa program yerine konur.
"""
import hashlib
import json
import os
import stat
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

DIRS = (Path('/usr/bin'), Path('/usr/sbin'), Path('/usr/local/bin'), Path('/usr/local/sbin'))
INTERVAL = 24 * 3600
MAX_HASH_BYTES = 512 * 1024 * 1024
VT_KEY = Path('/etc/satsuma-core/virustotal.key')
VT_PER_RUN = 4
VT_MALICIOUS = 3
# Offensive and traffic-interception tools. Many have honest uses; they are
# reported so the user decides whether they belong on this machine.
ATTACK_TOOLS = {
    'nmap': 'ağ tarayıcı', 'ncat': 'ters bağlantı/tünel', 'nc': 'ters bağlantı/tünel',
    'netcat': 'ters bağlantı/tünel', 'socat': 'tünel', 'hydra': 'parola deneme',
    'medusa': 'parola deneme', 'john': 'parola kırma', 'hashcat': 'parola kırma',
    'msfconsole': 'Metasploit', 'msfvenom': 'Metasploit', 'sqlmap': 'web saldırısı',
    'nikto': 'web tarayıcı', 'ettercap': 'ortadaki adam', 'bettercap': 'ortadaki adam',
    'arpspoof': 'ARP sahteciliği', 'dsniff': 'trafik dinleme', 'mitmproxy': 'ortadaki adam',
    'mitmdump': 'ortadaki adam', 'responder': 'kimlik bilgisi yakalama', 'aircrack-ng': 'Wi-Fi kırma',
    'masscan': 'ağ tarayıcı', 'hping3': 'paket üretici', 'proxychains4': 'trafik gizleme',
    'tcpdump': 'trafik dinleme', 'tshark': 'trafik dinleme', 'dnschef': 'sahte DNS',
}


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def rpm_inventory(runner=subprocess.run, dirs=DIRS):
    """{path: (package, digest or '', algorithm)} for files in dirs."""
    prefixes = tuple(sorted({str(p) + '/' for d in dirs for p in (Path(d), Path(os.path.realpath(d)))}))
    result = runner(['/usr/bin/rpm', '-qa', '--qf', '[%{FILENAMES}\t%{FILEDIGESTS}\t%{=FILEDIGESTALGO}\t%{=NAME}\n]'],
                    capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise RuntimeError('rpm query failed: ' + (result.stderr or '')[:300])
    owned = {}
    real_dirs = {}
    for line in result.stdout.splitlines():
        parts = line.split('\t')
        if len(parts) == 4 and parts[0].startswith(prefixes):
            # Packages may still record /usr/sbin/x although the file lives in
            # /usr/bin since the sbin merge; key every entry by its real path
            # (field log 2026-10-26: real sbin programs were shown as unowned).
            folder, name = os.path.split(parts[0])
            if folder not in real_dirs:
                real_dirs[folder] = os.path.realpath(folder)
            key = os.path.join(real_dirs[folder], name)
            if key not in owned or (parts[1] and not owned[key][1]):
                owned[key] = (parts[3], parts[1], parts[2])
    return owned


def unowned_kind(path):
    """/usr/local is where unpackaged software belongs."""
    return 'local' if str(path).startswith('/usr/local/') else 'unowned'


def audit(owned, dirs=DIRS):
    """Unowned, modified and attack-tool programs in dirs."""
    items = []
    seen = set()
    for directory in dirs:
        # Fedora 42+ merged sbin into bin: /usr/sbin is a link to /usr/bin.
        # Each real directory is read once, under its real name.
        directory = Path(os.path.realpath(directory))
        if directory in seen:
            continue
        seen.add(directory)
        try:
            entries = sorted(directory.iterdir())
        except OSError:
            continue
        for path in entries:
            try:
                info = path.lstat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            name, text = path.name, str(path)
            owner = owned.get(text)
            item = {'path': text, 'package': owner[0] if owner else None, 'size': info.st_size}
            kinds = []
            if owner is None:
                kinds.append(unowned_kind(text))
            elif owner[1] and owner[2] in ('8', 'SHA256', 'sha256') and info.st_size <= MAX_HASH_BYTES:
                try:
                    actual = _sha256(path)
                except OSError:
                    actual = None
                if actual and actual != owner[1]:
                    kinds.append('modified')
                    item['sha256'] = actual
                    item['package_sha256'] = owner[1]
            if name in ATTACK_TOOLS:
                kinds.append('attack_tool')
                item['tool'] = ATTACK_TOOLS[name]
            if kinds:
                if 'sha256' not in item and info.st_size <= MAX_HASH_BYTES:
                    try:
                        item['sha256'] = _sha256(path)
                    except OSError:
                        pass
                items.append({**item, 'kinds': kinds})
    return items


def virustotal(sha256, key, opener=urllib.request.urlopen):
    """VirusTotal verdict for one hash: malicious engine count, or None if unknown."""
    request = urllib.request.Request('https://www.virustotal.com/api/v3/files/' + sha256,
                                     headers={'x-apikey': key, 'accept': 'application/json'})
    try:
        with opener(request, timeout=20) as response:
            data = json.loads(response.read(2 * 1024 * 1024))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {'known': False}
        raise
    stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
    return {'known': True, 'malicious': int(stats.get('malicious', 0)), 'suspicious': int(stats.get('suspicious', 0))}


def _vt_key():
    try:
        info = VT_KEY.stat()
        if info.st_uid != 0 or info.st_mode & 0o007:
            return None
        return VT_KEY.read_text().strip() or None
    except OSError:
        return None


# Advice on every finding: deleting a system program can leave the machine
# unbootable (user's VM, 2026-10-26). Satsuma quarantines confirmed malware
# itself; the user is never asked to delete.
ADVICE = {
    'modified': 'SİLMEYİN. Programı paketinden yeniden kurun: sudo dnf reinstall {package}',
    'unowned': 'SİLMEYİN. Paketsiz olmak zararlı olduğu anlamına gelmez; Satsuma doğrulanmış '
               'zararlıyı (VirusTotal ya da ClamAV) kendisi karantinaya alır. Kontrol: rpm -qf {path}',
    'attack_tool': 'Bu aracı siz kurmadıysanız paketi kaldırın: sudo dnf remove {package}',
    'local': 'Paket dışı kurulum (/usr/local). Siz kurmadıysanız karantina önerisini kullanın.',
}
# Programs that booting and the quarantine rollback itself depend on. They
# are never quarantined, not even when confirmed: the fix is reinstalling
# their package (an unowned file with such a name is reported only).
ESSENTIAL_PACKAGES = frozenset((
    'bash', 'coreutils', 'coreutils-single', 'systemd', 'systemd-udev', 'glibc', 'util-linux', 'util-linux-core',
    'filesystem', 'rpm', 'dnf', 'dnf5', 'sudo', 'shadow-utils', 'policycoreutils', 'libselinux-utils', 'kmod',
    'dracut', 'grub2-tools', 'grub2-tools-minimal', 'python3', 'e2fsprogs', 'btrfs-progs', 'xfsprogs',
    'NetworkManager', 'dbus-broker', 'polkit', 'gdm', 'gnome-shell'))
ESSENTIAL_NAMES = frozenset(('sh', 'bash', 'mv', 'cp', 'cat', 'rm', 'mkdir', 'rmdir', 'chmod', 'chown', 'touch',
                             'restorecon', 'systemctl', 'mount', 'umount', 'login', 'sulogin', 'agetty', 'sudo', 'su',
                             'python3', 'rpm', 'dnf', 'dnf5', 'ldconfig', 'modprobe', 'kmod', 'init'))


def quarantine_allowed(item):
    """Whether a program may be quarantined at all (with rollback)."""
    return item.get('package') not in ESSENTIAL_PACKAGES and Path(item['path']).name not in ESSENTIAL_NAMES
# More unowned programs than this means the package query did not match the
# disk; no per-file findings are written then, only an error.
UNOWNED_SANITY_LIMIT = 50

FINDINGS = {
    'modified': ('SATSUMA-BIN-MODIFIED', 'critical', 'likely', 'Sistem programı paketindekinden farklı'),
    'unowned': ('SATSUMA-BIN-UNOWNED', 'medium', 'indicator', 'Hiçbir pakete ait olmayan sistem programı'),
    'attack_tool': ('SATSUMA-BIN-ATTACKTOOL', 'medium', 'indicator', 'Saldırı aracı kurulu'),
    'local': ('SATSUMA-BIN-LOCAL', 'info', 'indicator', 'Paket dışı kurulmuş program (/usr/local)'),
}


def run(store, manual=False, runner=subprocess.run, clamav_paths=(), key=None, lookup=virustotal,
        quarantine=None, now=time.time, dirs=DIRS):
    """Audit, look up, quarantine confirmed malware and record findings."""
    state = store.get('binary_audit', {}) or {}
    if not manual and now() - state.get('updated_at', 0) < INTERVAL:
        return state
    owned = rpm_inventory(runner, dirs)
    items = audit(owned, dirs)
    unowned = sum(1 for i in items if 'unowned' in i['kinds'])
    if unowned > UNOWNED_SANITY_LIMIT or not owned:
        state = {'updated_at': now(), 'checked_dirs': [str(d) for d in dirs], 'counts': {},
                 'error': f'Denetim güvenilmez: {unowned} paketsiz program ({len(owned)} paket kaydı); '
                          'paket sorgusu diskle eşleşmedi. Hiçbir bulgu yazılmadı; hiçbir dosyayı silmeyin.',
                 'quarantined': [], 'items': []}
        store.set('binary_audit', state)
        return state
    cache = store.get('binary_audit_vt_cache', {}) or {}
    key = key if key is not None else _vt_key()
    asked = 0
    for item in items:
        if not ({'unowned', 'modified', 'local'} & set(item['kinds'])) or not item.get('sha256'):
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
        confirmed = (verdict or {}).get('malicious', 0) >= VT_MALICIOUS or item['path'] in set(clamav_paths)
        if confirmed and quarantine_allowed(item):
            item['quarantine'] = (quarantine or _quarantine)(store, item)
        elif confirmed:
            item['quarantine'] = {'status': 'not_quarantined', 'source': item['path'],
                                  'reason': 'Açılış için gerekli program; paketi yeniden kurun: sudo dnf reinstall '
                                            + str(item.get('package') or '')}
        if quarantine_allowed(item) and not item.get('quarantine'):
            # Offered, never done by itself: the user decides; a boot that does
            # not complete afterwards puts the program back.
            item['quarantine_proposal'] = {'path': item['path'], 'sha256': item.get('sha256'),
                                           'command': 'sudo satsuma-admin karantina al ' + item['path']}
    store.set('binary_audit_vt_cache', cache)
    for item in items:
        for kind in item['kinds']:
            rule_id, severity, classification, title = FINDINGS[kind]
            if kind == 'attack_tool':
                title += ': ' + Path(item['path']).name + ' (' + item['tool'] + ')'
            ident = rule_id + ':' + item['path'] + ':' + str(item.get('sha256'))
            body = {'finding_id': ident, 'rule_id': rule_id, 'timestamp': now(), 'severity': severity,
                    'classification': classification, 'source': 'binary_audit', 'title': title,
                    'summary': item['path'] + (' · paket: ' + item['package'] if item['package'] else ' · paket yok'),
                    'item': item, 'advice': ADVICE[kind].format(package=item.get('package') or '', path=item['path'])
                    + (' Karantinaya almak için: ' + item['quarantine_proposal']['command']
                       + ' (sistem açılmazsa kendiliğinden geri alınır).'
                       if item.get('quarantine_proposal') and kind != 'attack_tool' else ''),
                    'status': 'QUARANTINED' if (item.get('quarantine') or {}).get('status') == 'quarantined' else 'REVIEW'}
            store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                             (ident, time.time(), json.dumps(body, ensure_ascii=False)))
    current = {FINDINGS[kind][0] + ':' + i['path'] for i in items for kind in i['kinds']}
    for ident, body in store.db.execute("SELECT finding_id, body FROM findings WHERE finding_id LIKE 'SATSUMA-BIN-%'").fetchall():
        data = json.loads(body)
        seen_as = data.get('rule_id', '') + ':' + (data.get('item') or {}).get('path', '')
        if seen_as not in current and data.get('status') != 'CLEARED':
            # An earlier audit (e.g. 2.2.13's sbin mismatch) reported what is fine now.
            data.update(status='CLEARED', severity='info',
                        cleared='Son denetimde sorun yok; önceki bulgu yanlış alarmdı ya da durum düzeldi.')
            store.db.execute('UPDATE findings SET body=? WHERE finding_id=?', (json.dumps(data, ensure_ascii=False), ident))
    store.db.commit()
    state = {'updated_at': now(), 'checked_dirs': [str(d) for d in dirs],
             'counts': {kind: sum(1 for i in items if kind in i['kinds']) for kind in FINDINGS},
             'virustotal': 'key_present' if key else 'no_key', 'virustotal_lookups': asked,
             'quarantined': [i['path'] for i in items if (i.get('quarantine') or {}).get('status') == 'quarantined'],
             'items': items[:200]}
    store.set('binary_audit', state)
    return state


def _quarantine(store, item):
    from .scan_quarantine import inspect_target, quarantine_target
    try:
        target = inspect_target(item['path'])
        return quarantine_target(target, lambda record: store.add('quarantine_actions',
                                 {**record, 'automatic': True, 'source': 'binary_audit', 'timestamp': time.time()}),
                                 system_ok=True)
    except (OSError, ValueError, RuntimeError) as exc:
        return {'status': 'not_quarantined', 'source': item['path'], 'reason': str(exc)[:250]}
