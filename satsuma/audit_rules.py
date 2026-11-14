"""Satsuma's own kernel audit rules, loaded locked (audit K4, K6).

2.1.6 read audit.log but never loaded a rule, so the 36 file rules and every
short-lived command went unseen. This module renders a fixed rule set (every
execve, and writes to /etc, binaries, systemd, /boot, man pages, /usr/local,
fonts and locale data), writes it last in /etc/audit/rules.d, loads it with
augenrules and verifies it in the kernel. The set ends with ``-e 2``: once
loaded, not even root can change or remove a rule until the next boot, which
is the point. A watched path that is a symbolic link is never followed; it is
reported instead, because a redirected system directory is itself an attack.
Lines in other rules.d files that would switch this set off (``-a task,never``,
which upstream audit says to remove when syscall auditing is needed; ``-e 0``
or ``-e 1``; ``-D`` after our file) are commented out, with the original file
kept under /var/lib/satsuma-core/audit-backup.

Satsuma'nın kendi çekirdek audit kuralları; kilitli yüklenir (denetim K4, K6).

2.1.6 audit.log'u okuyordu ama hiç kural yüklemiyordu; bu yüzden 36 dosya
kuralı ve kısa ömürlü her komut görülmüyordu. Bu modül sabit bir kural seti
üretir (her execve; /etc, çalıştırılabilir dosyalar, systemd, /boot, man
sayfaları, /usr/local, fontlar ve yerelleştirme verisine yazma), onu
/etc/audit/rules.d içine en sona yazar, augenrules ile yükler ve çekirdekte
doğrular. Set ``-e 2`` ile biter: yüklendikten sonra bir sonraki açılışa kadar
root bile hiçbir kuralı değiştiremez ya da silemez; amaç da budur. İzlenen
bir yol sembolik bağlantıysa izlenmez, bildirilir; yönlendirilmiş bir sistem
dizini başlı başına saldırıdır. Diğer rules.d dosyalarında bu seti devre
dışı bırakacak satırlar (resmi audit'in, sistem çağrısı izlemesi gerekiyorsa
kaldırılmasını söylediği ``-a task,never``; ``-e 0`` ya da ``-e 1``; bizim
dosyamızdan sonra gelen ``-D``) yorum satırına çevrilir, dosyanın aslı
/var/lib/satsuma-core/audit-backup altında saklanır.
"""
import json
import os
import stat
import subprocess
import time
from pathlib import Path

RULE_FILE = Path('/etc/audit/rules.d/99-satsuma-core.rules')
BACKUP_DIR = Path('/var/lib/satsuma-core/audit-backup')
NEUTRALIZED = '# Disabled by Satsuma (audit K6), original kept in {backup}: '

STATUS_FILE = Path('/var/lib/satsuma-core/audit-rules.json')
HEADER = '## Managed by Satsuma Core (audit K4/K6). Generated; do not edit.'

EXEC_RULES = [
    '-a always,exit -F arch=b64 -S execve,execveat -k satsuma_exec',
    '-a always,exit -F arch=b32 -S execve,execveat -k satsuma_exec',
]

# (path, key). Directory watches are recursive. Yazma ve öznitelik değişikliği izlenir.
WATCHES = [
    ('/etc', 'satsuma_etc'),
    ('/usr/bin', 'satsuma_bin'),
    ('/usr/sbin', 'satsuma_bin'),
    ('/usr/libexec', 'satsuma_bin'),
    ('/usr/lib/systemd', 'satsuma_systemd'),
    ('/usr/lib/udev', 'satsuma_systemd'),
    ('/boot', 'satsuma_boot'),
    ('/usr/share/man', 'satsuma_man'),
    ('/usr/local', 'satsuma_local'),
    ('/usr/share/fonts', 'satsuma_fonts'),
    ('/usr/share/locale', 'satsuma_locale'),
    ('/usr/lib/locale', 'satsuma_locale'),
    ('/usr/lib64/gconv', 'satsuma_locale'),
]
# Per-user font directories (font attacks), relative to each home.
USER_FONT_DIRS = ('.local/share/fonts', '.fonts')


def user_homes(passwd='/etc/passwd'):
    homes = []
    try:
        for line in Path(passwd).read_text().splitlines():
            parts = line.split(':')
            if len(parts) >= 7 and parts[2].isdigit() and 1000 <= int(parts[2]) < 60000 and parts[5].startswith('/home/'):
                homes.append(parts[5])
    except OSError:
        pass
    return sorted(set(homes))


# The merged-/usr links Fedora itself ships, with their only valid targets.
# Fedora'nın kendi gönderdiği birleşik /usr bağlantıları ve geçerli hedefleri.
DISTRIBUTION_LINKS = {
    '/bin': {'usr/bin'}, '/sbin': {'usr/sbin', 'usr/bin'}, '/lib': {'usr/lib'},
    '/lib64': {'usr/lib64'}, '/usr/sbin': {'bin'},
}


def classify(path, lstat=os.lstat, readlink=os.readlink):
    """'ok', 'missing', 'distribution_link' or 'symlink'."""
    try:
        info = lstat(path)
    except FileNotFoundError:
        return 'missing'
    if stat.S_ISLNK(info.st_mode):
        try:
            target = readlink(path)
        except OSError:
            return 'symlink'
        return 'distribution_link' if target in DISTRIBUTION_LINKS.get(path, ()) else 'symlink'
    return 'ok'


def watch_targets(homes=None, lstat=os.lstat, readlink=os.readlink):
    """Watch list plus the paths refused, without following any link.

    A distribution link (e.g. /usr/sbin -> bin on merged Fedora) is skipped:
    its target is already watched. Any other link is refused and reported.
    """
    targets, refused = [], []
    paths = list(WATCHES)
    for home in user_homes() if homes is None else homes:
        paths += [(os.path.join(home, rel), 'satsuma_fonts') for rel in USER_FONT_DIRS]
    for path, key in paths:
        kind = classify(path, lstat, readlink)
        # A parent that is a link redirects the watch just the same.
        parent = os.path.dirname(path)
        while kind == 'ok' and parent not in ('/', ''):
            if classify(parent, lstat, readlink) == 'symlink':
                kind = 'symlink'
            parent = os.path.dirname(parent)
        if kind == 'ok':
            targets.append((path, key))
        elif kind == 'symlink':
            refused.append({'path': path, 'reason': 'symlink'})
    return targets, refused


def render(targets):
    lines = [HEADER, *EXEC_RULES]
    for path, key in targets:
        if any(ch.isspace() for ch in path):
            raise ValueError('watch path with whitespace: ' + path)
        lines.append(f'-w {path} -p wa -k {key}')
    lines.append('-e 2')
    return '\n'.join(lines) + '\n'


def run(args, runner=subprocess.run):
    return runner(args, capture_output=True, text=True, timeout=30)


def kernel_state(runner=subprocess.run):
    status = run(['/usr/sbin/auditctl', '-s'], runner)
    enabled = None
    for line in status.stdout.splitlines():
        if line.startswith('enabled '):
            enabled = line.split()[1]
    listed = run(['/usr/sbin/auditctl', '-l'], runner)
    return enabled, listed.stdout.splitlines()


def loaded(expected_text, listed):
    """Every Satsuma key appears in the kernel the expected number of times."""
    keys = {}
    for line in expected_text.splitlines():
        if ' -k ' in line:
            key = line.rsplit(' -k ', 1)[1]
            keys[key] = keys.get(key, 0) + 1
    for key, count in keys.items():
        if sum(1 for line in listed if line.endswith('-F key=' + key) or line.endswith(' -k ' + key)) < count:
            return False
    return True


def _conflict(tokens, after_ours):
    """Lines in other rule files that would switch Satsuma's rules off.

    ``-a task,never`` suppresses syscall auditing for every task; upstream
    audit says to remove it when syscall auditing is needed. ``-e 0``/``-e 1``
    could unlock the set, and ``-D`` after our file would delete our rules.
    """
    if tokens[:2] in (['-a', 'task,never'], ['-a', 'never,task']):
        return True
    if tokens in (['-e', '0'], ['-e', '1']):
        return True
    return after_ours and tokens[:1] == ['-D']


def neutralize_conflicts(own=RULE_FILE, backup_dir=BACKUP_DIR, now=None):
    """Comment out conflicting lines in other rules.d files, keeping a backup."""
    now = int(time.time() if now is None else now)
    changes = []
    for other in sorted(own.parent.glob('*.rules')):
        if other.name == own.name or other.is_symlink() or not other.is_file():
            continue
        after_ours = other.name > own.name
        try:
            original = other.read_text()
        except OSError as exc:
            changes.append({'file': str(other), 'error': str(exc)})
            continue
        backup = backup_dir / f'{other.name}.{now}'
        marker = NEUTRALIZED.format(backup=backup)
        lines, hit = [], []
        for line in original.splitlines():
            if _conflict(line.split('#', 1)[0].split(), after_ours):
                hit.append(line.strip())
                line = marker + line.strip()
            lines.append(line)
        if not hit:
            continue
        try:
            backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            backup.write_text(original)
            os.chmod(backup, 0o600)
            write_rules('\n'.join(lines) + '\n', other)
        except OSError as exc:
            changes.append({'file': str(other), 'lines': hit, 'error': str(exc)})
            continue
        changes.append({'file': str(other), 'lines': hit, 'backup': str(backup)})
    return changes


def write_rules(text, path=RULE_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
    with os.fdopen(fd, 'w') as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def apply(runner=subprocess.run, path=RULE_FILE, homes=None, lstat=os.lstat, readlink=os.readlink,
          backup_dir=BACKUP_DIR):
    targets, refused = watch_targets(homes, lstat, readlink)
    neutralized = neutralize_conflicts(path, backup_dir)
    text = render(targets)
    current = path.read_text() if path.exists() else None
    if current != text:
        write_rules(text, path)
    enabled, listed = kernel_state(runner)
    if enabled == '2':
        # Locked: correct only if our rules are already in the kernel.
        status = 'LOCKED' if loaded(text, listed) else 'REBOOT_REQUIRED'
    else:
        result = run(['/usr/sbin/augenrules', '--load'], runner)
        enabled, listed = kernel_state(runner)
        if result.returncode or not loaded(text, listed):
            status = 'LOAD_FAILED'
        else:
            status = 'LOCKED' if enabled == '2' else 'LOADED_UNLOCKED'
    if status in ('LOCKED', 'LOADED_UNLOCKED') and any(line.startswith('-a never,task') for line in listed):
        # Suppression is still in the kernel. If we just removed it from the
        # files, the next boot loads without it; otherwise it is unexplained.
        removed = any(not c.get('error') for c in neutralized)
        status = 'REBOOT_REQUIRED' if removed and enabled == '2' else 'SYSCALL_AUDIT_SUPPRESSED'
    report = {'status': status, 'updated_at': time.time(), 'rule_file': str(path),
              'neutralized': neutralized,
              'watches': [p for p, _ in targets], 'refused_symlinks': refused,
              'immutable': enabled == '2'}
    return report


def save_status(report, path=STATUS_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.tmp')
    tmp.write_text(json.dumps(report, sort_keys=True))
    os.replace(tmp, path)


def main():
    report = apply()
    save_status(report)
    print(json.dumps(report, ensure_ascii=False))
    # Never stop the audit worker over this; health reports the status.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
