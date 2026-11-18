"""System accounts (UID 1-999, not root) must never hold a usable password.

Owner's report 2026-11-16: on Fedora Workstation the logs keep showing a
systemd account below UID 1000 with a changed password and a login, and
nothing stops it. A service account has no password: its hash is "!", "*" or
"!!" (locked). A real hash ($id$...) on such an account is a way in for anyone
who knows it.

What this module does, and does not do:

* find(): system accounts whose shadow hash is usable, or whose shell is
  interactive (the shell is only reported, never changed alone);
* lock(): copy the whole /etc/shadow line to the evidence folder (mode 0600),
  then ``usermod -L`` the account (the hash stays, behind a "!"); an
  interactive shell is replaced with /usr/sbin/nologin. No account is
  deleted and root and normal users (UID >= 1000) are never touched; a second
  UID 0 account (root under another name) is locked the same way (2.2.38);
* /etc/passwd and /etc/shadow are NOT made immutable (chattr +i): that would
  stop passwd, useradd, systemd-sysusers and every package that creates a
  service user, including Satsuma's own install. The guard runs every cycle
  of the kernel guard instead, so an undone lock is repeated within a minute.

Sistem hesapları (UID 1-999, root hariç) kullanılabilir parola taşımamalıdır.
Sahibinin bildirimi 2026-11-16: Fedora Workstation'da günlükler 1000 altındaki
bir systemd hesabının parolasının değiştiğini ve giriş yaptığını gösteriyor,
hiçbir şey durdurmuyor. Servis hesabının parolası yoktur: özet "!", "*" ya da
"!!" olur. Bu modül kullanılabilir özeti bulur, shadow satırını kanıt
klasörüne kopyalar, hesabı ``usermod -L`` ile kilitler; etkileşimli kabuğu
nologin yapar. Hesap silinmez; root ve normal kullanıcılara dokunulmaz.
/etc/passwd ve /etc/shadow değiştirilemez (chattr +i) yapılmaz: passwd,
useradd, systemd-sysusers ve servis kullanıcısı kuran her paket, Satsuma'nın
kendi kurulumu dahil, çalışmaz olurdu.
"""
import os
import time
from pathlib import Path

PASSWD = Path('/etc/passwd')
SHADOW = Path('/etc/shadow')
EVIDENCE = Path('/var/lib/satsuma-core/kernel-guard/account-evidence')
USERMOD = '/usr/sbin/usermod'
NOLOGIN = '/usr/sbin/nologin'
FIRST_NORMAL_UID = 1000
INTERACTIVE = frozenset(('/bin/bash', '/usr/bin/bash', '/bin/sh', '/usr/bin/sh', '/bin/zsh', '/usr/bin/zsh',
                         '/bin/fish', '/usr/bin/fish', '/bin/dash', '/usr/bin/dash', '/bin/tcsh', '/usr/bin/tcsh'))
# Accounts whose shell is not a login: shutdown, sync and halt keep theirs.
NOT_A_LOGIN = frozenset(('/sbin/shutdown', '/sbin/halt', '/bin/sync', '/usr/sbin/shutdown', '/usr/sbin/halt'))


def _rows(path):
    try:
        text = Path(path).read_text(errors='replace')
    except OSError:
        return None
    return [line.split(':') for line in text.splitlines() if line and not line.startswith('#')]


def usable(hash_field):
    """True when the field lets someone in: any hash ($id$ or old DES) or an empty field.

    2.2.38 (review 2026-11-18): only "$..." counted, so an empty field (no
    password at all under a PAM stack with nullok) and a 13-character DES hash
    were missed. Locked fields start with "!" or "*"; a missing shadow line
    (None) is not a password.
    Boş alan (nullok ile parolasız giriş) ve eski DES özeti de kullanılabilir sayılır.
    """
    if hash_field is None:
        return False
    return hash_field == '' or hash_field[0] not in '!*'


def _at_risk_uid(name, uid):
    """System accounts (1-999, 65534, systemd DynamicUser range) and a second UID 0."""
    if uid == 0:
        return name != 'root'
    return 1 <= uid < FIRST_NORMAL_UID or uid == 65534 or 61184 <= uid <= 65519


def find(passwd=PASSWD, shadow=SHADOW):
    """[{name, uid, shell, hash_usable, interactive_shell}] for system accounts at risk; None if unreadable.

    2.2.38: also a second UID 0 account (whatever its password: it is root under
    another name), the overflow user 65534 and systemd's dynamic users.
    2.2.38: ikinci UID 0 hesabı, 65534 ve systemd dinamik kullanıcıları da denetlenir.
    """
    accounts, shadows = _rows(passwd), _rows(shadow)
    if accounts is None or shadows is None:
        return None
    hashes = {row[0]: row[1] for row in shadows if len(row) >= 2}
    found = []
    for row in accounts:
        if len(row) < 7:
            continue
        name, uid, shell = row[0], row[2], row[6]
        try:
            uid = int(uid)
        except ValueError:
            continue
        if not _at_risk_uid(name, uid):
            continue
        field = hashes.get(name)
        if row[1] not in ('x', ''):
            field = row[1]   # a hash kept in /etc/passwd itself
        has_password = usable(field)
        interactive = shell in INTERACTIVE and shell not in NOT_A_LOGIN
        second_root = uid == 0
        if has_password or (second_root and interactive):
            found.append({'name': name, 'uid': uid, 'shell': shell, 'hash_usable': has_password,
                          'interactive_shell': interactive, 'second_root': second_root,
                          'empty_password': field == ''})
    return found


def _keep_evidence(name, shadow, evidence):
    evidence = Path(evidence)
    evidence.mkdir(parents=True, exist_ok=True, mode=0o700)
    line = next((row for row in (shadow.read_text(errors='replace').splitlines()) if row.split(':', 1)[0] == name), '')
    target = evidence / ('%s.%d.shadow' % (name, int(time.time())))
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(line + '\n')
    return str(target)


def lock(entries, runner, shadow=SHADOW, evidence=EVIDENCE):
    """Lock every entry; [{name, locked, shell_changed, evidence, error}]. Evidence first, then the lock."""
    results = []
    for entry in entries or ():
        name = entry['name']
        result = {'name': name, 'uid': entry['uid'], 'locked': False, 'shell_changed': False}
        try:
            result['evidence'] = _keep_evidence(name, Path(shadow), evidence)
        except OSError as exc:
            result['error'] = 'evidence_not_kept: ' + (exc.strerror or str(exc))
            results.append(result)   # no evidence, no change
            continue
        command = [USERMOD, '-L'] + (['-s', NOLOGIN] if entry.get('interactive_shell') else []) + [name]
        try:
            done = runner(command, capture_output=True, text=True, timeout=30)
            result['locked'] = done.returncode == 0
            result['shell_changed'] = result['locked'] and bool(entry.get('interactive_shell'))
            if done.returncode:
                result['error'] = (done.stderr or '').strip()[:200]
        except (OSError, ValueError) as exc:
            result['error'] = type(exc).__name__
        results.append(result)
    return results
