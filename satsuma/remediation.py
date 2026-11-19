"""Undo what a one-shot attack command left behind (2.2.56).

Owner's decision 2026-11-19 ("her şey"): a command such as `nft flush ruleset`,
`useradd -o -u 0`, or a write of a cron job, a systemd unit, an autostart entry,
authorized_keys or ld.so.preload is over within milliseconds; stopping the process
comes too late. Satsuma now undoes the effect:

* firewall deleted -> satsuma-firewall-watch runs at once (tables put back);
* persistence file written -> the file is moved into quarantine (restorable with
  `sudo satsuma-admin karantina geri-al <kimlik>`); a systemd unit is also stopped and
  systemd reloaded, a udev rule makes udev reload;
* new account with UID 0 or a duplicate UID, or any new account -> the account is
  locked and expired (`usermod -L -e 1`); an account added to wheel/sudo is taken out
  of the group again.

Never touched, whatever matched: root, the desktop owner, Satsuma's own accounts and
files, /etc/passwd, shadow, group, sudoers, PAM, /etc/profile, /etc/crontab, SELinux
configuration (breaking these would lock the owner out; they raise the alarm only).
The plan is made in the teams service and checked again, independently, by privd,
which alone acts. Every action is written to the record (actions: remediation.*).

Tek seferlik saldırı komutunun bıraktığını geri alır: güvenlik duvarı hemen geri
yüklenir, kalıcılık dosyası karantinaya alınır, yeni/UID 0 hesap kilitlenir, wheel'e
eklenen hesap gruptan çıkarılır. root, masaüstü sahibi, Satsuma'nın kendisi ve
oturum açmayı bozabilecek dosyalara asla dokunulmaz.
"""
import fnmatch
import os
import pwd
import re
import shlex
import subprocess
import time
from pathlib import Path

FIREWALL_RULES = frozenset({'SATSUMA-LNX-EVAS-002', 'SATSUMA-EVAS-005', 'SATSUMA-GAP-023'})
LOCK_RULES = frozenset({'SATSUMA-GAP-016', 'SATSUMA-GAP-042'})
DEMOTE_RULES = frozenset({'SATSUMA-GAP-017'})
FILE_RULES = frozenset({
    'SATSUMA-PERS-001', 'SATSUMA-PERS-002', 'SATSUMA-PERS-003', 'SATSUMA-PERS-004', 'SATSUMA-PERS-005',
    'SATSUMA-PERS-006', 'SATSUMA-PERS-007', 'SATSUMA-PERSIST-001', 'SATSUMA-SUDO-005', 'SATSUMA-GAP-010',
    'SATSUMA-GAP-011', 'SATSUMA-GAP-013', 'SATSUMA-GAP-015', 'SATSUMA-GAP-053'})

HOMES = ('/home/*', '/var/home/*', '/root', '/var/roothome')
# Where a persistence file may be taken from. Fnmatch on the real path.
FILE_PATTERNS = (
    '/etc/cron.d/*', '/etc/cron.hourly/*', '/etc/cron.daily/*', '/etc/cron.weekly/*', '/etc/cron.monthly/*',
    '/var/spool/cron/*',
    '/etc/systemd/system/*', '/etc/systemd/user/*',
    '/etc/profile.d/*', '/etc/xdg/autostart/*', '/etc/ld.so.preload', '/etc/udev/rules.d/*', '/etc/binfmt.d/*',
    '/etc/modules-load.d/*', '/etc/rc.d/rc.local', '/etc/rc.local', '/etc/sudoers.d/*',
    '/etc/pki/ca-trust/source/anchors/*',
    *(h + rel for h in HOMES for rel in (
        '/.ssh/authorized_keys', '/.ssh/authorized_keys2', '/.bashrc', '/.bash_profile', '/.bash_login', '/.profile',
        '/.zshrc', '/.pam_environment', '/.config/autostart/*', '/.config/systemd/user/*',
        '/.config/environment.d/*', '/.local/share/systemd/user/*')),
)
PROTECTED = ('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow', '/etc/sudoers', '/etc/profile',
             '/etc/bashrc', '/etc/crontab', '/etc/fstab', '/etc/selinux/config', '/etc/pam.d/*',
             '/etc/satsuma-core/*', '/etc/systemd/system/satsuma*', '/etc/systemd/system/*/satsuma*',
             '/etc/xdg/autostart/satsuma*', '/etc/modprobe.d/satsuma*', '/opt/satsuma-core/*', '/var/lib/satsuma-core/*')
SATSUMA_USERS = re.compile(r'^satsuma')
NAME = re.compile(r'^[a-z_][a-z0-9_.-]{0,31}\$?$')
SYSTEMCTL = '/usr/bin/systemctl'


def _event(finding):
    event = finding.get('event') if isinstance(finding.get('event'), dict) else {}
    ext = ((event.get('metadata') or {}).get('extensions') or {}) if isinstance(event.get('metadata'), dict) else {}
    raw = event.get('raw') if isinstance(event.get('raw'), dict) else {}
    get = lambda *keys: next((v for k in keys for v in (event.get(k), ext.get('host.' + k), raw.get(k)) if v), None)
    return {'cmd': str(get('cmd') or ''), 'path': str(get('file_path', 'path') or ''), 'exe': str(get('exe') or '')}


def _account_args(cmd):
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()
    return tokens


# Writers whose /etc changes are an update, not an attack (they run as root from the
# package database); their files are never undone. Güncelleme yazmaları geri alınmaz.
PACKAGE_WRITERS = frozenset({'rpm-ostree', 'rpm-ostreed', 'rpm', 'dnf', 'dnf5', 'dnf-3', 'bootc', 'ostree',
                             'packagekitd', 'systemd-sysusers', 'systemd-tmpfiles'})


def plan(finding):
    """What to undo for one finding: a list of actions (possibly empty)."""
    rule = str(finding.get('rule_id') or '')
    if finding.get('trace_only'):
        return []
    info = _event(finding)
    if Path(info['exe']).name in PACKAGE_WRITERS:
        return []
    base = {'rule_id': rule, 'finding_id': finding.get('finding_id')}
    if rule in FIREWALL_RULES:
        return [{**base, 'action': 'restore_firewall'}]
    if rule in FILE_RULES and info['path']:
        return [{**base, 'action': 'quarantine_file', 'path': info['path']}]
    tokens = _account_args(info['cmd'])
    names = [t for t in tokens[1:] if NAME.match(t) and not t.startswith('-')]
    if rule in LOCK_RULES and names and tokens and Path(tokens[0]).name in ('useradd', 'adduser', 'usermod'):
        return [{**base, 'action': 'lock_account', 'user': names[-1]}]
    if rule in DEMOTE_RULES and names and tokens:
        program = Path(tokens[0]).name
        for group in ('wheel', 'sudo', 'adm'):
            if program == 'usermod' and any(group in t.split(',') for t in tokens if not t.startswith('-')):
                return [{**base, 'action': 'remove_from_group', 'user': names[-1], 'group': group}]
            if program == 'gpasswd' and group in tokens:
                index = tokens.index(group)
                user = tokens[index - 1] if index > 0 and NAME.match(tokens[index - 1]) else None
                if user and user not in ('-a', '--add'):
                    return [{**base, 'action': 'remove_from_group', 'user': user, 'group': group}]
    return []


def _owners(store=None, group_lookup=None):
    """Enrolled desktop owners: members of satsuma-reader (installer.desktop_setup)."""
    import grp
    lookup = group_lookup or grp.getgrnam
    try:
        group = lookup('satsuma-reader')
    except KeyError:
        return set()
    names = set(group.gr_mem)
    try:
        names |= {u.pw_name for u in pwd.getpwall() if u.pw_gid == group.gr_gid}
    except Exception:
        pass
    return names


def allowed(action, owners=(), real=os.path.realpath):
    """(True, '') when privd may carry out the action; otherwise (False, reason)."""
    kind = action.get('action')
    if kind == 'restore_firewall':
        return True, ''
    if kind == 'quarantine_file':
        path = str(action.get('path') or '')
        if not path.startswith('/') or '..' in Path(path).parts:
            return False, 'path_not_absolute'
        resolved = real(path) if not os.path.islink(path) else os.path.join(real(os.path.dirname(path)), os.path.basename(path))
        for candidate in {path, resolved}:
            if any(fnmatch.fnmatchcase(candidate, p) for p in PROTECTED):
                return False, 'protected_path'
        if not any(fnmatch.fnmatchcase(c, p) for c in {path, resolved} for p in FILE_PATTERNS):
            return False, 'not_a_persistence_location'
        return True, ''
    if kind in ('lock_account', 'remove_from_group'):
        user = str(action.get('user') or '')
        if not NAME.match(user):
            return False, 'bad_user_name'
        if user == 'root' or SATSUMA_USERS.match(user) or user in set(owners or ()):
            return False, 'protected_account'
        if kind == 'remove_from_group' and action.get('group') not in ('wheel', 'sudo', 'adm'):
            return False, 'bad_group'
        try:
            info = pwd.getpwnam(user)
        except KeyError:
            return False, 'no_such_account'
        if info.pw_uid == 0:
            # A second UID 0 account is exactly what GAP-016 is about; root itself was refused above.
            return True, ''
        return True, ''
    return False, 'unknown_action'


def _run(args, runner):
    done = runner(args, capture_output=True, text=True, timeout=60)
    return {'returncode': done.returncode, 'error': (done.stderr or '')[-300:] if done.returncode else ''}


def _unconfirmed_keys(path, known, audit):
    """authorized_keys: only the keys the owner has not confirmed are taken out, line by line."""
    from . import ssh_keys
    text = Path(path).read_text(errors='replace')
    prints = []
    for line in text.splitlines():
        parsed = ssh_keys.parse_authorized(line)
        if parsed and parsed[0].get('fingerprint') and parsed[0]['fingerprint'] not in known:
            prints.append(parsed[0]['fingerprint'])
    removed = [ssh_keys.quarantine_authorized(path, fp, audit) for fp in dict.fromkeys(prints)]
    return {'status': 'keys_quarantined' if removed else 'only_confirmed_keys', 'keys': removed,
            'restore_hint': 'sudo satsuma-admin karantina geri-al <kimlik>'}


def _quarantine_file(path, audit, runner, known_keys=()):
    from . import scan_quarantine as q
    if Path(path).name in ('authorized_keys', 'authorized_keys2') and not os.path.islink(path):
        return _unconfirmed_keys(path, set(known_keys), audit)
    if os.path.islink(path):
        # A systemd .wants link or a linked unit: the link is removed and recorded.
        target = os.readlink(path)
        os.unlink(path)
        result = {'status': 'link_removed', 'source': path, 'link_target': target, 'restorable': True,
                  'restore_hint': f'sudo ln -s {shlex.quote(target)} {shlex.quote(path)}'}
        audit(result)
    else:
        target = q.inspect_target(path)
        result = q.quarantine_target(target, audit, extra_roots=(Path('/etc'), Path('/var/spool/cron'),
                                                                 Path('/var/home'), Path('/var/roothome')))
    unit = Path(path).name
    if '/systemd/system/' in path and unit.endswith(('.service', '.timer', '.path', '.socket')) \
            and not unit.startswith('satsuma'):
        result['unit_stop'] = _run([SYSTEMCTL, 'stop', '--no-block', unit], runner)
        result['daemon_reload'] = _run([SYSTEMCTL, 'daemon-reload'], runner)
    elif '/systemd/system/' in path:
        result['daemon_reload'] = _run([SYSTEMCTL, 'daemon-reload'], runner)
    if path.startswith('/etc/udev/rules.d/'):
        result['udev_reload'] = _run(['/usr/bin/udevadm', 'control', '--reload'], runner)
    return result


def execute(action, store=None, audit=lambda record: None, runner=subprocess.run):
    """Carry out one action after checking it again. Runs in privd (root)."""
    ok, reason = allowed(action, _owners(store))
    record = {'timestamp': time.time(), 'action': 'remediation.' + str(action.get('action')),
              'rule_id': action.get('rule_id'), 'finding_id': action.get('finding_id'),
              'target': action.get('path') or action.get('user')}
    if not ok:
        return {**record, 'status': 'refused', 'reason': reason}
    kind = action['action']
    try:
        if kind == 'restore_firewall':
            result = _run([SYSTEMCTL, 'start', '--no-block', 'satsuma-firewall-watch.service'], runner)
            status = 'requested' if result['returncode'] == 0 else 'failed'
        elif kind == 'quarantine_file':
            known = (store.get('ssh_keys_known', []) if store is not None else []) or []
            result = _quarantine_file(action['path'], audit, runner, known)
            status = result.get('status', 'quarantined')
        elif kind == 'lock_account':
            result = _run(['/usr/sbin/usermod', '-L', '-e', '1', action['user']], runner)
            status = 'locked' if result['returncode'] == 0 else 'failed'
            result['undo'] = f"sudo usermod -U -e '' {action['user']}"
        else:
            result = _run(['/usr/bin/gpasswd', '-d', action['user'], action['group']], runner)
            status = 'removed_from_group' if result['returncode'] == 0 else 'failed'
            result['undo'] = f"sudo gpasswd -a {action['user']} {action['group']}"
    except Exception as exc:  # recorded, never raised into the caller
        return {**record, 'status': 'failed', 'error': str(exc)[:300]}
    return {**record, 'status': status, **{k: v for k, v in result.items() if k not in ('status',)}}
