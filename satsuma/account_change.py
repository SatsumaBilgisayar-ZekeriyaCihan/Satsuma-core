"""What a write to /etc/passwd or /etc/shadow actually changed.

Owner's report 2026-11-18: "systemd-sysuser" (the kernel cuts systemd-sysusers
to 15 characters) and, on the COSMIC desktop, the cosmic-greeter account kept
raising critical "password changed" alarms. SATSUMA-PRIV-026/027 fired on every
write to the two files, whatever was written: systemd-sysusers rewrites both
files whole when it adds one locked service account, and Satsuma's own
``usermod -L`` does the same. Verified with the real systemd-sysusers: the new
lines carry "!*" (no password) and existing hashes stay byte for byte.

This module keeps a snapshot of every account (UID, shell and the state and
fingerprint of its password hash, never the hash itself) and compares the files
with it when such a write is evaluated:

* critical (still stops the writer under the blocking policy): a system account
  (UID 1-999, or 65534 and the systemd dynamic range) gets a usable or empty
  password, a second UID 0 account appears, an account moves to UID 0, root's
  password is removed;
* notice (recorded, never stops): an existing password changes (``passwd`` by a
  user or the administrator), a normal account is added with a password;
* benign (recorded at low severity, never stops): new locked accounts, accounts
  locked or removed, nothing security relevant changed.

When the files cannot be read or no snapshot exists, the verdict is "unknown"
and the rule keeps its original severity: unknown is never treated as safe.

/etc/passwd veya /etc/shadow'a yazmanın gerçekte neyi değiştirdiği. Kurallar her
yazmada kritik alarm veriyordu; systemd-sysusers kilitli servis hesabı eklerken
de, Satsuma'nın kendi kilitlemesi de dosyayı baştan yazar. Bu modül hesapların
özetini (parola özetinin kendisini değil, durumunu ve parmak izini) tutar ve
yazma değerlendirilirken karşılaştırır. Okunamayan dosya ya da eksik özet
"bilinmiyor" sayılır; kural özgün önemini korur.
"""
import hashlib
import json
import os
import threading
import time
from pathlib import Path

PASSWD = Path('/etc/passwd')
SHADOW = Path('/etc/shadow')
SNAPSHOT = Path('/var/lib/satsuma-core/account-snapshot.json')
FIRST_NORMAL_UID = 1000
# Accounts with no business holding a password besides UID 1-999: the overflow
# user and systemd's DynamicUser= range (61184-65519).
SYSTEM_EXTRA = frozenset((65534,))
DYNAMIC = range(61184, 65520)
RULES = frozenset(('SATSUMA-PRIV-026', 'SATSUMA-PRIV-027', 'SATSUMA-COLL-015'))
WATCHED = frozenset((str(PASSWD), str(SHADOW), '/etc/gshadow', '/etc/group'))
_LOCK = threading.Lock()


def hash_state(field):
    """'empty', 'locked' or 'usable' for one shadow password field.

    "" lets a PAM stack with nullok in without a password; "!..." and "*..."
    are locked; anything else (a $id$ hash or an old DES hash) is usable.
    """
    if field is None:
        return 'missing'
    if field == '':
        return 'empty'
    if field[0] in '!*':
        return 'locked'
    return 'usable'


def system_account(uid):
    return 1 <= uid < FIRST_NORMAL_UID or uid in SYSTEM_EXTRA or uid in DYNAMIC


def _rows(path):
    text = Path(path).read_text(errors='replace')
    return [line.split(':') for line in text.splitlines() if line and not line.startswith('#')]


def read(passwd=PASSWD, shadow=SHADOW):
    """{name: {uid, shell, state, fp}}; raises OSError when a file cannot be read."""
    hashes = {row[0]: row[1] for row in _rows(shadow) if len(row) >= 2}
    accounts = {}
    for row in _rows(passwd):
        if len(row) < 7:
            continue
        try:
            uid = int(row[2])
        except ValueError:
            continue
        field = hashes.get(row[0])
        # "x" in passwd points to shadow; anything else in passwd is the hash itself.
        if row[1] not in ('x', ''):
            field = row[1]
        accounts[row[0]] = {
            'uid': uid, 'shell': row[6], 'state': hash_state(field),
            # Fingerprint only: tells a change apart without keeping the hash.
            'fp': hashlib.sha256(field.encode()).hexdigest()[:16] if field else None,
        }
    return accounts


def diff(old, new):
    """Changes between two snapshots, each {'kind', 'name', 'uid', ...}."""
    changes = []
    for name in sorted(set(old) | set(new)):
        before, after = old.get(name), new.get(name)
        if before is None:
            changes.append({'kind': 'added', 'name': name, 'uid': after['uid'], 'state': after['state']})
            continue
        if after is None:
            changes.append({'kind': 'removed', 'name': name, 'uid': before['uid']})
            continue
        if before['uid'] != after['uid']:
            changes.append({'kind': 'uid_changed', 'name': name, 'uid': after['uid'], 'from_uid': before['uid']})
        if before['fp'] != after['fp'] or before['state'] != after['state']:
            changes.append({'kind': 'password_changed', 'name': name, 'uid': after['uid'],
                            'from_state': before['state'], 'state': after['state']})
        if before['shell'] != after['shell']:
            changes.append({'kind': 'shell_changed', 'name': name, 'uid': after['uid'],
                            'from_shell': before['shell'], 'shell': after['shell']})
    return changes


def _risk(change, accounts):
    """'critical', 'notice' or 'benign' for one change."""
    uid, name, kind = change['uid'], change['name'], change['kind']
    opens = change.get('state') in ('usable', 'empty')
    if uid == 0 and name != 'root' and kind in ('added', 'uid_changed'):
        return 'critical'
    if kind == 'uid_changed' and uid == 0:
        return 'critical'
    if name == 'root' and kind == 'password_changed' and change.get('state') == 'empty':
        return 'critical'
    if system_account(uid) and opens and kind in ('added', 'password_changed', 'uid_changed'):
        return 'critical'
    if kind == 'password_changed' and change.get('state') in ('usable', 'empty'):
        return 'notice'
    if kind == 'added' and opens:
        return 'notice'
    return 'benign'


LABELS = {
    'added': 'hesap eklendi', 'removed': 'hesap silindi', 'uid_changed': 'UID değişti',
    'password_changed': 'parola değişti', 'shell_changed': 'kabuk değişti',
}
STATES = {'locked': 'kilitli, parolasız', 'empty': 'BOŞ parola', 'usable': 'kullanılabilir parola',
          'missing': 'shadow satırı yok'}


def describe(change):
    text = f"{change['name']} (UID {change['uid']}): {LABELS[change['kind']]}"
    if change['kind'] == 'password_changed':
        text += f" ({STATES.get(change['from_state'], change['from_state'])} → {STATES.get(change['state'], change['state'])})"
    elif change['kind'] == 'added':
        text += f" ({STATES.get(change['state'], change['state'])})"
    elif change['kind'] == 'uid_changed':
        text += f" ({change['from_uid']} → {change['uid']})"
    return text


def assess(changes, accounts=None):
    """{'verdict', 'changes', 'summary'} for a list of changes."""
    ranked = [{**c, 'risk': _risk(c, accounts or {})} for c in changes]
    order = {'critical': 3, 'notice': 2, 'benign': 1}
    verdict = max((c['risk'] for c in ranked), key=order.get, default='benign')
    if not ranked:
        summary = 'Dosya yazıldı; hesaplarda ve parolalarda değişiklik yok.'
    else:
        shown = sorted(ranked, key=lambda c: -order[c['risk']])[:6]
        summary = '; '.join(describe(c) for c in shown)
        if len(ranked) > len(shown):
            summary += f'; +{len(ranked) - len(shown)} değişiklik daha'
    return {'verdict': verdict, 'changes': ranked[:50], 'summary': summary}


class Tracker:
    """Snapshot kept in memory and on disk (0600) so a restart keeps the baseline."""

    def __init__(self, passwd=PASSWD, shadow=SHADOW, snapshot=SNAPSHOT, clock=time.time):
        self.passwd, self.shadow, self.snapshot, self.clock = Path(passwd), Path(shadow), Path(snapshot), clock
        self.accounts = None

    def _load(self):
        try:
            data = json.loads(self.snapshot.read_text())
            accounts = data.get('accounts')
            return accounts if isinstance(accounts, dict) else None
        except (OSError, ValueError, AttributeError):
            return None

    def _save(self, accounts):
        try:
            self.snapshot.parent.mkdir(parents=True, exist_ok=True)
            temporary = self.snapshot.with_name(self.snapshot.name + '.tmp')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'w') as stream:
                json.dump({'updated_at': self.clock(), 'accounts': accounts}, stream, sort_keys=True)
            os.replace(temporary, self.snapshot)
        except OSError:
            pass

    def baseline(self):
        """Take a snapshot if none exists; returns True when one is available."""
        with _LOCK:
            if self.accounts is None:
                self.accounts = self._load()
            if self.accounts is None:
                try:
                    self.accounts = read(self.passwd, self.shadow)
                except OSError:
                    return False
                self._save(self.accounts)
            return True

    def check(self):
        """Assess the files against the snapshot, then move the snapshot forward."""
        with _LOCK:
            if self.accounts is None:
                self.accounts = self._load()
            try:
                current = read(self.passwd, self.shadow)
            except OSError as exc:
                return {'verdict': 'unknown', 'changes': [], 'summary': 'Hesap dosyaları okunamadı: ' + (exc.strerror or str(exc))}
            if self.accounts is None:
                self.accounts = current
                self._save(current)
                return {'verdict': 'unknown', 'changes': [], 'summary': 'Önceki hesap özeti yoktu; karşılaştırma yapılamadı, özet alındı.'}
            result = assess(diff(self.accounts, current), current)
            if result['changes']:
                self.accounts = current
                self._save(current)
            return result


TRACKER = Tracker()

# How each verdict turns the rule finding: classification, severity, log_only.
VERDICTS = {
    'benign': ('indicator', 'low', True),
    'notice': ('indicator', 'medium', True),
}


def applies(finding):
    if finding.get('rule_id') not in RULES:
        return False
    event = finding.get('event') or {}
    path = str(event.get('file_path') or event.get('path') or '')
    return not path or path in WATCHED


def apply(finding, result=None, tracker=None):
    """Rewrite a PRIV-026/027 / COLL-015 finding with what the write changed.

    ``result`` is one check() shared by every finding of the same event, so the
    second rule never sees "no change" after the first moved the snapshot.
    Critical and unknown verdicts keep the rule's own classification and severity.
    """
    if not applies(finding):
        return finding
    if result is None:
        result = (tracker or TRACKER).check()
    finding['account_change'] = result
    title = {'critical': 'Hesap dosyasında tehlikeli değişiklik', 'notice': 'Hesap dosyası değişti',
             'benign': 'Hesap dosyası yazıldı (güvenlik açısından önemsiz)',
             'unknown': 'Hesap dosyası yazıldı (içerik doğrulanamadı)'}[result['verdict']]
    finding['summary'] = f"{title}: {result['summary']}"
    # The panel titles a finding by rule_name; "Passwd degistirme" read as
    # "password changed" for any write. The rule files stay byte for byte
    # (tests/fixtures/candidate18-original-rules.json); only the finding is named.
    finding['rule_name_original'] = finding.get('rule_name')
    finding['rule_name'] = title
    if result['verdict'] in VERDICTS:
        classification, severity, log_only = VERDICTS[result['verdict']]
        finding.update(classification=classification, severity=severity, log_only=log_only,
                       original_classification=finding.get('classification'),
                       original_severity=finding.get('severity'))
    return finding
