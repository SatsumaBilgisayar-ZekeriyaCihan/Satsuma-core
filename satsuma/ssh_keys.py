"""SSH key audit: who can log in with a key, and which private keys lie around.

Every key is a question to the user (2.2.15, user decision 2026-10-26:
"is this SSH key known to you? if not, quarantine"). Nothing is done by
itself; the user answers per key:

- known: the key is not asked about again (satsuma-admin ssh tanidik);
- quarantine: an authorized_keys entry is taken out of its file (only that
  line; owner, mode and SELinux label kept) and a private key file is
  moved; both can be put back (satsuma-admin karantina geri-al).

Every security scan looks at:

- authorized_keys / authorized_keys2 of root and every login user, plus
  /etc/ssh/authorized_keys: each key by its SHA256 fingerprint (as
  ssh-keygen -l shows it). Every key not confirmed is a high finding asking
  whether it is known; one that appeared since the last audit says so.
- private keys: asked about the same way; unencrypted ones and copies
  outside ~/.ssh are high.
- permissions: an .ssh directory or authorized_keys others can write.
- sshd: whether it is enabled or running (incoming connections should not
  be accepted on this machine), PermitRootLogin, PasswordAuthentication
  and an AuthorizedKeysFile moved somewhere else.

SSH anahtarı denetimi: kim anahtarla giriş yapabilir, hangi özel anahtarlar
ortada duruyor.

Her anahtar kullanıcıya bir sorudur (2.2.15, kullanıcı kararı: "bu SSH
anahtarı bilginiz dahilinde mi? değilse karantina"). Hiçbir şey
kendiliğinden yapılmaz; kullanıcı her anahtar için cevap verir: tanıdık
(bir daha sorulmaz) ya da karantina (authorized_keys içindeki yalnızca o
satır çıkarılır, sahibi, izni ve SELinux etiketi korunur; özel anahtar
dosyası taşınır; ikisi de geri alınabilir). Her taramada root'un ve her
giriş kullanıcısının authorized_keys dosyaları, özel anahtarlar,
başkalarının yazabildiği .ssh izinleri ve sshd (çalışıyor mu, root girişi,
parola girişi, anahtar dosyasının yeri) denetlenir; SSH sunucusu açıksa
kapatma önerilir (satsuma-admin ssh sunucu-kapat).
"""
import base64
import hashlib
import json
import os
import pwd
import stat
import subprocess
import time
from pathlib import Path

PRIVATE_MARKERS = (b'-----BEGIN OPENSSH PRIVATE KEY-----', b'-----BEGIN RSA PRIVATE KEY-----',
                   b'-----BEGIN DSA PRIVATE KEY-----', b'-----BEGIN EC PRIVATE KEY-----',
                   b'-----BEGIN PRIVATE KEY-----', b'-----BEGIN ENCRYPTED PRIVATE KEY-----')
KEY_TYPES = ('ssh-rsa', 'ssh-dss', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384',
             'ecdsa-sha2-nistp521', 'sk-ssh-ed25519@openssh.com', 'sk-ecdsa-sha2-nistp256@openssh.com')
MAX_KEY_FILE = 64 * 1024
SEARCH_DEPTH = 4


def fingerprint(blob_b64):
    blob = base64.b64decode(blob_b64)
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def parse_authorized(text):
    """Keys in an authorized_keys file: type, fingerprint, comment, options."""
    keys = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        index = next((i for i, part in enumerate(parts) if part in KEY_TYPES), None)
        if index is None or index + 1 >= len(parts):
            keys.append({'line': number, 'error': 'Okunamayan satır', 'text': line[:120]})
            continue
        try:
            fp = fingerprint(parts[index + 1])
        except ValueError:
            keys.append({'line': number, 'error': 'Bozuk anahtar', 'text': line[:120]})
            continue
        keys.append({'line': number, 'type': parts[index], 'fingerprint': fp,
                     'options': ' '.join(parts[:index]), 'comment': ' '.join(parts[index + 2:])[:120]})
    return keys


def private_key_encrypted(data):
    """True/False for a private key, None if it cannot be told."""
    if b'BEGIN ENCRYPTED PRIVATE KEY' in data or b'Proc-Type: 4,ENCRYPTED' in data:
        return True
    if b'BEGIN OPENSSH PRIVATE KEY' in data:
        body = b''.join(line for line in data.splitlines() if line and not line.startswith(b'-----'))
        try:
            raw = base64.b64decode(body)
        except ValueError:
            return None
        magic = b'openssh-key-v1\x00'
        if not raw.startswith(magic):
            return None
        length = int.from_bytes(raw[len(magic):len(magic) + 4], 'big')
        cipher = raw[len(magic) + 4:len(magic) + 4 + length]
        return cipher != b'none'
    if b'BEGIN RSA PRIVATE KEY' in data or b'BEGIN EC PRIVATE KEY' in data or b'BEGIN DSA PRIVATE KEY' in data \
            or b'BEGIN PRIVATE KEY' in data:
        return False
    return None


def login_homes(passwd=None):
    """(user, home) for root and every user with a real login shell."""
    rows = passwd if passwd is not None else [(p.pw_name, p.pw_uid, p.pw_dir, p.pw_shell) for p in pwd.getpwall()]
    homes = []
    for name, uid, home, shell in rows:
        if uid == 0 or (uid >= 1000 and not str(shell).endswith(('nologin', 'false'))):
            homes.append((name, Path(home)))
    return homes


def _private_keys(root, inside_ssh):
    found = []
    def walk(directory, depth):
        if depth > SEARCH_DEPTH:
            return
        try:
            entries = list(os.scandir(directory))
        except OSError:
            return
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir():
                    if entry.name not in ('.cache', 'node_modules', '.local', '.mozilla', '.var', '.git'):
                        walk(entry.path, depth + 1)
                    continue
                if not entry.is_file() or entry.stat().st_size > MAX_KEY_FILE:
                    continue
                with open(entry.path, 'rb') as stream:
                    head = stream.read(200)
                    if not any(marker in head for marker in PRIVATE_MARKERS):
                        continue
                    head += stream.read(MAX_KEY_FILE)
            except OSError:
                continue
            found.append({'path': entry.path, 'encrypted': private_key_encrypted(head),
                          'outside_ssh': not entry.path.startswith(str(inside_ssh) + '/')})
    walk(root, 0)
    return found


def _writable_by_others(path):
    try:
        info = path.stat()
    except OSError:
        return False
    return bool(info.st_mode & (stat.S_IWGRP | stat.S_IWOTH))


def sshd_state(config_path=Path('/etc/ssh/sshd_config'), runner=subprocess.run):
    settings = {}
    paths = [config_path] + sorted(Path(str(config_path) + '.d').glob('*.conf'))
    for path in paths:
        try:
            lines = path.read_text(errors='replace').splitlines()
        except OSError:
            continue
        for line in lines:
            parts = line.split(None, 1)
            if len(parts) == 2 and not parts[0].startswith('#'):
                # sshd uses the first value it reads for a keyword.
                settings.setdefault(parts[0].lower(), parts[1].strip())
    state = {'permitrootlogin': settings.get('permitrootlogin', 'prohibit-password'),
             'passwordauthentication': settings.get('passwordauthentication', 'yes'),
             'authorizedkeysfile': settings.get('authorizedkeysfile', '.ssh/authorized_keys .ssh/authorized_keys2')}
    for verb in ('is-active', 'is-enabled'):
        try:
            state[verb] = runner(['systemctl', verb, 'sshd.service'], capture_output=True, text=True,
                                 timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            state[verb] = 'unknown'
    return state


def audit(homes=None, extra_authorized=(Path('/etc/ssh/authorized_keys'),), sshd=None):
    """Everything this module reports, without judging new versus known."""
    result = {'authorized': [], 'private': [], 'permissions': [], 'sshd': sshd if sshd is not None else sshd_state()}
    files = []
    for user, home in (homes if homes is not None else login_homes()):
        ssh_dir = home / '.ssh'
        if ssh_dir.is_dir() and _writable_by_others(ssh_dir):
            result['permissions'].append({'user': user, 'path': str(ssh_dir)})
        for name in ('authorized_keys', 'authorized_keys2'):
            files.append((user, ssh_dir / name))
        result['private'] += [{**k, 'user': user} for k in _private_keys(home, ssh_dir)]
    for path in extra_authorized:
        if path.is_dir():
            files += [('?', p) for p in sorted(path.iterdir()) if p.is_file()]
        elif path.is_file():
            files.append(('?', path))
    for user, path in files:
        try:
            text = path.read_text(errors='replace')
        except OSError:
            continue
        if _writable_by_others(path):
            result['permissions'].append({'user': user, 'path': str(path)})
        for key in parse_authorized(text):
            result['authorized'].append({**key, 'user': user, 'file': str(path)})
    return result


def _finding(store, ident, severity, classification, title, summary, advice, extra, now):
    body = {'finding_id': ident, 'rule_id': ident.split(':', 1)[0], 'timestamp': now, 'severity': severity,
            'classification': classification, 'source': 'ssh_keys', 'title': title, 'summary': summary,
            'advice': advice, **extra}
    store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                     (ident, time.time(), json.dumps(body, ensure_ascii=False)))


def pending(data, known):
    """Every key the user has not confirmed: authorized entries and private keys."""
    rows = []
    for key in data['authorized']:
        if 'fingerprint' in key and key['fingerprint'] not in known:
            rows.append({'kind': 'authorized', 'id': key['fingerprint'], 'file': key['file'], 'user': key['user'],
                         'type': key['type'], 'fingerprint': key['fingerprint'], 'comment': key['comment'],
                         'options': key['options']})
    for key in data['private']:
        if key['path'] not in known:
            rows.append({'kind': 'private', 'id': key['path'], 'path': key['path'], 'user': key['user'],
                         'encrypted': key['encrypted'], 'outside_ssh': key['outside_ssh']})
    return rows


def run(store, now=time.time, **kwargs):
    """Audit and ask about every key the user has not confirmed."""
    data = audit(**kwargs)
    known = set(store.get('ssh_keys_known', []) or [])
    seen_before = set(store.get('ssh_keys_seen', []) or [])
    stamp = now()
    for key in data['authorized']:
        if 'error' in key:
            _finding(store, f"SATSUMA-SSH-BADLINE:{key['file']}:{key['line']}", 'medium', 'indicator',
                     'authorized_keys içinde okunamayan satır', f"{key['file']}:{key['line']} {key['text']}",
                     'Satırı tanımıyorsanız dosyayı karantinaya alın: sudo satsuma-admin karantina al ' + key['file'],
                     {}, stamp)
    asks = pending(data, known)
    for item in asks:
        new = item['id'] not in seen_before and bool(seen_before)
        if item['kind'] == 'authorized':
            command = f"sudo satsuma-admin ssh karantina {item['file']} {item['fingerprint']}"
            title = ('Yeni eklenmiş' if new else 'Onay bekleyen') + ' SSH yetkili anahtarı: bilginiz dahilinde mi?'
            summary = f"{item['file']} · {item['type']} {item['fingerprint']} {item['comment']}"
            if item['options']:
                summary += ' · seçenek: ' + item['options'][:200]
            advice = ('Bu anahtarla ' + item['user'] + ' kullanıcısına şifresiz giriş yapılabilir. Tanımıyorsanız '
                      'karantinaya alın: ' + command + ' (yalnızca bu satır çıkarılır, geri alınabilir). '
                      'Tanıyorsanız: sudo satsuma-admin ssh tanidik ' + item['fingerprint'])
            severity = 'high'
        else:
            command = 'sudo satsuma-admin ssh karantina ' + item['path']
            notes = []
            if item['encrypted'] is False:
                notes.append('parolasız')
            if item['outside_ssh']:
                notes.append('~/.ssh dışında')
            title = 'SSH özel anahtarı: bilginiz dahilinde mi?' + (' (' + ', '.join(notes) + ')' if notes else '')
            summary = item['path']
            advice = ('Tanımıyorsanız karantinaya alın: ' + command + ' (geri alınabilir). '
                      'Tanıyorsanız: sudo satsuma-admin ssh tanidik ' + item['path'])
            severity = 'high' if notes else 'medium'
        _finding(store, f"SATSUMA-SSH-ASK:{item['id']}:{item.get('file', '')}", severity,
                 'suspicious' if severity == 'high' else 'indicator', title, summary, advice,
                 {'key': item, 'new': new, 'quarantine_proposal': {'command': command, **item}}, stamp)
    for item in data['permissions']:
        _finding(store, f"SATSUMA-SSH-PERM:{item['path']}", 'high', 'suspicious', 'SSH dosyasına başkaları yazabiliyor',
                 item['path'], 'Düzeltmek için: chmod go-w ' + item['path'], {}, stamp)
    sshd = data['sshd']
    sshd_open = sshd.get('is-active') == 'active' or sshd.get('is-enabled') == 'enabled'
    if sshd_open:
        _finding(store, f"SATSUMA-SSH-SSHD:{sshd.get('is-active')}:{sshd.get('is-enabled')}", 'high', 'suspicious',
                 'SSH sunucusu açık: bu bilgisayara dışarıdan bağlanılabilir',
                 f"sshd {sshd.get('is-active')} / {sshd.get('is-enabled')}",
                 'SSH kullanmıyorsanız kapatın: sudo satsuma-admin ssh sunucu-kapat', {'sshd': sshd}, stamp)
    if not sshd.get('authorizedkeysfile', '').startswith('.ssh/'):
        _finding(store, f"SATSUMA-SSH-KEYFILE:{sshd.get('authorizedkeysfile')}", 'high', 'suspicious',
                 'sshd anahtar dosyasının yeri değiştirilmiş', sshd.get('authorizedkeysfile', ''),
                 '/etc/ssh/sshd_config içindeki AuthorizedKeysFile satırını inceleyin.', {'sshd': sshd}, stamp)
    store.db.commit()
    store.set('ssh_keys_seen', sorted(seen_before | {item['id'] for item in asks} | known))
    state = {'updated_at': stamp, 'authorized_count': sum(1 for k in data['authorized'] if 'fingerprint' in k),
             'pending': asks[:200], 'new_keys': [i['id'] for i in asks if seen_before and i['id'] not in seen_before],
             'unencrypted_private': [k['path'] for k in data['private'] if k['encrypted'] is False],
             'stray_private': [k['path'] for k in data['private'] if k['outside_ssh']],
             'permissions': [i['path'] for i in data['permissions']], 'sshd_open': sshd_open,
             'sshd': {k: sshd.get(k) for k in ('is-active', 'is-enabled', 'permitrootlogin', 'passwordauthentication')}}
    store.set('ssh_keys', state)
    return state


def mark_known(store, ident):
    """The user confirmed a key (fingerprint) or a private key (path)."""
    known = set(store.get('ssh_keys_known', []) or [])
    known.add(ident)
    store.set('ssh_keys_known', sorted(known))
    for finding_id, body in store.db.execute("SELECT finding_id, body FROM findings WHERE finding_id LIKE 'SATSUMA-SSH-ASK:%'").fetchall():
        data = json.loads(body)
        if (data.get('key') or {}).get('id') == ident and data.get('status') != 'CLEARED':
            data.update(status='CLEARED', severity='info', cleared='Kullanıcı bu anahtarı tanıdığını onayladı.')
            store.db.execute('UPDATE findings SET body=? WHERE finding_id=?', (json.dumps(data, ensure_ascii=False), finding_id))
    store.db.commit()
    return {'status': 'known', 'id': ident}


def quarantine_authorized(path, key_fingerprint, audit, directory=None):
    """Take the matching lines out of one authorized_keys file, restorably."""
    from . import scan_quarantine
    import uuid
    directory = Path(directory or scan_quarantine.QUARANTINE)
    path = Path(path)
    if path.name not in ('authorized_keys', 'authorized_keys2') and not str(path).startswith('/etc/ssh/authorized_keys'):
        raise ValueError('Yalnızca authorized_keys dosyalarındaki anahtarlar')
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError('authorized_keys düzenli bir dosya değil')
    text = path.read_text(errors='replace')
    kept, removed = [], []
    for line in text.splitlines(keepends=True):
        parsed = parse_authorized(line)
        if parsed and parsed[0].get('fingerprint') == key_fingerprint:
            removed.append(line)
        else:
            kept.append(line)
    if not removed:
        raise ValueError('Bu parmak izi dosyada yok: ' + key_fingerprint)
    ident = uuid.uuid4().hex
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    record = {'kind': 'ssh_authorized_key', 'quarantine_id': ident, 'path': str(path), 'fingerprint': key_fingerprint,
              'lines': removed, 'sha256': hashlib.sha256(''.join(removed).encode()).hexdigest()}
    audit({'status': 'REQUESTED', 'quarantine_id': ident, 'target': {'path': str(path), 'fingerprint': key_fingerprint}})
    meta = directory / (ident + '.json')
    fd = os.open(meta, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, json.dumps(record, ensure_ascii=False).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    _rewrite(path, ''.join(kept), info)
    result = {'status': 'quarantined', 'quarantine_id': ident, 'source': str(path), 'fingerprint': key_fingerprint,
              'lines_removed': len(removed), 'restorable': True}
    audit(result)
    return result


def _rewrite(path, text, info):
    """Atomic rewrite keeping owner, mode and SELinux label."""
    tmp = path.with_name(path.name + '.satsuma-tmp')
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    # The directory may belong to the user: never reuse a file already there.
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, text.encode())
        os.fchown(fd, info.st_uid, info.st_gid)
        os.fchmod(fd, stat.S_IMODE(info.st_mode))
        try:
            os.setxattr(fd, 'security.selinux', os.getxattr(path, 'security.selinux', follow_symlinks=False))
        except OSError:
            pass
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)


def restore_authorized(record, audit):
    """Put quarantined authorized_keys lines back (missing ones only)."""
    path = Path(record['path'])
    info = path.lstat()
    text = path.read_text(errors='replace')
    if text and not text.endswith('\n'):
        text += '\n'
    present = set(text.splitlines(keepends=True))
    text += ''.join(line if line.endswith('\n') else line + '\n' for line in record['lines'] if line not in present)
    _rewrite(path, text, info)
    result = {'status': 'restored', 'quarantine_id': record['quarantine_id'], 'path': str(path),
              'fingerprint': record['fingerprint']}
    audit(result)
    return result


def disable_sshd(runner=subprocess.run):
    """Stop and disable the SSH server (and its socket), on the user's request."""
    results = {}
    for unit in ('sshd.service', 'sshd.socket'):
        try:
            done = runner(['systemctl', 'disable', '--now', unit], capture_output=True, text=True, timeout=30)
            results[unit] = 'ok' if done.returncode == 0 else (done.stderr or '').strip()[:200]
        except (OSError, subprocess.SubprocessError) as exc:
            results[unit] = str(exc)[:200]
    return {'status': 'sshd_disabled', 'units': results}
