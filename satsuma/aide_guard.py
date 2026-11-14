"""AIDE guard: one snapshot after Satsuma has set everything, then every change is compared and undone on approval.

User decision 2026-11-10. Satsuma configures the machine once (satsuma-kur);
only after every step has passed is the snapshot taken, so that a mistake in
the middle is never protected. The snapshot has two parts:

* an AIDE database over Satsuma's own profile (aide.conf generated here, not
  the system /etc/aide.conf): DNS, firewall, kernel, services, browser
  policies, the certificate store, package sources, accounts and
  authorization, SSH, autostart and scheduled jobs, library injection points,
  and the programs (hash only);
* a copy of every protected configuration file, because AIDE keeps only
  hashes and cannot put a file back.

The hourly check compares the machine with the snapshot. Every change is
listed with how it can be undone: from the copy, by moving an added file to
Satsuma's holding folder (never deleted), or by reinstalling the signed
package that owns a program. Nothing is undone without approval: the root
command ``satsuma-admin aide geri-al <yol>`` with the Satsuma admin password
is the approval; a wrong password is recorded and nothing is undone.
/etc/hosts is put back only after every line is checked. Files changed
by a package update whose digest the RPM database confirms are not alarms;
when they are the only changes the snapshot is renewed. The AIDE database and
the copies are root-only, and their digests are kept in Satsuma's store: a
changed snapshot is reported and never trusted.

AIDE bekçisi: Satsuma her şeyi ayarladıktan sonra bir kez örnek alınır; sonra
her değişiklik karşılaştırılır ve onayla geri alınır.

Kullanıcı kararı 2026-11-10. Satsuma makineyi bir kez yapılandırır
(satsuma-kur); örnek ancak bütün adımlar geçtikten sonra alınır, böylece
aradaki bir hata korunmaz. Örneğin iki parçası vardır: Satsuma'nın kendi
profiline göre AIDE veritabanı (DNS, güvenlik duvarı, çekirdek, servisler,
tarayıcı politikaları, sertifika deposu, paket kaynakları, hesaplar ve
yetkiler, SSH, otomatik başlatma ve zamanlanmış işler, kütüphane enjeksiyon
noktaları ve programlar) ve korunan her ayar dosyasının kopyası; çünkü AIDE
yalnızca özet tutar, dosyayı geri koyamaz. Saatlik denetim makineyi örnekle
karşılaştırır. Her değişiklik nasıl geri alınacağıyla listelenir: kopyadan,
eklenen dosya Satsuma'nın bekletme klasörüne taşınır (asla silinmez) ya
da programın imzalı paketi yeniden kurulur. Onay olmadan hiçbir şey geri
alınmaz: onay, ``satsuma-admin aide geri-al <yol>`` root komutu ve Satsuma
yönetici parolasıdır; yanlış parola kaydedilir. /etc/hosts her satırı
denetlendikten sonra geri konur. RPM
veritabanının doğruladığı paket güncellemesi değişikliği alarm değildir;
tek değişiklik bunlarsa örnek yenilenir. AIDE veritabanı ve kopyalar yalnızca
root'a açıktır, özetleri Satsuma deposunda tutulur: değişmiş örnek bildirilir
ve ona güvenilmez.
"""
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

BASE = Path('/var/lib/satsuma-core/aide')
AIDE = '/usr/sbin/aide'
RPM = '/usr/bin/rpm'
DNF = '/usr/bin/dnf'
MAX_FILE = 8 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024

# Configuration: copied, so a change can be put back.
COPY = (
    # DNS (the most sensitive point)
    '/etc/resolv.conf', '/etc/hosts', '/etc/nsswitch.conf', '/etc/NetworkManager', '/etc/dnsmasq.conf',
    '/etc/dnsmasq.d', '/etc/systemd/resolved.conf', '/etc/systemd/resolved.conf.d',
    # firewall, IPS, devices
    '/etc/nftables', '/etc/sysconfig/nftables.conf', '/etc/firewalld', '/etc/satsuma-core', '/etc/suricata',
    '/etc/opensnitchd', '/etc/usbguard',
    # kernel
    '/etc/sysctl.conf', '/etc/sysctl.d', '/etc/modprobe.d', '/etc/default/grub', '/etc/kernel/cmdline',
    '/boot/loader/entries',
    # services and their overrides, masks
    '/etc/systemd/system',
    # browser policies
    '/etc/firefox/policies', '/etc/opt/chrome/policies', '/etc/chromium/policies',
    # interception and package sources
    '/etc/pki/ca-trust', '/etc/yum.repos.d', '/etc/pki/rpm-gpg',
    # accounts and authorization
    '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d', '/etc/pam.d',
    '/etc/security', '/etc/polkit-1/rules.d',
    # remote login
    '/etc/ssh', '/root/.ssh',
    # autostart and scheduled jobs
    '/etc/crontab', '/etc/cron.d', '/etc/cron.hourly', '/etc/cron.daily', '/etc/cron.weekly', '/etc/cron.monthly',
    '/var/spool/cron', '/etc/xdg/autostart', '/root/.bashrc', '/root/.bash_profile', '/root/.profile',
    # library injection and environment
    '/etc/ld.so.preload', '/etc/ld.so.conf', '/etc/ld.so.conf.d', '/etc/environment', '/etc/profile',
    '/etc/profile.d', '/etc/bashrc',
    # devices and mandatory access control
    '/etc/udev/rules.d', '/etc/selinux/config',
)
# Put back only after every line is checked (user decision 2026-11-10; audit
# G6: a removed sinkhole once wrote unvalidated names here, a MITM door).
# Her satırı denetlendikten sonra geri konur (denetim G6).
VALIDATED = {'/etc/hosts': 'hosts'}
_NAME = re.compile(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?'
                   r'(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*')


def validate_hosts(data):
    """Every line is an IP address followed by valid host names; anything else refuses the restore."""
    import ipaddress
    if len(data) > 1024 * 1024:
        raise RuntimeError('hosts kopyası çok büyük')
    try:
        text = data.decode('ascii')
    except UnicodeDecodeError:
        raise RuntimeError('hosts kopyasında ASCII dışı karakter var')
    for number, line in enumerate(text.splitlines(), 1):
        words = line.split('#', 1)[0].split()
        if not words:
            continue
        try:
            ipaddress.ip_address(words[0].split('%')[0])
        except ValueError:
            raise RuntimeError(f'hosts {number}. satır: geçersiz adres')
        if len(words) < 2 or not all(_NAME.fullmatch(name) for name in words[1:]):
            raise RuntimeError(f'hosts {number}. satır: geçersiz ad')
    return True
# Per desktop user (uid >= 1000).
USER_COPY = ('.ssh/authorized_keys', '.bashrc', '.bash_profile', '.profile', '.config/autostart',
             '.config/systemd/user', '.config/environment.d')
# Programs: hash only; put back by reinstalling the signed package.
PACKAGE = ('/usr/bin', '/usr/sbin', '/usr/lib64', '/usr/lib/systemd', '/usr/lib/modules', '/boot', '/opt/satsuma-core')
# Changes all the time on purpose; never a change to undo.
EXCLUDE = (r'/var/log', r'/var/lib/satsuma-core', r'/etc/satsuma-core/dns', r'/etc/NetworkManager/.*\.lease',
           r'/.*\.satsuma-backup-.*', r'/etc/pki/ca-trust/extracted/.*\.tmp', r'/boot/grub2/grubenv',
           r'/etc/systemd/system/.*\.wants/.*\.service\.d')


def protected_paths(passwd=None):
    """Every path of the profile on this machine: (copy, package)."""
    users = passwd if passwd is not None else [p for p in pwd.getpwall() if p.pw_uid >= 1000 and p.pw_uid < 60000]
    copy = list(COPY)
    for user in users:
        home = user.pw_dir
        if home and home.startswith('/') and home != '/':
            copy += [os.path.join(home, rel) for rel in USER_COPY]
    return copy, list(PACKAGE)


def _rx(path):
    return re.escape(path).replace('\\/', '/')


def aide_config(base=BASE, passwd=None):
    copy, package = protected_paths(passwd)
    lines = ['# Satsuma AIDE profile (satsuma.aide_guard). Generated; do not edit.',
             '# Satsuma AIDE profili. Üretilmiş dosya; elle değiştirmeyin.',
             f'database_in=file:{base}/aide.db.gz', f'database_out=file:{base}/aide.db.new.gz',
             'gzip_dbout=yes', 'report_url=stdout', 'report_format=json',
             'SATSUMA = p+u+g+n+s+m+c+i+sha256']
    lines += ['!' + rx for rx in EXCLUDE]
    lines += [_rx(path) + ' SATSUMA' for path in copy + package]
    return '\n'.join(lines) + '\n'


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def _files(paths):
    """Regular files and symlinks under the given paths, without following links."""
    for top in paths:
        try:
            info = os.lstat(top)
        except OSError:
            continue
        if stat.S_ISDIR(info.st_mode):
            for root, dirs, names in os.walk(top, followlinks=False):
                dirs.sort()
                for name in sorted(names):
                    yield os.path.join(root, name)
        else:
            yield top


def _excluded(path):
    return any(re.fullmatch(rx + '(/.*)?', path) for rx in EXCLUDE)


def copy_files(paths, base=BASE):
    """Copy the configuration into base/files; return the manifest (path -> record)."""
    target = Path(base) / 'files'
    if target.exists():
        shutil.rmtree(target)
    target.mkdir(parents=True, mode=0o700)
    manifest, total, skipped = {}, 0, {}
    for path in _files(paths):
        if _excluded(path):
            continue
        try:
            info = os.lstat(path)
        except OSError:
            continue
        record = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        if stat.S_ISLNK(info.st_mode):
            manifest[path] = {**record, 'type': 'link', 'target': os.readlink(path)}
            continue
        if not stat.S_ISREG(info.st_mode):
            continue
        if info.st_size > MAX_FILE or total + info.st_size > MAX_TOTAL:
            skipped[path] = 'size_limit'
            continue
        destination = target / path.lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            with os.fdopen(fd, 'rb', closefd=False) as source, open(destination, 'wb') as out:
                os.fchmod(out.fileno(), 0o600)
                shutil.copyfileobj(source, out)
        finally:
            os.close(fd)
        total += info.st_size
        manifest[path] = {**record, 'type': 'file', 'sha256': sha256_file(destination), 'size': info.st_size}
    return manifest, skipped


class Guard:
    def __init__(self, store=None, base=BASE, runner=subprocess.run, clock=time.time, passwd=None, verifier=None):
        self.store, self.base, self.runner, self.clock, self.passwd = store, Path(base), runner, clock, passwd
        if verifier is None:
            from .dashboard_auth import verify_admin_password as verifier
        self.verifier = verifier

    # -- paths -------------------------------------------------------------------
    @property
    def config(self):
        return self.base / 'aide.conf'

    @property
    def db(self):
        return self.base / 'aide.db.gz'

    @property
    def manifest_path(self):
        return self.base / 'manifest.json'

    def _write(self, path, text):
        tmp = path.with_suffix(path.suffix + '.tmp')
        tmp.write_text(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def _aide(self, *args, timeout=7200):
        return self.runner([AIDE, '--config', str(self.config), *args], capture_output=True, text=True, timeout=timeout)

    # -- snapshot --------------------------------------------------------------------
    def snapshot(self):
        """Take the reference: AIDE database plus copies. Call only after Satsuma has set everything."""
        self.base.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.base, 0o700)
        self._write(self.config, aide_config(self.base, self.passwd))
        result = self._aide('--init')
        new = self.base / 'aide.db.new.gz'
        if result.returncode != 0 or not new.exists():
            raise RuntimeError('aide --init başarısız: ' + (result.stderr or result.stdout or '')[-300:])
        os.replace(new, self.db)
        os.chmod(self.db, 0o600)
        copy, _ = protected_paths(self.passwd)
        manifest, skipped = copy_files(copy, self.base)
        self._write(self.manifest_path, json.dumps(manifest, ensure_ascii=False, sort_keys=True))
        record = {'taken_at': self.clock(), 'db_sha256': sha256_file(self.db),
                  'manifest_sha256': sha256_file(self.manifest_path), 'copied_files': len(manifest),
                  'skipped': skipped}
        self.store.set('aide_snapshot', record)
        self.store.set('aide_changes', {'status': 'CLEAN', 'checked_at': self.clock(), 'changes': []})
        return record

    def _trusted_snapshot(self):
        record = self.store.get('aide_snapshot', None)
        if not record:
            return None, 'NO_SNAPSHOT'
        try:
            if (sha256_file(self.db) != record['db_sha256']
                    or sha256_file(self.manifest_path) != record['manifest_sha256']):
                return None, 'SNAPSHOT_CHANGED'
            return json.loads(self.manifest_path.read_text()), 'OK'
        except (OSError, KeyError, ValueError):
            return None, 'SNAPSHOT_CHANGED'

    # -- comparison ----------------------------------------------------------------------
    @staticmethod
    def parse_report(text):
        """added/removed/changed paths from AIDE's JSON report."""
        try:
            report = json.loads(text or '{}')
        except ValueError:
            raise RuntimeError('AIDE raporu okunamadı')
        result = {}
        for kind in ('added', 'removed', 'changed'):
            entries = report.get(kind) or {}
            result[kind] = sorted(entries if isinstance(entries, list) else entries.keys())
        return result

    def _package(self, path):
        result = self.runner([RPM, '-qf', '--qf', '%{NAME}\\n', '--', path], capture_output=True, text=True, timeout=60)
        names = (result.stdout or '').split()
        return names[0] if result.returncode == 0 and names else None

    def _package_update(self, path):
        """The RPM database confirms the file's current digest: a package update, not tampering."""
        result = self.runner([RPM, '-Vf', '--nomtime', '--', path], capture_output=True, text=True, timeout=120)
        for line in (result.stdout or '').splitlines():
            if line.rstrip().endswith(' ' + path) or line.rstrip().endswith('\t' + path):
                return '5' not in line.split()[0] and 'missing' not in line
        return result.returncode == 0

    def classify(self, kind, path, manifest):
        under_copy = any(path == top or path.startswith(top.rstrip('/') + '/')
                         for top in protected_paths(self.passwd)[0])
        if kind == 'added':
            return {'path': path, 'kind': kind, 'restore': 'hold' if under_copy else 'none'}
        if path in manifest:
            return {'path': path, 'kind': kind, 'restore': 'copy'}
        package = self._package(path)
        if package:
            if kind == 'changed' and self._package_update(path):
                return {'path': path, 'kind': kind, 'restore': 'none', 'package': package, 'package_update': True}
            return {'path': path, 'kind': kind, 'restore': 'package', 'package': package}
        return {'path': path, 'kind': kind, 'restore': 'none'}

    def check(self):
        manifest, state = self._trusted_snapshot()
        if manifest is None:
            row = {'status': state, 'checked_at': self.clock(), 'changes': []}
            self.store.set('aide_changes', row)
            return row
        result = self._aide('--check')
        if result.returncode > 7:
            row = {'status': 'CHECK_FAILED', 'checked_at': self.clock(), 'changes': [],
                   'error': (result.stderr or '')[-300:]}
            self.store.set('aide_changes', row)
            return row
        found = self.parse_report(result.stdout)
        changes = [self.classify(kind, path, manifest) for kind in ('added', 'removed', 'changed')
                   for path in found[kind] if not _excluded(path)]
        real = [c for c in changes if not c.get('package_update')]
        updates = [c for c in changes if c.get('package_update')]
        if updates and not real:
            # Only confirmed package updates: renew the program part of the reference.
            self.snapshot()
            row = {'status': 'CLEAN', 'checked_at': self.clock(), 'changes': [], 'renewed_after_update': len(updates)}
        else:
            row = {'status': 'CHANGED' if real else 'CLEAN', 'checked_at': self.clock(), 'changes': real,
                   'package_updates_seen': len(updates)}
        self.store.set('aide_changes', row)
        if real:
            self.store.add('aide_events', {'timestamp': self.clock(), 'changes': real[:200]})
        return row

    # -- undo, only on approval -----------------------------------------------------------------
    def restore(self, path, password):
        """Undo one listed change; the Satsuma admin password is the approval (user decision 2026-11-10).

        Bekleyen bir değişikliği geri alır; onay Satsuma yönetici parolasıdır.
        """
        try:
            accepted = isinstance(password, str) and bool(password) and self.verifier(password)
        except (OSError, ValueError, PermissionError):
            accepted = False
        if not accepted:
            self.store.add('aide_restores', {'timestamp': self.clock(), 'path': path, 'status': 'password_refused'})
            raise PermissionError('Satsuma yönetici parolası doğrulanmadı; geri alma yapılmadı')
        manifest, state = self._trusted_snapshot()
        if manifest is None:
            raise RuntimeError('Örneğe güvenilemiyor: ' + state)
        listed = {c['path']: c for c in (self.store.get('aide_changes', {}) or {}).get('changes', [])}
        change = listed.get(path)
        if change is None:
            raise RuntimeError('Bu yol bekleyen değişiklikler listesinde yok: ' + path)
        how = change['restore']
        if how == 'copy':
            self._restore_copy(path, manifest[path])
        elif how == 'hold':
            holding = self.base / 'held' / time.strftime('%Y%m%d-%H%M%S') / path.lstrip('/')
            holding.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.replace(path, holding)
        elif how == 'package':
            result = self.runner([DNF, '-y', '--setopt=gpgcheck=True', 'reinstall', '--', change['package']],
                                 capture_output=True, text=True, timeout=1800)
            if result.returncode != 0:
                raise RuntimeError('Paket yeniden kurulamadı: ' + (result.stderr or '')[-300:])
        else:
            raise RuntimeError('Bu değişiklik için geri alma yolu yok; elle incelenmeli: ' + path)
        left = [c for c in listed.values() if c['path'] != path]
        current = self.store.get('aide_changes', {}) or {}
        self.store.set('aide_changes', {**current, 'changes': left, 'status': 'CHANGED' if left else 'CLEAN'})
        self.store.add('aide_restores', {'timestamp': self.clock(), 'path': path, 'how': how, 'status': 'restored',
                                         'package': change.get('package'), 'approval': 'admin_password'})
        return {'path': path, 'how': how}

    def _restore_copy(self, path, record):
        if record['type'] == 'link':
            tmp = path + '.satsuma-restore'
            if os.path.lexists(tmp):
                os.unlink(tmp)
            os.symlink(record['target'], tmp)
            os.replace(tmp, path)
            return
        source = self.base / 'files' / path.lstrip('/')
        if sha256_file(source) != record['sha256']:
            raise RuntimeError('Kopya değişmiş; geri konmadı: ' + path)
        if VALIDATED.get(path) == 'hosts':
            validate_hosts(source.read_bytes())
        parent = os.path.dirname(path)
        os.makedirs(parent, exist_ok=True)
        tmp = os.path.join(parent, '.satsuma-restore-' + os.urandom(6).hex())
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as out, open(source, 'rb') as data:
                shutil.copyfileobj(data, out)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(tmp, record['mode'])
            try:
                os.chown(tmp, record['uid'], record['gid'])
            except PermissionError:
                if os.geteuid() == 0:
                    raise
            os.replace(tmp, path)
        finally:
            if os.path.lexists(tmp):
                os.unlink(tmp)
        if os.path.exists('/usr/sbin/restorecon'):
            self.runner(['/usr/sbin/restorecon', '--', path], capture_output=True, text=True, timeout=60)


def status_text(row):
    if not row:
        return 'AIDE örneği yok: sudo satsuma-kur (son adım) ya da sudo satsuma-admin aide ornek-al'
    state = row.get('status')
    if state == 'CLEAN':
        return 'Örnekle aynı'
    if state == 'SNAPSHOT_CHANGED':
        return 'AIDE örneği değiştirilmiş; karşılaştırmaya güvenilmiyor'
    if state == 'NO_SNAPSHOT':
        return 'AIDE örneği yok'
    if state == 'CHECK_FAILED':
        return 'AIDE denetimi çalışmadı: ' + str(row.get('error') or '')[:150]
    names = {'copy': 'kopyadan', 'hold': 'bekletme klasörüne alınır', 'package': 'paketten', 'none': 'elle inceleme'}
    return (str(len(row.get('changes') or [])) + ' değişiklik onay bekliyor: '
            + '; '.join(c['kind'] + ' ' + c['path'] + ' (' + names.get(c['restore'], c['restore']) + ')'
                        for c in (row.get('changes') or [])[:10]))


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if os.geteuid() != 0:
        print('Root yetkisi gerekli.', file=sys.stderr)
        return 1
    from .store import Store
    store = Store()
    try:
        guard = Guard(store)
        if args[:1] == ['--snapshot']:
            print(json.dumps(guard.snapshot(), ensure_ascii=False, indent=1))
        elif args[:1] == ['--check']:
            print(status_text(guard.check()))
        else:
            print(status_text(store.get('aide_changes', None)))
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        store.close()


if __name__ == '__main__':
    raise SystemExit(main())
