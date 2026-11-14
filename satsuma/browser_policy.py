"""Browser policies: Firefox, Chrome and Chromium locked to safe settings (from satsuma-omni V62).

Taken from the satsuma-omni V62 setup (user request 2026-11-10). Written as
enterprise policy files that the browsers read at start:

* HTTPS only, plain http:// addresses blocked (also a modem's http admin page);
* no proxy (an attacker's proxy is a classic interception point);
* certificate errors and Safe Browsing warnings cannot be clicked through;
* extensions: every extension is blocked except the user's own approved
  Firefox extension; native messaging (an extension starting a local program)
  is denied; the GNOME Shell connector is blocked;
* signed extensions only, tracking/cryptomining/fingerprinting protection,
  Safe Browsing on, Firefox content sandbox level 6, third-party cookies off.

Existing unrelated policy keys are kept; Satsuma's keys win. A changed file is
backed up first. Parent directories and existing files must be root-owned
and not group/world writable. The Flatpak Firefox reads its own policy path
and is not covered.

Tarayıcı politikaları: Firefox, Chrome ve Chromium güvenli ayarlara kilitlenir.

satsuma-omni V62 kurulumundan alındı (kullanıcı isteği 2026-11-10).
Tarayıcıların açılışta okuduğu kurumsal politika dosyaları olarak yazılır:
yalnızca HTTPS (düz http:// adresleri, modemin http yönetim sayfası dahil,
engellenir); vekil sunucu yok; sertifika hatası ve Safe Browsing uyarısı
geçilemez; kullanıcının onaylı Firefox eklentisi dışında bütün eklentiler
engellenir, native messaging reddedilir, GNOME Shell bağlayıcısı engellenir;
yalnızca imzalı eklenti, izleme koruması, Firefox içerik sandbox düzeyi 6,
üçüncü taraf çerezleri kapalı. İlgisiz politika anahtarları korunur;
Satsuma'nınkiler geçerli olur. Değişen dosya önce yedeklenir. Flatpak
Firefox kendi politika yolunu okur ve kapsanmaz.
"""
import datetime
import json
import os
import re
import stat
import sys
from pathlib import Path

ALLOWED_FIREFOX_EXTENSION_ID = 'armut-bildirici@satsuma.local'
FIREFOX_PATH = 'etc/firefox/policies/policies.json'
CHROMIUM_PATHS = ('etc/opt/chrome/policies/managed/satsuma-security.json',
                  'etc/chromium/policies/managed/satsuma-security.json')
POLICY_FILES = (FIREFOX_PATH,) + CHROMIUM_PATHS


def firefox_policy(addon_id=ALLOWED_FIREFOX_EXTENSION_ID):
    if not addon_id or len(addon_id) > 255 or not re.fullmatch(r'[A-Za-z0-9{}@._+\-]+', addon_id):
        raise ValueError('İzinli Firefox eklentisinin kimliği geçersiz')
    return {
        'HttpsOnlyMode': 'force_enabled',
        'IPProtectionAvailable': False,
        'Proxy': {'Mode': 'none', 'Locked': True},
        'WebsiteFilter': {'Block': ['http://*/*']},
        'ExtensionSettings': {
            '*': {'installation_mode': 'blocked', 'blocked_permissions': ['nativeMessaging']},
            addon_id: {'installation_mode': 'allowed', 'blocked_permissions': ['nativeMessaging']},
            'chrome-gnome-shell@gnome.org': {'installation_mode': 'blocked'},
        },
        'DisableSecurityBypass': {'InvalidCertificate': True, 'SafeBrowsing': True},
        'EnableTrackingProtection': {'Value': True, 'Locked': True, 'Cryptomining': True, 'Fingerprinting': True},
        'Preferences': {
            'extensions.enabledScopes': {'Value': 5, 'Status': 'locked'},
            'xpinstall.signatures.required': {'Value': True, 'Status': 'locked'},
            'extensions.langpacks.signatures.required': {'Value': True, 'Status': 'locked'},
            'browser.safebrowsing.malware.enabled': {'Value': True, 'Status': 'locked'},
            'browser.safebrowsing.phishing.enabled': {'Value': True, 'Status': 'locked'},
            'browser.safebrowsing.downloads.enabled': {'Value': True, 'Status': 'locked'},
            'security.sandbox.content.level': {'Value': 6, 'Status': 'locked'},
        },
    }


def chromium_policy():
    return {'ProxyMode': 'direct', 'HttpsOnlyMode': 'force_enabled', 'URLBlocklist': ['http://*'],
            'ExtensionSettings': {'*': {'installation_mode': 'blocked'},
                                  'gphhapmejobijbbhgpjhcjognlahblep': {'installation_mode': 'blocked'}},
            'BlockExternalExtensions': True,
            'NativeMessagingBlocklist': ['*'], 'NativeMessagingAllowlist': [],
            'NativeMessagingUserLevelHosts': False,
            'SafeBrowsingProtectionLevel': 1, 'DisableSafeBrowsingProceedAnyway': True,
            'BlockThirdPartyCookies': True, 'DefaultNotificationsSetting': 2}


def merged(path, old, owner_check=True):
    """Satsuma's keys over an existing policy file's content."""
    if path == FIREFOX_PATH:
        new = firefox_policy()
        policies = dict((old or {}).get('policies') or {})
        prefs = policies.get('Preferences') or {}
        if not isinstance(prefs, dict):
            raise ValueError('Preferences must be an object')
        policies.update({**new, 'Preferences': {**prefs, **new['Preferences']}})
        return {**(old or {}), 'policies': policies}
    return {**(old or {}), **chromium_policy()}


def _trusted_parent(root, relative, uid=0):
    """Open (and create) the parent directories without following links; refuse writable ones."""
    fd = os.open(str(root), os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in Path(relative).parent.parts:
            try:
                os.mkdir(part, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
            info = os.fstat(fd)
            if info.st_uid != uid or info.st_mode & 0o022:
                raise RuntimeError('Güvenilmeyen politika klasörü: ' + str(Path(relative).parent))
        return fd
    except BaseException:
        os.close(fd)
        raise


def apply(root='/', uid=0, now=None):
    """Write every policy file; return the paths written and the backups made."""
    written, backups = [], []
    stamp = (now or datetime.datetime.now()).strftime('%Y%m%d%H%M%S%f')
    for relative in POLICY_FILES:
        parent = _trusted_parent(root, relative, uid)
        name = os.path.basename(relative)
        try:
            old, raw = None, None
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
                try:
                    info = os.fstat(fd)
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid or info.st_mode & 0o022
                            or info.st_nlink != 1 or info.st_size > 1048576):
                        raise RuntimeError('Güvenilmeyen politika dosyası: /' + relative)
                    raw = os.read(fd, 1048577)
                finally:
                    os.close(fd)
                old = json.loads(raw)
            except FileNotFoundError:
                pass
            new = merged(relative, old)
            if old == new:
                continue
            if raw is not None:
                backup = name + '.satsuma-backup-' + stamp
                bf = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
                with os.fdopen(bf, 'wb') as out:
                    out.write(raw)
                backups.append('/' + str(Path(relative).parent / backup))
            tmp = '.satsuma-' + os.urandom(12).hex()
            wf = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=parent)
            try:
                with os.fdopen(wf, 'w') as out:
                    json.dump(new, out, ensure_ascii=False, indent=2)
                    out.write('\n')
                    out.flush()
                    os.fsync(out.fileno())
                    os.fchmod(out.fileno(), 0o644)
                os.replace(tmp, name, src_dir_fd=parent, dst_dir_fd=parent)
            finally:
                try:
                    os.unlink(tmp, dir_fd=parent)
                except FileNotFoundError:
                    pass
            written.append('/' + relative)
        finally:
            os.close(parent)
    return {'written': written, 'backups': backups, 'requires_browser_restart': bool(written)}


def status(root='/'):
    """Which policy files carry Satsuma's settings now."""
    rows = {}
    for relative in POLICY_FILES:
        try:
            current = json.loads((Path(root) / relative).read_text())
            rows['/' + relative] = merged(relative, current) == current
        except (OSError, ValueError):
            rows['/' + relative] = False
    return {'ok': all(rows.values()), 'files': rows}


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if '--status' in args:
        print(json.dumps(status(), ensure_ascii=False, indent=2))
        return 0
    if os.geteuid() != 0:
        print('Root yetkisi gerekli.', file=sys.stderr)
        return 1
    try:
        print(json.dumps(apply(), ensure_ascii=False, indent=2))
    except (OSError, RuntimeError, ValueError) as exc:
        print('Tarayıcı politikası yazılamadı: ' + str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
