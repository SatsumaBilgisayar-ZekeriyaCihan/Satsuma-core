"""Verify installed files against Fedora's signed packages, not the local rpmdb.

The local package database can be rewritten together with the files it
describes, so ``rpm -V`` alone proves nothing on a system from an untrusted
supply chain. For each package that runs early boot or Satsuma itself this
module fetches the exact installed NEVRA again, checks its signature with a
throw-away keyring holding only the Fedora key pinned in Satsuma (never the
system keyring), and compares every file's on-disk digest, read without
following links, with the digest in the signed header. It also compares the
local rpmdb's digests with the signed ones: a difference means the database
itself was altered.

Repositories may be poisoned; they can only withhold a package here, never
pass a forged one, because the signature is checked against the pinned key.
What stays trusted is the rpmkeys and gpg binaries; they are among the
packages checked, so a change to them shows on the next run from another
trusted boot. Until a key is pinned the status is NO_PINNED_KEY and nothing
is reported clean.

Kurulu dosyaları yerel rpmdb'ye değil Fedora'nın imzalı paketlerine karşı
doğrular.

Yerel paket veritabanı tarif ettiği dosyalarla birlikte yeniden yazılabilir;
bu yüzden güvenilmeyen tedarik zincirinden gelen bir sistemde yalnız
``rpm -V`` hiçbir şey kanıtlamaz. Erken açılışı ya da Satsuma'yı çalıştıran
her paket için bu modül kurulu NEVRA'yı yeniden indirir, imzasını yalnızca
Satsuma'ya sabitlenmiş Fedora anahtarını içeren geçici bir anahtarlıkla
denetler (sistem anahtarlığıyla asla) ve her dosyanın, bağlantı izlenmeden
okunan diskteki özetini imzalı başlıktaki özetle karşılaştırır. Yerel
rpmdb'nin özetlerini de imzalı olanlarla karşılaştırır: fark, veritabanının
kendisinin değiştirildiği anlamına gelir.

Depolar zehirlenmiş olabilir; burada yalnızca bir paketi vermeyebilirler,
sahte bir paketi geçiremezler, çünkü imza sabitlenmiş anahtara karşı
denetlenir. Güvenilmeye devam edilen rpmkeys ve gpg programlarıdır; bunlar
da denetlenen paketler arasındadır. Anahtar sabitlenene kadar durum
NO_PINNED_KEY olur ve hiçbir şey temiz sayılmaz.
"""
import hashlib
import json
import os
import stat
import subprocess
import tempfile
import time
from pathlib import Path

# Pinned Fedora signing keys: fingerprint -> key file shipped with Satsuma.
# Sabitlenmiş Fedora imza anahtarları. Resmi kaynaktan doğrulanıp eklenir.
PINNED_KEYS = {}
KEY_DIR = Path(__file__).resolve().parent / 'trust'
STATUS_FILE = Path('/var/lib/satsuma-core/signed-verify.json')
CORE_PACKAGES = ('systemd', 'systemd-libs', 'systemd-udev', 'dracut', 'kernel-core', 'glibc', 'glibc-common',
                 'audit', 'audit-libs', 'usbguard', 'rpm', 'rpm-libs', 'gnupg2', 'python3', 'python3-libs',
                 'bash', 'coreutils', 'util-linux', 'sudo', 'pam', 'shadow-utils', 'nftables', 'NetworkManager',
                 'suricata', 'clamav')
DIGEST = {2: 'sha1', 8: 'sha256', 9: 'sha384', 10: 'sha512'}
RPMFILE_CONFIG, RPMFILE_DOC, RPMFILE_GHOST, RPMFILE_LICENSE = 1, 2, 64, 128
QUERY = '[%{FILENAMES}\t%{FILEDIGESTS}\t%{FILEFLAGS}\t%{FILEMODES}\n]'


def run(args, runner=subprocess.run, timeout=300):
    return runner(args, capture_output=True, text=True, timeout=timeout)


def key_fingerprint(path, runner=subprocess.run):
    out = run(['/usr/bin/gpg', '--batch', '--show-keys', '--with-colons', str(path)], runner).stdout
    return [line.split(':')[9] for line in out.splitlines() if line.startswith('fpr:')][:1]


def pinned_keys(runner=subprocess.run, pins=None, key_dir=None):
    """Key files whose fingerprint matches the pin; anything else is ignored."""
    pins = PINNED_KEYS if pins is None else pins
    key_dir = KEY_DIR if key_dir is None else key_dir
    good = []
    for fingerprint, name in pins.items():
        path = key_dir / name
        if path.is_file() and not path.is_symlink() and key_fingerprint(path, runner) == [fingerprint]:
            good.append(path)
    return good


def parse_files(text):
    files = {}
    for line in text.splitlines():
        parts = line.split('\t')
        if len(parts) == 4:
            path, digest, flags, mode = parts
            files[path] = {'digest': digest, 'flags': int(flags), 'mode': int(mode)}
    return files


def disk_digest(path, algorithm):
    """Digest of a regular file opened without following links, or a reason."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, 'missing'
    if not stat.S_ISREG(info.st_mode):
        return None, 'not_a_regular_file'
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        return None, 'unreadable:' + exc.__class__.__name__
    digest = hashlib.new(algorithm)
    with os.fdopen(fd, 'rb') as fh:
        for block in iter(lambda: fh.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest(), None


def compare(signed, local, algorithm, digest_of=disk_digest):
    """Findings for one package: disk vs signed header, rpmdb vs signed header."""
    findings = []
    for path, entry in signed.items():
        if local.get(path, {}).get('digest') != entry['digest']:
            findings.append({'path': path, 'reason': 'rpmdb_differs_from_signed_package', 'severity': 'high'})
        if entry['flags'] & RPMFILE_GHOST or not stat.S_ISREG(entry['mode']) or not entry['digest']:
            continue
        actual, problem = digest_of(path, algorithm)
        optional = entry['flags'] & (RPMFILE_DOC | RPMFILE_LICENSE)
        if problem == 'missing' and optional:
            continue  # docs and translations may be excluded at install time
        if problem or actual != entry['digest']:
            config = entry['flags'] & RPMFILE_CONFIG
            findings.append({'path': path, 'reason': problem or ('config_changed' if config else 'file_changed'),
                             'severity': 'review' if config else 'high'})
    return findings


def verify_package(name, keyring_keys, workdir, runner=subprocess.run, digest_of=disk_digest):
    nevra = run(['/usr/bin/rpm', '-q', '--qf', '%{NAME}-%{EPOCH}:%{VERSION}-%{RELEASE}.%{ARCH}\n', name], runner)
    if nevra.returncode:
        return {'package': name, 'status': 'NOT_INSTALLED'}
    nevra = nevra.stdout.split()[0].replace('-(none):', '-0:')
    dest = Path(workdir) / name
    dest.mkdir()
    got = run(['/usr/bin/dnf', 'download', '--destdir', str(dest), nevra], runner, timeout=900)
    rpms = sorted(dest.glob('*.rpm'))
    if got.returncode or len(rpms) != 1:
        return {'package': name, 'nevra': nevra, 'status': 'UNVERIFIED_NO_DOWNLOAD'}
    db = Path(workdir) / ('db-' + name)
    db.mkdir()
    for key in keyring_keys:
        run(['/usr/bin/rpmkeys', '--dbpath', str(db), '--import', str(key)], runner)
    check = run(['/usr/bin/rpmkeys', '--dbpath', str(db), '--checksig', '-v', str(rpms[0])], runner)
    text = check.stdout + check.stderr
    if check.returncode or 'Signature' not in text or any(bad in text for bad in ('NOKEY', 'BAD', 'NOTTRUSTED')):
        return {'package': name, 'nevra': nevra, 'status': 'SIGNATURE_INVALID'}
    algo = run(['/usr/bin/rpm', '-qp', '--qf', '%{FILEDIGESTALGO}\n', str(rpms[0])], runner).stdout.strip()
    algorithm = DIGEST.get(int(algo) if algo.isdigit() else 0)
    if not algorithm:
        return {'package': name, 'nevra': nevra, 'status': 'UNKNOWN_DIGEST'}
    signed = parse_files(run(['/usr/bin/rpm', '-qp', '--qf', QUERY, str(rpms[0])], runner).stdout)
    local = parse_files(run(['/usr/bin/rpm', '-q', '--qf', QUERY, name], runner).stdout)
    findings = compare(signed, local, algorithm, digest_of)
    status = 'CHANGED' if any(f['severity'] == 'high' for f in findings) else 'VERIFIED'
    return {'package': name, 'nevra': nevra, 'status': status, 'files': len(signed), 'findings': findings}


def verify(packages=CORE_PACKAGES, runner=subprocess.run, keys=None, digest_of=disk_digest):
    keys = pinned_keys(runner) if keys is None else keys
    report = {'updated_at': time.time(), 'trust': 'pinned_fedora_key'}
    if not keys:
        report.update(status='NO_PINNED_KEY', packages=[])
        return report
    with tempfile.TemporaryDirectory(prefix='satsuma-verify-') as workdir:
        results = [verify_package(name, keys, workdir, runner, digest_of) for name in sorted(set(packages))]
    statuses = {r['status'] for r in results}
    report['packages'] = results
    report['status'] = ('CHANGED' if statuses & {'CHANGED', 'SIGNATURE_INVALID'}
                        else 'INCOMPLETE' if statuses & {'UNVERIFIED_NO_DOWNLOAD', 'UNKNOWN_DIGEST'}
                        else 'VERIFIED')
    return report


def save(report, path=STATUS_FILE):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name('.' + path.name + '.tmp')
    tmp.write_text(json.dumps(report, sort_keys=True))
    os.replace(tmp, path)


def main():
    packages = set(CORE_PACKAGES)
    try:
        inventory = json.loads(Path('/var/lib/satsuma-core/boot-inventory.json').read_text())
        packages |= {f['package'] for f in inventory.get('findings', []) if f.get('package')}
    except (OSError, ValueError):
        pass
    report = verify(sorted(packages))
    save(report)
    print(json.dumps({'status': report['status']}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
