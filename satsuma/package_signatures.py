"""Package signature audit: dnf must check signatures, and installed packages must be signed.

User report 2026-11-04: package signature checking was missing. The
libdnf5 veto plugin (dnf_guard) needs a Fedora toolchain and is not built
since 2.2.16, so this audit covers what can be checked from Python:

- dnf's main setting and every enabled repository must have gpgcheck on;
  a repository with gpgcheck=0 can install an unsigned or forged package;
- every installed package must carry an RPM signature (RSA, or DSA/EdDSA
  as OpenSnitch's packages use: field 2026-11-04), except the
  gpg-pubkey entries and Satsuma's own package (signed locally with
  Satsuma's seal, not with a distribution key).

tam-kontrol turns gpgcheck on where it is off (a dated copy of each file
changed is kept); unsigned installed packages are listed, never removed.

Paket imza denetimi: dnf imzaları denetlemeli, kurulu paketler imzalı olmalı.
Kullanıcı bildirimi 2026-11-04: paket imza doğrulaması yoktu. libdnf5 veto
eklentisi (dnf_guard) Fedora derleme araçları istiyor ve 2.2.16'dan beri
derlenmiyor; bu denetim Python'dan denetlenebileni kapsar: dnf'in ana ayarı
ve etkin her depo gpgcheck açık olmalı; kurulu her paket RPM imzası (RSA ya da OpenSnitch paketlerindeki gibi
DSA/EdDSA) taşımalı
(gpg-pubkey kayıtları ve Satsuma'nın kendi paketi hariç). tam-kontrol kapalı
gpgcheck'i açar (değişen her dosyanın tarihli kopyası saklanır); imzasız
kurulu paketler listelenir, asla silinmez.
"""
import configparser
from pathlib import Path
import shutil
import subprocess
import time

DNF_CONF = Path('/etc/dnf/dnf.conf')
REPOS = Path('/etc/yum.repos.d')
OWN = {'satsuma-core', 'gpg-pubkey'}


def _false(value):
    return str(value).strip().lower() in ('0', 'no', 'false', 'off')


def _read(path):
    parser = configparser.RawConfigParser(strict=False)
    try:
        parser.read(path, encoding='utf-8')
    except (configparser.Error, OSError, UnicodeDecodeError):
        return None
    return parser


def repositories(dnf_conf=DNF_CONF, repos=REPOS):
    """[(file, section, enabled, gpgcheck_off)] for dnf.conf [main] and every repo section."""
    found = []
    main = _read(dnf_conf)
    if main is not None and main.has_section('main'):
        found.append((str(dnf_conf), 'main', True, _false(main.get('main', 'gpgcheck', fallback='1'))))
    for path in sorted(Path(repos).glob('*.repo')):
        parser = _read(path)
        if parser is None:
            continue
        for section in parser.sections():
            enabled = not _false(parser.get(section, 'enabled', fallback='1'))
            off = _false(parser.get(section, 'gpgcheck', fallback='1'))
            found.append((str(path), section, enabled, off))
    return found


def weak(dnf_conf=DNF_CONF, repos=REPOS):
    return [(f, s) for f, s, enabled, off in repositories(dnf_conf, repos) if enabled and off]


def enforce(dnf_conf=DNF_CONF, repos=REPOS, now=None):
    """Set gpgcheck=1 where an enabled section has it off; keeps a dated copy of each changed file."""
    changed = []
    stamp = time.strftime('%Y%m%d-%H%M%S', time.localtime(now))
    for path in sorted({f for f, _ in weak(dnf_conf, repos)}):
        sections = {s for f, s in weak(dnf_conf, repos) if f == path}
        lines = Path(path).read_text(encoding='utf-8').splitlines(keepends=True)
        current, out = None, []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('[') and stripped.endswith(']'):
                current = stripped[1:-1].strip()
            key = stripped.split('=', 1)[0].strip().lower() if '=' in stripped else ''
            if current in sections and key == 'gpgcheck':
                out.append('gpgcheck=1\n')
            else:
                out.append(line)
        shutil.copy2(path, path + '.satsuma-' + stamp)
        Path(path).write_text(''.join(out), encoding='utf-8')
        changed.append(path)
    return changed


def unsigned_packages(runner=subprocess.run):
    """Installed packages with no RPM signature, Satsuma's own and gpg-pubkey excluded."""
    result = runner(['/usr/bin/rpm', '-qa', '--qf', '%{NAME}\t%{SIGPGP:pgpsig}\t%{RSAHEADER:pgpsig}\t%{DSAHEADER:pgpsig}\t%{SIGGPG:pgpsig}\n'],
                    capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError('rpm okunamadı: ' + (result.stderr or '')[:200])
    missing = []
    for line in result.stdout.splitlines():
        name, *signatures = line.split('\t')
        if name in OWN:
            continue
        if all(value.strip() in ('', '(none)') for value in signatures):
            missing.append(name)
    return sorted(set(missing))


def audit(runner=subprocess.run, fix=False, dnf_conf=DNF_CONF, repos=REPOS):
    changed = enforce(dnf_conf, repos) if fix else []
    still_weak = weak(dnf_conf, repos)
    try:
        unsigned, error = unsigned_packages(runner), None
    except Exception as exc:
        unsigned, error = [], str(exc)[:200]
    return {'weak_repositories': still_weak, 'fixed_files': changed, 'unsigned': unsigned, 'error': error,
            'ok': not still_weak and not unsigned and error is None}
