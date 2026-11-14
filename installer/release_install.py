#!/usr/bin/env python3
"""Verify, build, sign and install a Satsuma Fedora release without shell eval."""
import argparse
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile

FINGERPRINT = '913483F4FD53BAD88F35DD39073C0B49B01769D9'
BUNDLE = 'satsuma-memory-update-bundle.tar.gz'
PUBLIC_KEY = 'RPM-GPG-KEY-SatsumaBilgisayar'
RPM_NAME = 'satsuma-core-2.2.37-1.fc44.x86_64.rpm'
BUILD_PACKAGES = ['rpm-build', 'rpm-sign', 'cpio', 'tar', 'gzip', 'gcc', 'python3',
                  'python3-pytest', 'python3-pydantic', 'python3-psutil',
                  'python3-pyyaml', 'python3-jsonschema', 'python3-pyqt6-base',
                  'squashfs-tools', 'libnetfilter_queue', 'systemd']


def run(args, **kwargs):
    return subprocess.run([str(x) for x in args], check=True, **kwargs)


def dnf_command(allow_network, action, *args):
    return ['dnf', *([] if allow_network else ['--cacheonly']), '-y',
            '--setopt=localpkg_gpgcheck=1', action, *args]


def privileged(args):
    return args if os.geteuid() == 0 else ['sudo', *args]


def require_fedora44(path=Path('/etc/os-release'), machine=None):
    fields = dict(line.split('=', 1) for line in path.read_text().splitlines()
                  if '=' in line and not line.startswith('#'))
    fields = {key: value.strip('"') for key, value in fields.items()}
    if (fields.get('ID') != 'fedora' or fields.get('VERSION_ID') != '44'
            or (machine or platform.machine()) != 'x86_64'):
        raise RuntimeError('Kurulum/derleme Fedora 44 x86_64 gerektirir; --verify-only her sistemde kullanılabilir.')


def verify_signature(home, signature, data):
    result = run(['gpg', '--no-options', '--homedir', home, '--batch',
                  '--no-auto-key-retrieve', '--status-fd', '1', '--verify', signature, data],
                 capture_output=True, text=True)
    valid = [line.split() for line in result.stdout.splitlines()
             if line.startswith('[GNUPG:] VALIDSIG ')]
    if not valid or any(row[-1] != FINGERPRINT for row in valid):
        raise RuntimeError('İmza beklenen SatsumaBilgisayar anahtarına ait değil.')


def verify_package(package, home):
    key = package / PUBLIC_KEY
    listing = run(['gpg', '--no-options', '--homedir', home, '--batch',
                   '--with-colons', '--show-keys', key], capture_output=True, text=True).stdout
    primary = []
    expect = False
    for line in listing.splitlines():
        if line.startswith('pub:'):
            expect = True
        elif line.startswith('fpr:') and expect:
            primary.append(line.split(':')[9]); expect = False
    if primary != [FINGERPRINT]:
        raise RuntimeError('Açık anahtarın tam parmak izi eşleşmiyor.')
    run(['gpg', '--no-options', '--homedir', home, '--batch', '--import', key],
        capture_output=True)
    verify_signature(home, package / (BUNDLE + '.asc'), package / BUNDLE)


def extract(archive, directory):
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        if len(members) > 50000 or sum(member.size for member in members) > 512 * 1024 * 1024:
            raise RuntimeError('Kaynak arşivi boyut sınırını aşıyor.')
        # Releases contain ordinary files/directories only. Refuse links and
        # special nodes, including traversal via an otherwise-safe link.
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isfile() or member.isdir()):
                raise RuntimeError('Güvensiz arşiv girdisi: ' + member.name)
        tar.extractall(directory, members=members, filter='data')


def verify_rpm(rpm, public_key, directory):
    database = directory / 'rpmdb'
    database.mkdir(mode=0o700)
    run(['rpm', '--dbpath', database, '--initdb'], capture_output=True)
    run(['rpmkeys', '--dbpath', database, '--import', public_key], capture_output=True)
    result = run(['rpmkeys', '--dbpath', database, '--checksig', '--verbose', rpm],
                 capture_output=True, text=True)
    # Unsigned RPMs can have valid digests. Require a real verified signature
    # in a database containing only the pinned publisher key.
    if not re.search(r'^.*signature.*:\s*OK\s*$', result.stdout, re.I | re.M):
        raise RuntimeError('RPM digest kontrolü yeterli değil; doğrulanmış GPG imzası bulunamadı.')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package-dir', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output-dir', type=Path, default=Path.cwd() / 'satsuma-build')
    parser.add_argument('--verify-only', action='store_true', help='Yalnızca kaynak paketinin GPG imzasını kontrol et')
    parser.add_argument('--build-only', action='store_true', help='Test/derleme yap; ürünü sisteme kurma')
    parser.add_argument('--allow-network', action='store_true', help='DNF paket indirmesine açıkça izin ver')
    parser.add_argument('--signing-home', type=Path, help='Yalnızca yayıncı için: özel GPG anahtarlığının dizini')
    args = parser.parse_args(argv)
    package = args.package_dir.resolve()
    with tempfile.TemporaryDirectory(prefix='satsuma-verify-') as temporary:
        verify_home = Path(temporary) / 'gnupg'; verify_home.mkdir(mode=0o700)
        verify_package(package, verify_home)
        print('Kaynak paketinin SatsumaBilgisayar GPG imzası doğrulandı.', flush=True)
        if args.verify_only:
            return 0
        require_fedora44()
        supplied_rpm = package / RPM_NAME
        if not supplied_rpm.exists() and not args.build_only and args.signing_home is None:
            raise RuntimeError('Bu teslim kaynak paketidir. Otomatik derleme+imzalama+kurulum için '
                               '--signing-home /guvenli/gnupg kullanın; yalnızca derleme için --build-only kullanın. '
                               'İmzasız RPM otomatik kurulmaz.')
        if args.allow_network:
            print('DNF ağ erişimine izin verildi.', flush=True)
        else:
            print('İnternet indirmesi kapalı; DNF yalnızca yerel cache kullanacak.', flush=True)
        args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        build = Path(tempfile.mkdtemp(prefix='release-', dir=args.output_dir.resolve()))
        public_key = package / PUBLIC_KEY
        if supplied_rpm.exists():
            rpm = supplied_rpm
        else:
            run(privileged(dnf_command(args.allow_network, 'install', *BUILD_PACKAGES)))
            extract(package / BUNDLE, build)
            inner = build / 'satsuma-memory-update'
            verify_signature(verify_home, inner / 'SHA256SUMS.asc', inner / 'SHA256SUMS')
            run(['sha256sum', '-c', 'SHA256SUMS'], cwd=inner)
            extract(inner / 'satsuma-core-2.2.37.tar.gz', build)
            source = build / 'satsuma-core-2.2.37'
            environment = {**os.environ, 'PYTHONPATH': '.', 'QT_QPA_PLATFORM': 'offscreen'}
            tests = ['test_memory_validation', 'test_memory_access', 'test_memory_hardening',
                     'test_memory_mounts', 'test_hardware_memory', 'test_auto_process', 'test_memory_status']
            run(['python3', '-m', 'pytest', '-q', *(f'tests/{test}.py' for test in tests)],
                cwd=source, env=environment)
            environment['SATSUMA_RPM_BUILD_ROOT'] = str(build / 'rpmbuild')
            run(['bash', 'packaging/build.sh'], cwd=source, env=environment)
            rpm = build / 'rpmbuild/RPMS/x86_64' / RPM_NAME
            if args.signing_home:
                signing = args.signing_home.resolve()
                if not signing.is_dir() or signing.stat().st_mode & 0o077:
                    raise RuntimeError('İmzalama anahtarlığı 0700 izinli güvenli dizin olmalı.')
                run(['rpmsign', '--define', '_openpgp_sign gpg', '--define',
                     '_openpgp_sign_id ' + FINGERPRINT, '--define', '_gpg_name ' + FINGERPRINT,
                     '--addsign', rpm], env={**os.environ, 'GNUPGHOME': str(signing)})
            elif args.build_only:
                print('RPM derlendi; GPG imzası yok, sisteme kurulmadı: ' + str(rpm), flush=True)
                return 0
        verify_rpm(rpm, public_key, Path(temporary))
        print('RPM GPG imzası ayrı, yalnızca yayıncı anahtarını içeren RPM veritabanında doğrulandı.', flush=True)
        if args.build_only:
            print('İmzalı RPM hazır; sisteme kurulmadı: ' + str(rpm), flush=True)
            return 0
        run(privileged(['rpmkeys', '--import', public_key]))
        query = '%{VERSION}-%{RELEASE}.%{ARCH}'
        expected = run(['rpm', '-qp', '--queryformat', query, rpm], capture_output=True, text=True).stdout
        current = subprocess.run(['rpm', '-q', '--queryformat', query, 'satsuma-core'], capture_output=True, text=True)
        action = 'reinstall' if current.returncode == 0 and current.stdout == expected else 'install'
        run(privileged(dnf_command(args.allow_network, action, rpm)))
        run(privileged(['python3', '-I', '-B', '/opt/satsuma-core/installer/boot_setup.py', '--check-memory']))
        run(privileged(['systemctl', 'is-active', 'satsuma-core.service', 'satsuma-teams.service']))
        print('Kurulum ve anlık bellek politikası kontrolü tamamlandı. Yeniden başlatma kabul kontrolünü rehbere göre yapın.', flush=True)
        return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError, tarfile.TarError) as exc:
        raise SystemExit('SATSUMA KURULUM DURDU: ' + str(exc))
