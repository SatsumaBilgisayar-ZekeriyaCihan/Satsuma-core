"""Installed files are checked against Fedora's signed packages, not the local rpmdb.

Kurulu dosyalar yerel rpmdb'ye değil Fedora'nın imzalı paketlerine karşı denetlenir.
"""
import stat
from pathlib import Path
from types import SimpleNamespace as NS

from satsuma import signed_verify as sv

ROOT = Path(__file__).parents[1]
REG = stat.S_IFREG | 0o755
CFG = stat.S_IFREG | 0o644


def header(entries):
    return ''.join(f'{p}\t{d}\t{f}\t{m}\n' for p, d, f, m in entries)


SIGNED = [('/usr/lib/systemd/systemd', 'aa', 0, REG), ('/etc/systemd/system.conf', 'bb', sv.RPMFILE_CONFIG, CFG),
          ('/usr/share/doc/systemd/README', 'cc', sv.RPMFILE_DOC, CFG)]


class Host:
    def __init__(self, local=SIGNED, checksig='Header V4 RSA/SHA256 Signature, key ID abc: OK\n', download=True):
        self.local, self.checksig, self.download, self.calls = local, checksig, download, []

    def runner(self, args, **kw):
        self.calls.append(args)
        tool = args[0].rsplit('/', 1)[-1]
        if tool == 'rpm' and args[1] == '-q' and args[3].startswith('%{NAME}'):
            return NS(returncode=0, stdout='systemd-(none):256.1-1.fc44.x86_64\n', stderr='')
        if tool == 'dnf':
            if self.download:
                Path(args[3], 'systemd-256.1-1.fc44.x86_64.rpm').write_bytes(b'rpm')
            return NS(returncode=0 if self.download else 1, stdout='', stderr='')
        if tool == 'rpmkeys' and '--checksig' in args:
            return NS(returncode=0 if 'OK' in self.checksig else 1, stdout=self.checksig, stderr='')
        if tool == 'rpmkeys':
            return NS(returncode=0, stdout='', stderr='')
        if tool == 'rpm' and args[1] == '-qp' and 'FILEDIGESTALGO' in args[3]:
            return NS(returncode=0, stdout='8\n', stderr='')
        if tool == 'rpm' and args[1] == '-qp':
            return NS(returncode=0, stdout=header(SIGNED), stderr='')
        if tool == 'rpm' and args[1] == '-q':
            return NS(returncode=0, stdout=header(self.local), stderr='')
        raise AssertionError(args)


def disk(table):
    return lambda path, algorithm: table.get(path, (None, 'missing'))


GOOD_DISK = {'/usr/lib/systemd/systemd': ('aa', None), '/etc/systemd/system.conf': ('bb', None)}


def test_without_a_pinned_key_nothing_is_called_clean():
    report = sv.verify(['systemd'], Host().runner, keys=[])
    assert report['status'] == 'NO_PINNED_KEY'


def test_matching_files_verify_and_excluded_docs_are_fine():
    report = sv.verify(['systemd'], Host().runner, keys=['/k'], digest_of=disk(GOOD_DISK))
    assert report['status'] == 'VERIFIED', report
    assert report['packages'][0]['nevra'] == 'systemd-0:256.1-1.fc44.x86_64'


def test_changed_binary_is_high_changed_config_is_review():
    table = {**GOOD_DISK, '/usr/lib/systemd/systemd': ('ff', None), '/etc/systemd/system.conf': ('ee', None)}
    result = sv.verify(['systemd'], Host().runner, keys=['/k'], digest_of=disk(table))
    findings = {f['path']: (f['reason'], f['severity']) for f in result['packages'][0]['findings']}
    assert findings == {'/usr/lib/systemd/systemd': ('file_changed', 'high'),
                        '/etc/systemd/system.conf': ('config_changed', 'review')}
    assert result['status'] == 'CHANGED'


def test_rewritten_rpmdb_is_caught_even_when_disk_matches_it():
    # Attacker replaced the binary and rewrote the local database to match.
    forged = [('/usr/lib/systemd/systemd', 'ff', 0, REG), *SIGNED[1:]]
    table = {**GOOD_DISK, '/usr/lib/systemd/systemd': ('ff', None)}
    result = sv.verify(['systemd'], Host(local=forged).runner, keys=['/k'], digest_of=disk(table))
    reasons = {f['reason'] for f in result['packages'][0]['findings']}
    assert {'rpmdb_differs_from_signed_package', 'file_changed'} <= reasons


def test_bad_signature_or_missing_download_is_never_verified():
    bad = sv.verify(['systemd'], Host(checksig='Header V4 RSA/SHA256 Signature, key ID abc: NOKEY\n').runner,
                    keys=['/k'], digest_of=disk(GOOD_DISK))
    assert bad['status'] == 'CHANGED' and bad['packages'][0]['status'] == 'SIGNATURE_INVALID'
    none = sv.verify(['systemd'], Host(download=False).runner, keys=['/k'], digest_of=disk(GOOD_DISK))
    assert none['status'] == 'INCOMPLETE'


def test_signature_check_uses_a_private_keyring_never_the_system_one():
    host = Host()
    sv.verify(['systemd'], host.runner, keys=['/k'], digest_of=disk(GOOD_DISK))
    for args in host.calls:
        if args[0].endswith('rpmkeys'):
            assert args[1] == '--dbpath' and 'satsuma-verify-' in args[2]


def test_disk_digest_never_follows_links(tmp_path):
    real = tmp_path / 'real'; real.write_bytes(b'x')
    link = tmp_path / 'link'; link.symlink_to(real)
    assert sv.disk_digest(str(link), 'sha256') == (None, 'not_a_regular_file')
    assert sv.disk_digest(str(real), 'sha256')[0] == __import__('hashlib').sha256(b'x').hexdigest()


def test_key_with_wrong_fingerprint_is_not_used(tmp_path):
    (tmp_path / 'k.asc').write_text('key')
    runner = lambda args, **kw: NS(returncode=0, stdout='fpr:::::::::OTHER:\n', stderr='')
    assert sv.pinned_keys(runner, {'EXPECTED': 'k.asc'}, tmp_path) == []
    runner_ok = lambda args, **kw: NS(returncode=0, stdout='fpr:::::::::EXPECTED:\n', stderr='')
    assert sv.pinned_keys(runner_ok, {'EXPECTED': 'k.asc'}, tmp_path) == [tmp_path / 'k.asc']


def test_service_runs_signed_verification_after_the_inventory():
    unit = (ROOT / 'systemd/satsuma-boot-inventory.service').read_text()
    assert unit.index('--boot-inventory') < unit.index('--signed-verify')
    assert 'network-online.target' in unit
