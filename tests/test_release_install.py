import io
from pathlib import Path
import subprocess
import tarfile

import pytest

from installer import release_install as install


def test_network_download_is_opt_in_and_signature_checks_remain_enabled():
    command = install.dnf_command(False, 'install', 'gcc')
    assert '--cacheonly' in command
    assert '--setopt=localpkg_gpgcheck=1' in command
    assert '--cacheonly' not in install.dnf_command(True, 'install', 'gcc')
    assert not any('nogpg' in token for token in command)


def test_wrong_platform_cannot_install(tmp_path):
    release = tmp_path / 'os-release'
    release.write_text('ID=debian\nVERSION_ID="13"\n')
    with pytest.raises(RuntimeError, match='Fedora 44'):
        install.require_fedora44(release, 'x86_64')
    release.write_text('ID=fedora\nVERSION_ID="44"\n')
    install.require_fedora44(release, 'x86_64')


@pytest.mark.parametrize('name,kind', [('../escape', 'file'), ('/absolute', 'file'),
                                      ('link', 'symlink'), ('device', 'device')])
def test_archive_cannot_escape_or_create_special_nodes(tmp_path, name, kind):
    archive = tmp_path / 'source.tar.gz'
    with tarfile.open(archive, 'w:gz') as tar:
        member = tarfile.TarInfo(name)
        if kind == 'symlink':
            member.type = tarfile.SYMTYPE; member.linkname = '../../escape'
        elif kind == 'device':
            member.type = tarfile.CHRTYPE
        else:
            member.size = 1
        tar.addfile(member, io.BytesIO(b'x') if member.isfile() else None)
    with pytest.raises(RuntimeError, match='Güvensiz'):
        install.extract(archive, tmp_path / 'unpack')
    assert not (tmp_path / 'unpack').exists()


def test_signature_from_another_primary_key_is_rejected(monkeypatch, tmp_path):
    monkeypatch.setattr(install, 'run', lambda *a, **k: subprocess.CompletedProcess([], 0,
        stdout='[GNUPG:] VALIDSIG ' + 'A' * 40 + ' 2026-10-23 1 0 4 0 1 10 00 ' + 'B' * 40 + '\n'))
    with pytest.raises(RuntimeError, match='beklenen'):
        install.verify_signature(tmp_path, tmp_path / 'sig', tmp_path / 'data')


def test_unsigned_rpm_digest_success_is_not_accepted_as_signature(monkeypatch, tmp_path):
    monkeypatch.setattr(install, 'run', lambda *a, **k: subprocess.CompletedProcess([], 0,
        stdout='Header SHA256 digest: OK\nPayload SHA256 digest: OK\n'))
    with pytest.raises(RuntimeError, match='GPG imzası'):
        install.verify_rpm(tmp_path / 'test.rpm', tmp_path / 'pub', tmp_path)


def test_verify_only_never_calls_dnf_or_sudo(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(install, 'verify_package', lambda *a: calls.append('verified'))
    monkeypatch.setattr(install, 'require_fedora44', lambda *a: pytest.fail('verify is platform independent'))
    monkeypatch.setattr(install, 'run', lambda *a, **k: pytest.fail('no installation during verify-only'))
    assert install.main(['--verify-only', '--package-dir', str(tmp_path)]) == 0
    assert calls == ['verified']
