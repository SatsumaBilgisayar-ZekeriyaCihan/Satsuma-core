"""SHA-256 blacklist: shipped in the image, enforced by every ClamAV scan.

SHA-256 kara listesi: imajla gelir, her ClamAV taramasında uygulanır.
"""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from satsuma import hash_blacklist as hb

ROOT = Path(__file__).parents[1]


def table_for(path):
    data = Path(path).read_bytes()
    return {hashlib.sha256(data).hexdigest(): (len(data), 'Satsuma.Blacklist.Test.1')}


def test_shipped_list_covers_the_quarantined_web_console():
    data = json.loads(hb.BLACKLIST.read_text())
    paths = {e['path'] for g in data['groups'] for e in g['entries']}
    assert 'optional_components/web-console/app/frontend/package-lock.json' in paths
    assert 'satsuma-web-console-current.zip' in paths
    assert any(p.startswith('optional_components/web-bridge/') for p in paths)
    table = hb.load()
    assert '91398da55d830ac2f91436ac989abc8e5ce9945072eb25d199c1b17a664a8246' in table
    assert len(table) == 78  # 77 web console files + the manifest key


MANIFEST_KEY_SHA256 = 'b19430a6ec25be32e4ca036d185416c6432a550d664fdd5c911ed030d05c551f'


def test_the_manifest_key_digest_is_blacklisted_at_the_owners_request():
    """The key's digest is listed, never the key: a 32-byte key cannot be recovered from it.

    Anahtarın kendisi değil özeti listelenir: 32 baytlık anahtar özetinden geri çıkarılamaz.
    """
    table = hb.load()
    assert table[MANIFEST_KEY_SHA256] == (32, 'Satsuma.Blacklist.ManifestKey.1')
    assert f'{MANIFEST_KEY_SHA256}:32:Satsuma.Blacklist.ManifestKey.1' in hb.render_hsb(table).splitlines()
    data = json.loads(hb.BLACKLIST.read_text())
    group = [g for g in data['groups'] if g['name'] == 'ManifestKey'][0]
    assert [e['path'] for e in group['entries']] == ['/etc/satsuma-core/trust/manifest.key']


def test_a_file_with_the_blacklisted_digest_is_reported_by_check(tmp_path):
    key = tmp_path / 'k'
    key.write_bytes(b'x' * 32)
    table = {hashlib.sha256(b'x' * 32).hexdigest(): (32, 'Satsuma.Blacklist.ManifestKey.1')}
    assert hb.check(key, table) == 'Satsuma.Blacklist.ManifestKey.1'
    key.write_bytes(b'y' * 32)
    assert hb.check(key, table) is None


def test_nothing_shipped_with_the_product_is_blacklisted():
    table = hb.load()
    for path in ROOT.rglob('*'):
        if {'.git', '__pycache__', '.pytest_cache'} & set(path.parts) or path.is_symlink() or not path.is_file():
            continue
        assert hashlib.sha256(path.read_bytes()).hexdigest() not in table, path


def test_hsb_lines_follow_clamav_format():
    for line in hb.render_hsb(hb.load()).splitlines():
        digest, size, name = line.split(':')
        assert len(digest) == 64 and int(size) > 0 and name.startswith(('Satsuma.Blacklist.WebConsole.', 'Satsuma.Blacklist.ManifestKey.'))


@pytest.mark.parametrize('bad', [
    {'groups': [{'name': 'X', 'entries': [{'sha256': 'zz', 'size': 1}]}]},
    {'groups': [{'name': 'X', 'entries': [{'sha256': 'a' * 64, 'size': 0}]}]},
    {'groups': [{'name': 'bad name', 'entries': [{'sha256': 'a' * 64, 'size': 1}]}]},
    {'groups': []},
])
def test_malformed_list_is_an_error_never_an_empty_list(tmp_path, bad):
    path = tmp_path / 'l.json'
    path.write_text(json.dumps(bad))
    with pytest.raises((ValueError, KeyError)):
        hb.load(path)


def _has_group(name):
    import grp
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


@pytest.mark.skipif(not _has_group('clamscan'), reason='needs the Fedora clamscan group (ClamAV package)')
def test_install_is_idempotent_and_refuses_a_symlink(tmp_path):
    table = {'a' * 64: (10, 'Satsuma.Blacklist.Test.1')}
    assert hb.install(table, tmp_path)['status'] == 'INSTALLED'
    assert hb.install(table, tmp_path)['status'] == 'UNCHANGED'
    assert (tmp_path / hb.HSB_NAME).read_text() == 'a' * 64 + ':10:Satsuma.Blacklist.Test.1\n'
    other = tmp_path / 'other'; other.mkdir()
    (other / hb.HSB_NAME).symlink_to(tmp_path / 'elsewhere')
    with pytest.raises(RuntimeError):
        hb.install(table, other)


def test_check_finds_a_listed_file_and_never_follows_links(tmp_path):
    bad = tmp_path / 'bad.bin'; bad.write_bytes(b'quarantined content ' * 4)
    table = table_for(bad)
    assert hb.check(bad, table) == 'Satsuma.Blacklist.Test.1'
    clean = tmp_path / 'clean.bin'; clean.write_bytes(b'x' * len(bad.read_bytes()))
    assert hb.check(clean, table) is None
    link = tmp_path / 'link'; link.symlink_to(bad)
    assert hb.check(link, table) is None


@pytest.mark.skipif(not shutil.which('clamscan'), reason='ClamAV not installed here')
def test_real_clamav_reports_a_listed_file(tmp_path):
    bad = tmp_path / 'bad.bin'; bad.write_bytes(b'quarantined content ' * 4)
    hb.install(table_for(bad), tmp_path)
    run = subprocess.run(['clamscan', '--no-summary', '-d', str(tmp_path / hb.HSB_NAME), str(bad)],
                         capture_output=True, text=True, timeout=120)
    assert run.returncode == 1 and 'Satsuma.Blacklist.Test.1' in run.stdout


def test_blacklist_is_installed_at_install_and_on_every_inventory_run():
    unit = (ROOT / 'systemd/satsuma-boot-inventory.service').read_text()
    assert 'main.py --hash-blacklist' in unit and '-/var/lib/clamav' in unit
    assert 'main.py --hash-blacklist ||' in (ROOT / 'packaging/satsuma-core.spec').read_text()
