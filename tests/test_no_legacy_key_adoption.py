"""2.2.36: a key left by the pre-2.2 product is never adopted as the integrity key.

2.2.36: 2.2 öncesi üründen kalan anahtar, bütünlük anahtarı olarak asla benimsenmez.

provision_key() used to copy /etc/anka-core/trust/manifest.key into the new key
file whenever that old file (or a symlink with that name) existed. The old key
signs the application manifest and the DNS configuration; a copy that leaked
while the old product ran would have kept signing the new one.
provision_key() eskiden /etc/anka-core/trust/manifest.key dosyası (ya da o adla
bir sembolik bağ) varsa onu yeni anahtar dosyasına kopyalıyordu. Eski anahtar
uygulama manifestosunu ve DNS yapılandırmasını imzalar; eski ürün çalışırken
sızan bir kopya yenisini de imzalamaya devam ederdi.
"""
import inspect
import os
from pathlib import Path

from installer import integrity
from satsuma import protected_storage


def _provision(tmp_path, monkeypatch, legacy_present):
    reads = []
    original = Path.exists
    monkeypatch.setattr(integrity, 'read_key', lambda path=None, ownership=True: reads.append(str(path)) or b'L' * 32)
    monkeypatch.setattr(protected_storage, 'open_directory',
                        lambda path: os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY))
    monkeypatch.setattr(Path, 'exists',
                        lambda self: legacy_present and str(self).startswith('/etc/anka-core') or original(self))
    key_path = tmp_path / 'manifest.key'
    return integrity.provision_key(key_path), key_path, reads


def test_an_existing_old_key_is_neither_read_nor_copied(tmp_path, monkeypatch):
    key, key_path, reads = _provision(tmp_path, monkeypatch, legacy_present=True)
    assert reads == []
    assert key != b'L' * 32 and len(key) == 32 and key_path.read_bytes() == key


def test_a_fresh_random_key_is_made_when_none_exists(tmp_path, monkeypatch):
    first, _, _ = _provision(tmp_path, monkeypatch, legacy_present=False)
    (tmp_path / 'manifest.key').unlink()
    second, _, _ = _provision(tmp_path, monkeypatch, legacy_present=False)
    assert len(first) == len(second) == 32 and first != second


def test_the_old_product_path_is_not_in_the_installer_at_all():
    assert 'anka-core' not in inspect.getsource(integrity)
