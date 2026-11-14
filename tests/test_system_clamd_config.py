"""Fail-closed system clamd configuration for descriptor-bound file scans."""
from pathlib import Path
from types import SimpleNamespace
import pytest

from satsuma.temporary_scan import _system_clamd_config


def write_config(tmp_path, content, monkeypatch):
    config = tmp_path / 'scan.conf'
    config.write_text(content)
    original_lstat = Path.lstat
    def trusted_lstat(self, *args, **kwargs):
        info = original_lstat(self, *args, **kwargs)
        if self == config:
            return SimpleNamespace(st_mode=info.st_mode, st_uid=0)
        return info
    monkeypatch.setattr(Path, 'lstat', trusted_lstat)
    return config


def test_local_socket_only(tmp_path, monkeypatch):
    p = write_config(tmp_path, 'LocalSocket /run/clamd.scan/clamd.sock\n', monkeypatch)
    assert _system_clamd_config(p) == p


@pytest.mark.parametrize('content', [
    '',
    'LocalSocket relative.sock\n',
    'LocalSocket /run/clamd.scan/clamd.sock\nLocalSocket /tmp/other.sock\n',
    'LocalSocket /run/satsuma-ram-clamd/clamd.sock\n',
    'LocalSocket /run/../tmp/clamd.sock\n',
    'LocalSocket /run/clamd.scan/clamd.sock\nTCPSocket 3310\n',
    'LocalSocket /run/clamd.scan/clamd.sock\nTCPAddr 127.0.0.1\n',
])
def test_unsafe_socket_config_is_refused(tmp_path, content, monkeypatch):
    p = write_config(tmp_path, content, monkeypatch)
    with pytest.raises(RuntimeError):
        _system_clamd_config(p)


def test_world_writable_config_is_refused(tmp_path, monkeypatch):
    p = write_config(tmp_path, 'LocalSocket /run/clamd.scan/clamd.sock\n', monkeypatch)
    p.chmod(0o666)
    with pytest.raises(PermissionError):
        _system_clamd_config(p)
