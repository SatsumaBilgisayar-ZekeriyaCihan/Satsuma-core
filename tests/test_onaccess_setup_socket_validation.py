"""On-access setup must refuse ambiguous and retired sockets."""
import importlib.util
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('onaccess_setup_v17', ROOT / 'installer/onaccess_setup.py')
setup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(setup)

@pytest.mark.parametrize('config', [
    'LocalSocket /run/clamd.sock\nLocalSocket /run/other.sock\n',
    'LocalSocket /run/clamd.sock\nTCPSocket 3310\n',
    'LocalSocket /run/clamd.sock\nTCPAddr 127.0.0.1\n',
    'LocalSocket relative.sock\n',
    'LocalSocket /run/../tmp/clamd.sock\n',
    'LocalSocket /run/satsuma-ram-clamd/clamd.sock\n',
    'LocalSocket /run/satsuma-ram-clamd/sub/clamd.sock\n',
])
def test_rejects_unsafe_socket_config(config, monkeypatch):
    monkeypatch.setattr(setup.pwd, 'getpwnam', lambda user: object())
    with pytest.raises(RuntimeError):
        setup.render(config)


def test_valid_local_only_socket(monkeypatch):
    monkeypatch.setattr(setup.pwd, 'getpwnam', lambda user: object())
    rendered = setup.render('LocalSocket /run/clamd.scan/clamd.sock\n')
    assert 'OnAccessPrevention yes' in rendered


def test_verify_rejects_duplicate_endpoint(tmp_path, monkeypatch):
    config = tmp_path / 'scan.conf'
    config.write_text('LocalSocket /run/clamd.sock\nLocalSocket /run/other.sock\n'
                      '# SATSUMA_ONACCESS_BEGIN\nOnAccessIncludePath /home\n'
                      'OnAccessPrevention yes\nOnAccessExcludeUname clamscan\n'
                      'OnAccessMaxFileSize 5M\n# SATSUMA_ONACCESS_END\n')
    monkeypatch.setattr(setup, 'CONFIG', config)
    monkeypatch.setattr(setup, 'trusted_file', lambda path: None)
    with pytest.raises(RuntimeError):
        setup.verify()
