from pathlib import Path
from unittest.mock import patch
import importlib.util

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('onaccess_setup', ROOT/'installer/onaccess_setup.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

def test_default_blocking_is_enabled_and_no_vm_gate():
    with patch.object(module.pwd, 'getpwnam'):
        rendered=module.render('LocalSocket /run/clamd.scan/clamd.sock\nUser clamscan\n')
    assert 'OnAccessPrevention yes' in rendered
    assert 'OnAccessIncludePath /home' in rendered
    assert 'OnAccessExcludeUname clamscan' in rendered
    assert 'OnAccessMountPath /' not in rendered
    assert 'require_vm' not in (ROOT/'installer/onaccess_setup.py').read_text()

def test_refuse_tcp_and_conflicting_policy():
    import pytest
    with pytest.raises(RuntimeError): module.render('TCPSocket 3310\n')
    with pytest.raises(RuntimeError): module.render('LocalSocket /run/clamd.sock\nOnAccessPrevention no\n')

def test_wired_to_rpm_and_systemd():
    rpm=(ROOT/'packaging/satsuma-core.spec').read_text()
    unit=(ROOT/'systemd/satsuma-clamonacc.service').read_text()
    assert 'onaccess_setup.py install' in rpm
    assert 'systemctl enable clamd@scan.service satsuma-clamonacc.service' in rpm
    assert 'systemctl start satsuma-clamonacc.service' in rpm
    assert 'ExecStartPre=' in unit
    assert 'ExecStart=/usr/bin/clamonacc ' in unit
    assert 'Requires: clamav-clamonacc' not in rpm


def test_candidate_listener_enabled_but_no_unverified_log_actions():
    rpm=(ROOT/'packaging/satsuma-core.spec').read_text()
    unit=(ROOT/'systemd/satsuma-clamonacc.service').read_text()
    assert 'systemctl enable satsuma-onaccess-listener.service' in rpm
    assert 'systemctl start satsuma-onaccess-listener.service' in rpm
    assert '--foreground --verbose' in unit
    assert 'satsuma-onaccess-listener' in rpm

def test_unknown_format_does_not_invoke_quarantine():
    from satsuma.onaccess_events import candidate_from_trusted_journal_fields
    record={'_SYSTEMD_UNIT': 'satsuma-clamonacc.service', '_EXE':'/usr/bin/clamonacc',
            '_UID':'0', 'MESSAGE':'Unknown ClamAV finding /home/test FOUND'}
    assert candidate_from_trusted_journal_fields(record) is None
