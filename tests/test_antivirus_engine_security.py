"""Antivirus engine regression checks: no real scanners or host mutations."""
import os
from types import SimpleNamespace

from satsuma import security_scan


def test_scanner_log_remains_private_even_with_permissive_umask(tmp_path):
    old = os.umask(0o000)
    try:
        def fake_scanner(command, *, stdout, **kwargs):
            stdout.write(b"Infected files: 0\n")
            return SimpleNamespace(returncode=0)
        result = security_scan._result("clamav", ["/usr/bin/clamscan"], runner=fake_scanner, archive=tmp_path / "logs")
    finally:
        os.umask(old)
    logs = list((tmp_path / "logs").glob("*.log"))
    assert len(logs) == 1
    assert logs[0].stat().st_mode & 0o777 == 0o600
    assert result["status"] == "COMPLETED"
    assert logs[0].read_bytes() == b"Infected files: 0\n"


def test_unavailable_antivirus_does_not_report_clean(tmp_path):
    def failed(command, *, stdout, **kwargs):
        raise FileNotFoundError("Scanner is missing")
    result = security_scan._result("clamav", ["/nonexistent/clamscan"], runner=failed, archive=tmp_path / "logs")
    assert result["status"] == "ERROR"
    assert result["findings"] == 0
    assert result["error"]
