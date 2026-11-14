"""Read-only CLI help must remain available before an installation inventory exists."""
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_help_and_version_do_not_require_installed_manifest():
    help_result = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--help"],
        cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    assert help_result.returncode == 0, help_result.stderr
    assert "usage:" in help_result.stdout

    version_result = subprocess.run(
        [sys.executable, str(ROOT / "main.py"), "--version"],
        cwd=ROOT, capture_output=True, text=True, timeout=10,
    )
    assert version_result.returncode == 0, version_result.stderr
    assert (ROOT / "VERSION").read_text().strip() in version_result.stdout
