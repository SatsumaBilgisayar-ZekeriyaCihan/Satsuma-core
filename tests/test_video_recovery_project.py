"""satsuma-video-recovery is tested in its own directory, so its tests always run with Satsuma's.

satsuma-video-recovery kendi klasöründe test edilir; testleri Satsuma'nınkilerle birlikte hep çalışır.
"""
import subprocess
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1] / 'satsuma-video-recovery'
import pytest
if not PROJECT.exists():
    pytest.skip('satsuma-video-recovery not in this source tree', allow_module_level=True)


def test_video_recovery_tests_pass():
    result = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-p', 'no:cacheprovider', 'tests'],
                            cwd=PROJECT, capture_output=True, text=True, timeout=600)
    assert result.returncode == 0, result.stdout[-3000:] + result.stderr[-2000:]
