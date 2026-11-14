"""No host sysctl changes: use isolated files and one disposable child."""
import json
from pathlib import Path
import subprocess
import sys

import pytest

from satsuma.memory_access import POLICY, check, harden
from satsuma.early_guard import run_guard


def fixture_tree(root):
    for name in POLICY:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('0\n')


def test_hardening_enforces_memory_read_and_dump_policy(tmp_path):
    fixture_tree(tmp_path)
    assert check(tmp_path)['ok'] is False
    assert harden(tmp_path)['ok'] is True
    for name, value in POLICY.items():
        assert (tmp_path / name).read_text().strip() == value
    assert harden(tmp_path)['ok'] is True


def test_preexisting_stronger_ptrace_policy_is_not_weakened(tmp_path):
    fixture_tree(tmp_path)
    (tmp_path / 'kernel/yama/ptrace_scope').write_text('3\n')
    assert harden(tmp_path)['ok'] is True
    assert (tmp_path / 'kernel/yama/ptrace_scope').read_text().strip() == '3'


def test_missing_control_is_not_silently_skipped(tmp_path):
    fixture_tree(tmp_path)
    (tmp_path / 'kernel/yama/ptrace_scope').unlink()
    with pytest.raises(FileNotFoundError):
        harden(tmp_path)
    assert check(tmp_path)['ok'] is False


def test_unsafe_access_controls_do_not_unlock_boot_response():
    result = run_guard(verifier=lambda: 1, boot_id='fixture',
                       memory_access_checker=lambda: {'ok': False})
    assert result['response_unlocked'] is False
    assert any(r['code'] == 'MEMORY_ACCESS_UNSAFE' for r in result['failure_reasons'])


def test_daemon_can_make_own_memory_non_dumpable():
    root = Path(__file__).resolve().parents[1]
    completed = subprocess.run([sys.executable, '-c',
        'from satsuma.memory_access import protect_self; import ctypes; '
        'protect_self(); print(ctypes.CDLL(None).prctl(3,0,0,0,0))'],
        cwd=root, capture_output=True, text=True, check=True, timeout=5)
    assert completed.stdout.strip() == '0'
