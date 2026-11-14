"""Regression tests for the owner-supplied 2.2.37 entrypoint.

Use module doubles to avoid starting services or touching the real host.
"""
import json
import runpy
import sys
import types
from pathlib import Path

import pytest

ENTRYPOINT = Path(__file__).resolve().parents[1] / 'main.py'


def _run(monkeypatch, argv, *, failure=None):
    called = []
    guard = types.ModuleType('satsuma.self_guard')
    def verify():
        called.append('verify')
        if failure is not None:
            raise failure
    guard.verify = verify
    app = types.ModuleType('satsuma.app')
    app.main = lambda: called.append('main')
    status = types.ModuleType('satsuma.configuration_status')
    def entrypoint(fn):
        called.append('entrypoint')
        fn()
        return 0
    status.entrypoint = entrypoint
    monkeypatch.setitem(sys.modules, 'satsuma.self_guard', guard)
    monkeypatch.setitem(sys.modules, 'satsuma.app', app)
    monkeypatch.setitem(sys.modules, 'satsuma.configuration_status', status)
    monkeypatch.setattr(sys, 'argv', ['main.py', *argv])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(ENTRYPOINT), run_name='__main__')
    return called, stopped.value.code


def test_normal_start_requires_integrity(monkeypatch):
    called, code = _run(monkeypatch, [])
    assert called == ['verify', 'entrypoint', 'main']
    assert code == 0


@pytest.mark.parametrize('argv', [['-h'], ['--help'], ['--version']])
def test_recovery_information_skips_guard(monkeypatch, argv):
    called, code = _run(monkeypatch, argv)
    assert called == ['entrypoint', 'main']
    assert code == 0


def test_integrity_failure_never_enters_application(monkeypatch, capsys):
    called, code = _run(monkeypatch, [], failure=RuntimeError('bad signature'))
    assert called == ['verify']
    assert code == 78
    error = json.loads(capsys.readouterr().err)
    assert error['status'] == 'INTEGRITY_CHECK_FAILED'
    assert error['monitoring_started'] is False
    assert error['mutations_locked'] is True
