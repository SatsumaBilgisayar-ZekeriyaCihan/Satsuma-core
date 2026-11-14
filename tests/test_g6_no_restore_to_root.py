"""Audit G6: no code path unpacks an archive over the root filesystem.

Denetim G6: hiçbir kod yolu bir arşivi sistemin köküne açmaz.
"""
import re
from pathlib import Path

from satsuma.response import ResponseWorker

ROOT = Path(__file__).parents[1]


def test_restore_config_is_gone():
    assert not hasattr(ResponseWorker, 'restore_config')


def test_nothing_extracts_into_slash():
    pattern = re.compile(r"""['"]-C['"]\s*,\s*['"]/['"]|extractall\(\s*['"]/['"]""")
    hits = [str(p.relative_to(ROOT)) for p in [*ROOT.glob('satsuma/**/*.py'), *ROOT.glob('integrations/*.py'),
                                              *ROOT.glob('installer/*.py'), *ROOT.glob('*.py')]
            if pattern.search(p.read_text(errors='replace'))]
    assert not hits


def test_nothing_writes_etc_hosts():
    # A removed sinkhole appended unvalidated names to /etc/hosts (MITM door).
    assert not hasattr(ResponseWorker, 'dns_sinkhole')
    hits = [str(p.relative_to(ROOT)) for p in [*ROOT.glob('satsuma/**/*.py'), *ROOT.glob('integrations/*.py'),
                                              *ROOT.glob('installer/*.py'), *ROOT.glob('workers/**/*.py')]
            if "'/etc/hosts'" in p.read_text() or '"/etc/hosts"' in p.read_text()]
    # Only the AIDE guard may name it (user decision 2026-11-10): it puts back the
    # snapshot copy, never new names, only with the admin password and only
    # after every line is validated.
    assert hits in ([], ['satsuma/aide_guard.py'])
    import inspect
    from satsuma import aide_guard
    assert aide_guard.VALIDATED.get('/etc/hosts') == 'hosts'
    assert 'password' in inspect.signature(aide_guard.Guard.restore).parameters
    assert 'validate_hosts' in inspect.getsource(aide_guard.Guard._restore_copy)
    with __import__('pytest').raises(RuntimeError):
        aide_guard.validate_hosts(b'203.0.113.66 bank.example evil!name\n')
