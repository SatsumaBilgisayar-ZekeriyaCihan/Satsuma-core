"""unhide hidden process/port scan and required tools (2.2.31).

Field 2026-11-04: unhide and dbus-monitor were not dependencies; the D-Bus
worker could not run and no hidden-object scan existed.

unhide ile gizli süreç/port taraması ve gerekli araçlar.
"""
import os
import socket
import subprocess
from types import SimpleNamespace

import pytest

from satsuma import unhide_scan as unhide
from satsuma.dbus_stream import DbusStream

LINUX = """Unhide 20211016
[*]Searching for Hidden processes through getpriority() scanning

Found HIDDEN PID: 31337
\tCmdline: "/usr/lib/.x/kworker"
\tExecutable: "/usr/lib/.x/kworker"

Found HIDDEN PID: 4242
\tCmdline: "<none>"
\tExecutable: "<no link>"
Found FAKE PID: 5555\tCommand = ghost not seen by 4 sys fonc
"""
TCP = """Unhide-tcp 20211016
[*]Starting TCP checking
Found Hidden port that not appears in ss: 31337
[*]Starting UDP checking
Found Hidden port that not appears in ss: 5353
Found Hidden port that not appears in ss: 99999
"""


def test_parsers():
    found = unhide.parse_linux(LINUX)
    assert found[0] == {'kind': 'hidden_pid', 'pid': 31337, 'cmdline': '/usr/lib/.x/kworker', 'executable': '/usr/lib/.x/kworker'}
    assert found[1]['executable'] == '<no link>'
    assert found[2] == {'kind': 'fake_pid', 'pid': 5555, 'command': 'ghost'}
    assert unhide.parse_tcp(TCP) == [{'kind': 'hidden_port', 'proto': 'tcp', 'port': 31337, 'missing_from': 'ss'},
                                     {'kind': 'hidden_port', 'proto': 'udp', 'port': 5353, 'missing_from': 'ss'}]


@pytest.mark.parametrize('alive,listed,verdict', [
    ([True, True], {1, 2}, 'hidden'), ([False], {1, 2}, 'transient'),
    ([True], {42}, 'visible'), ([True, False], {1}, 'transient')])
def test_hidden_pid_is_verified_again(alive, listed, verdict):
    answers = iter(alive)
    assert unhide.confirm_pid(42, listed=lambda: listed, alive=lambda pid: next(answers)) == verdict


def test_fake_and_port_verification():
    assert unhide.confirm_fake(7, listed=lambda: {7}, alive=lambda p: False) == 'fake'
    assert unhide.confirm_fake(7, listed=lambda: {7}, alive=lambda p: True) == 'real'
    assert unhide.confirm_fake(7, listed=set, alive=lambda p: False) == 'transient'
    assert unhide.confirm_pid(1, listed=set, alive=lambda p: True) == 'invalid'
    assert unhide.confirm_port('tcp', 1, in_use=lambda *a: True, listed=lambda p: set()) == 'hidden'
    assert unhide.confirm_port('tcp', 1, in_use=lambda *a: True, listed=lambda p: {1}) == 'visible'
    assert unhide.confirm_port('tcp', 1, in_use=lambda *a: False, listed=lambda p: set()) == 'transient'


def test_live_checks_on_this_machine():
    server = socket.socket()
    server.bind(('0.0.0.0', 0))
    server.listen(1)
    try:
        port = server.getsockname()[1]
        assert unhide.confirm_port('tcp', port) == 'visible'
    finally:
        server.close()
    assert unhide.confirm_pid(os.getpid()) == 'visible'
    assert unhide.confirm_pid(2 ** 22 + 7) == 'transient'


def test_run_reports_only_verified_objects_with_a_clean_environment():
    calls = []
    def runner(args, **kwargs):
        calls.append((args, kwargs['env']))
        return SimpleNamespace(stdout=TCP if args[0] == unhide.UNHIDE_TCP else LINUX)
    report = unhide.run(runner=runner, confirm_pid=lambda pid: 'hidden' if pid == 31337 else 'transient',
                        confirm_port=lambda proto, port: 'hidden' if port == 31337 else 'visible',
                        confirm_fake=lambda pid: 'real')
    assert [(f['kind'], f.get('pid') or f.get('port')) for f in report['findings']] == [('hidden_pid', 31337), ('hidden_port', 31337)]
    assert len(report['discarded']) == 3
    assert all(env == {'PATH': '/usr/sbin:/usr/bin', 'LC_ALL': 'C'} for _, env in calls)
    assert calls[0][0] == [unhide.linux_binary(), '-m', 'quick', 'reverse']


def test_missing_dbus_monitor_is_named(monkeypatch):
    monkeypatch.setattr(os.path, 'exists', lambda p: False if p == '/usr/bin/dbus-monitor' else True)
    with pytest.raises(RuntimeError, match='dbus-tools'):
        DbusStream()


def test_spec_requires_the_tools():
    from pathlib import Path
    spec = (Path(__file__).parents[1] / 'packaging/satsuma-core.spec').read_text()
    assert 'Requires: dbus-tools' in spec and 'Requires: unhide' in spec
