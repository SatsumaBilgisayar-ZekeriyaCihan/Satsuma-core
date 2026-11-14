"""2.2.36: the hidden process/port scan finds unhide under the name the Fedora package ships.

2.2.36: gizli süreç/port taraması unhide'ı Fedora paketinin verdiği adla bulur.

Field 2026-11-04 (unhide-20240510 on Fedora): the package installs /usr/bin/unhide,
unhide-tcp and unhide_rb; there is no unhide-linux. The scan looked only for
/usr/sbin/unhide-linux, so it never ran and the full check reported "unhide eksik"
although the package was installed.
Saha 2026-11-04 (Fedora'da unhide-20240510): paket /usr/bin/unhide, unhide-tcp ve
unhide_rb kurar; unhide-linux yoktur. Tarama yalnızca /usr/sbin/unhide-linux'a
bakıyordu, hiç çalışmadı ve paket kurulu olduğu hâlde tam kontrol "unhide eksik"
bildirdi.
"""
import os
from types import SimpleNamespace

from satsuma import full_check, unhide_scan as unhide

NEW = '/usr/sbin/unhide'
OLD = '/usr/sbin/unhide-linux'
TOOLS = {'/usr/bin/dbus-monitor', '/usr/sbin/unhide-tcp', '/usr/bin/rkhunter', '/usr/bin/suricata-update'}


def test_the_new_package_name_is_found():
    assert unhide.linux_binary(exists=lambda p: p in {NEW, '/usr/sbin/unhide-tcp'}) == NEW


def test_the_old_package_name_is_still_found():
    assert unhide.linux_binary(exists=lambda p: p == OLD) == OLD


def test_the_new_name_wins_when_both_exist():
    assert unhide.linux_binary(exists=lambda p: p in {NEW, OLD}) == NEW


def test_the_name_the_current_package_ships_is_reported_when_none_exists():
    assert unhide.linux_binary(exists=lambda p: False) == NEW


def test_run_executes_the_resolved_binary_and_unhide_tcp(monkeypatch):
    monkeypatch.setattr(unhide, 'linux_binary', lambda *a, **k: NEW)
    calls = []

    def runner(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout='')

    unhide.run(runner=runner)
    assert calls == [[NEW, '-m', 'quick', 'reverse'], [unhide.UNHIDE_TCP]]


def test_run_is_available_with_only_the_new_binary(monkeypatch):
    present = {NEW, unhide.UNHIDE_TCP}
    monkeypatch.setattr(os.path, 'exists', lambda p: p in present)
    assert unhide.run(runner=lambda *a, **k: SimpleNamespace(stdout=''))['available'] is True


def test_the_scheduled_scan_runs_when_either_name_is_installed():
    assert unhide.installed(lambda name: '/usr/bin/unhide' if name == 'unhide' else None) is True
    assert unhide.installed(lambda name: '/usr/bin/unhide-linux' if name == 'unhide-linux' else None) is True
    assert unhide.installed(lambda name: None) is False


def test_full_check_accepts_the_new_binary_name():
    assert full_check.missing_tools(exists=lambda p: p in TOOLS | {NEW}) == []


def test_full_check_accepts_the_old_binary_name():
    assert full_check.missing_tools(exists=lambda p: p in TOOLS | {OLD}) == []


def test_full_check_still_reports_a_really_missing_unhide():
    assert full_check.missing_tools(exists=lambda p: p in TOOLS) == ['unhide']
    assert full_check.missing_tools(exists=lambda p: p in (TOOLS - {'/usr/sbin/unhide-tcp'}) | {NEW}) == ['unhide']


def test_full_check_names_every_missing_package():
    assert full_check.missing_tools(exists=lambda p: False) == ['dbus-tools', 'rkhunter', 'suricata-update', 'unhide']
