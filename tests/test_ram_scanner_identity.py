"""The RAM scanner trusts only the private clamd of satsuma-ram-clamd.service.

A process of the same clamscan user (Fedora's system clamd parses every
downloaded file) could replace the socket and answer "OK" for every chunk.
The peer must also sit in the unit's cgroup. A clamd copy started from a user
session is scanned; only a clamd system service is left out.

RAM tarayıcısı yalnızca satsuma-ram-clamd.service'in özel clamd'sine güvenir.
Aynı clamscan kullanıcısının süreci soketi değiştirip her parçaya "OK"
diyebilirdi; karşı taraf birimin cgroup'unda da olmalı. Kullanıcı
oturumundan başlatılan clamd kopyası taranır.
"""
import os
import pwd
import socket
import tempfile
import threading
import time
from pathlib import Path

import pytest

from satsuma.ram import clamd as rc
from satsuma.ram import coordinator


def fake_proc(tmp_path, pid, cgroup):
    root = tmp_path / 'proc'
    (root / str(pid)).mkdir(parents=True)
    (root / str(pid) / 'cgroup').write_text(cgroup + '\n')
    return root


def serve_ok(path, ready):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        os.chmod(path, 0o660)
        listener.listen(1)
        listener.settimeout(5)
        ready.set()
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        with connection:
            connection.settimeout(5)
            data = b''
            while not data.endswith(b'\0\0\0\0'):
                part = connection.recv(65536)
                if not part:
                    return
                data += part
            connection.sendall(b'stream: OK\0')  # an impostor says "clean"


@pytest.fixture
def impostor():
    if os.geteuid() != 0 or not Path('/run').is_dir():
        pytest.skip('needs root and /run: the socket checks demand a root-owned path')
    directory = Path(tempfile.mkdtemp(prefix='satsuma-ram-id-', dir='/run'))
    directory.chmod(0o750)
    path = directory / 'clamd.sock'
    ready = threading.Event()
    thread = threading.Thread(target=serve_ok, args=(path, ready), daemon=True)
    thread.start()
    assert ready.wait(5)
    yield path
    thread.join(timeout=6)
    path.unlink(missing_ok=True)
    directory.rmdir()


def client(path, proc_root):
    return rc.Clamd(path, account=pwd.getpwuid(0).pw_name, client_group='root', proc_root=proc_root)


def test_a_same_user_peer_outside_the_unit_is_refused(impostor, tmp_path):
    root = fake_proc(tmp_path, os.getpid(), '0::/system.slice/clamd@scan.service')
    with pytest.raises(PermissionError, match='untrusted_scanner_unit'):
        client(impostor, root).scan(b'fixture', time.monotonic() + 3)


def test_the_peer_in_the_ram_clamd_unit_is_accepted(impostor, tmp_path):
    root = fake_proc(tmp_path, os.getpid(), '0::/system.slice/satsuma-ram-clamd.service')
    assert client(impostor, root).scan(b'fixture', time.monotonic() + 3) == {'status': 'NO_MATCH'}


def test_a_user_unit_with_the_same_name_is_not_the_service(tmp_path):
    root = fake_proc(tmp_path, 7, '0::/user.slice/user-1000.slice/user@1000.service/app.slice/satsuma-ram-clamd.service')
    assert rc.peer_unit(7, root) == ''


def test_the_default_client_demands_the_ram_clamd_unit():
    assert rc.Clamd().unit == 'satsuma-ram-clamd.service'


@pytest.fixture
def scanner_binary(tmp_path):
    binary = tmp_path / 'clamd'
    binary.write_bytes(b'\x7fELF')
    info = binary.stat()
    return binary, (info.st_dev, info.st_ino)


@pytest.mark.parametrize('cgroup, excluded', [
    ('0::/system.slice/satsuma-ram-clamd.service', 'satsuma-ram-clamd.service'),
    ('0::/system.slice/clamd@scan.service', 'clamd@scan.service'),
    ('0::/user.slice/user-1000.slice/session-2.scope', ''),
    ('0::/system.slice/attacker.service', ''),
])
def test_only_a_clamd_system_service_is_left_out_of_the_signature_scan(tmp_path, scanner_binary, cgroup, excluded):
    binary, inode = scanner_binary
    root = fake_proc(tmp_path, 42, cgroup)
    identity = (42, 1, str(binary), *inode)
    assert coordinator.scanner_unit(42, identity, root, binary) == excluded


def test_another_program_in_the_unit_is_scanned(tmp_path, scanner_binary):
    binary, _ = scanner_binary
    root = fake_proc(tmp_path, 42, '0::/system.slice/satsuma-ram-clamd.service')
    assert coordinator.scanner_unit(42, (42, 1, '/tmp/x', 1, 2), root, binary) == ''


UNITS = Path(__file__).resolve().parents[1] / 'systemd'


def test_the_ram_clamd_is_never_given_up_and_starts_at_boot():
    text = (UNITS / 'satsuma-ram-clamd.service').read_text()
    assert 'Restart=always' in text and 'StartLimitIntervalSec=0' in text
    assert 'StartLimitBurst' not in text
    assert text.rstrip().endswith('[Install]\nWantedBy=multi-user.target')


def test_the_temporary_scan_wants_the_ram_clamd_that_exists():
    text = (UNITS / 'satsuma-temporary-scan.service').read_text()
    assert 'Wants=satsuma-ram-clamd.service' in text and 'satsuma-memory-clamd' not in text


def test_the_kernel_guard_starts_a_stopped_ram_scanner_again():
    from satsuma import kernel_guard as kg
    assert {'satsuma-ram-clamd.service', 'satsuma-core.service'} <= set(kg.REQUIRED_RUNNING)
    states = {u: {'load': 'loaded', 'active': 'active', 'file': 'enabled'} for u in kg.NEVER_RUN}
    states.update({u: {'load': 'loaded', 'active': 'active', 'file': 'enabled'} for u in kg.REQUIRED_RUNNING})
    for unit in kg.NEVER_RUN:
        states[unit] = {'load': 'not-found', 'active': 'inactive', 'file': ''}
    states['satsuma-ram-clamd.service']['active'] = 'inactive'
    assert kg.unit_drift(states) == [{'unit': 'satsuma-ram-clamd.service', 'want': 'running',
                                      'active': 'inactive', 'file': 'enabled'}]
    # Never while rpm or dnf runs: an upgrade stops it on purpose.
    assert kg.unit_drift(states, package_manager_running=True) == []
