"""2.2.11: ClamAV falls back to clamscan, reports its error and quarantines.

2.2.11: ClamAV clamscan'e düşer, hatasını bildirir ve karantinaya alır.
"""
import errno
import os
from types import SimpleNamespace as NS

import pytest

from satsuma import scan_quarantine as q, security_scan
from satsuma.host_store import HostStore
from satsuma.policy import FIXED_SCAN_POLICY


@pytest.fixture
def private_storage(tmp_path, monkeypatch):
    monkeypatch.setattr(q, 'ALLOWED_ROOTS', (tmp_path,))
    monkeypatch.setattr(q, 'QUARANTINE', tmp_path / 'quarantine')
    monkeypatch.setattr('satsuma.protected_storage.open_directory',
                        lambda p: os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    return tmp_path


def test_cross_filesystem_quarantine_copies_verifies_then_removes(private_storage, monkeypatch):
    source = private_storage / 'dropper.bin'
    source.write_bytes(b'harmless cross-device fixture')
    target = q.inspect_target(source)
    def exdev(*args, **kwargs):
        raise OSError(errno.EXDEV, 'Invalid cross-device link')
    monkeypatch.setattr(q.os, 'rename', exdev)
    result = q.quarantine_target(target, lambda r: None, directory=private_storage / 'quarantine')
    assert result['status'] == 'quarantined' and result['method'] == 'verified_copy'
    assert not source.exists()
    moved = private_storage / 'quarantine' / result['quarantine_id']
    assert moved.read_bytes() == b'harmless cross-device fixture' and moved.stat().st_mode & 0o777 == 0o600


def test_scanner_error_line_is_kept(tmp_path):
    def clamd_down(command, stdout, **kw):
        stdout.write(b'ERROR: Could not connect to clamd on LocalSocket /run/clamd.scan/clamd.sock\n')
        return NS(returncode=2)
    result = security_scan._result('clamav', ['/usr/bin/clamdscan'], runner=clamd_down, archive=tmp_path / 'out')
    assert result['status'] == 'ERROR' and 'Could not connect to clamd' in result['error']


def test_clamd_down_falls_back_to_clamscan_and_quarantines(private_storage):
    infected = private_storage / 'eicar-like.txt'
    infected.write_bytes(b'harmless detection fixture')
    host = HostStore(private_storage / 'host', test=True)
    calls = []
    def runner(command, stdout, **kw):
        calls.append(command[0])
        if command[0].endswith('clamdscan'):
            stdout.write(b'ERROR: Could not connect to clamd\n');return NS(returncode=2)
        if command[0].endswith('clamscan'):
            stdout.write((str(infected) + ': Fixture.Signature FOUND\nInfected files: 1\n').encode());return NS(returncode=1)
        return NS(returncode=0)
    which = lambda name: '/usr/bin/' + name
    try:
        rows = security_scan.run_once(store=host, runner=runner, which=which,
                                      scan_policy={**FIXED_SCAN_POLICY, 'order': ['clamav']},
                                      binary_audit=lambda *a, **k: {}, ssh_audit=lambda *a, **k: {},
                                      python_audit=lambda *a, **k: {}, media_audit=lambda *a, **k: {},
                                      systemd_audit=lambda *a, **k: {}, boot_correlator=lambda *a, **k: {},
                                      mitm_watch=lambda *a, **k: {})
        assert calls == ['/usr/bin/clamdscan', '/usr/bin/clamscan']
        row = rows[0]
        assert row['fallback_from'] == 'clamdscan' and 'Could not connect' in row['fallback_reason']
        assert row['status'] == 'FINDINGS' and row['quarantine'][0]['status'] == 'quarantined'
        assert not infected.exists()
        health = host.get('security_scan_health')
        assert health['quarantined_count'] == 1 and health['finding_count'] == 1
        finding = host.db.execute("SELECT body FROM findings").fetchone()[0]
        assert '"status": "QUARANTINED"' in finding
    finally:
        host.close()


def test_system_directories_are_reported_not_quarantined(private_storage, monkeypatch):
    host = HostStore(private_storage / 'host', test=True)
    try:
        result = security_scan.quarantine_files(host, [{'path': '/usr/bin/ls', 'sha256': 'x' * 64}])
        assert result[0]['status'] == 'not_quarantined'
    finally:
        host.close()


def test_policy_and_full_protection_turn_automatic_quarantine_on():
    from satsuma.full_protection import apply
    from satsuma.policy import from_legacy, validate
    from satsuma.config import DEFAULT
    assert FIXED_SCAN_POLICY['automatic_quarantine'] is True
    policy = from_legacy(DEFAULT)
    policy['scheduled_scans']['automatic_quarantine'] = False
    validate(policy)  # a stored "off" is still a valid document …
    assert apply({'scheduled_scans': dict(policy['scheduled_scans'])})['scheduled_scans']['automatic_quarantine'] is True
    assert set(security_scan.SCAN_TARGETS) >= {'/tmp', '/var/tmp', '/dev/shm', '/root', '/usr/bin', '/usr/sbin'}


def test_both_scan_services_may_quarantine_and_see_dev_shm():
    from pathlib import Path
    for unit in ('satsuma-core-security-scan.service', 'satsuma-core-security-scan-now.service'):
        text = Path('systemd', unit).read_text()
        assert 'ProtectHome=no' in text and 'PrivateDevices=false' in text, unit
        assert '-/tmp' in text and '-/dev/shm' in text and 'CAP_DAC_OVERRIDE' in text, unit


def test_minute_timer_never_hits_a_start_limit():
    from pathlib import Path
    unit = Path('systemd/satsuma-core-security-scan.service').read_text()
    timer = Path('systemd/satsuma-core-security-scan.timer').read_text()
    assert 'OnUnitActiveSec=1min' in timer
    assert 'StartLimitIntervalSec=0' in unit and 'StartLimitBurst' not in unit
