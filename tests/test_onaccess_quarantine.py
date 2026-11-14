"""On-access quarantine handoff; tests never move host files."""
import os
from pathlib import Path
from unittest.mock import patch

from satsuma.onaccess_quarantine import verify_and_quarantine


class MemoryStore:
    def __init__(self): self.events = []
    def add(self, kind, record): self.events.append((kind, record))


def test_confirmed_rescan_uses_existing_quarantine(tmp_path):
    target = tmp_path / 'sample'
    target.write_bytes(b'harmless test content')
    calls = []
    def mover(data, audit):
        calls.append(data)
        audit({'status': 'REQUESTED'})
        return {'status': 'quarantined'}
    store = MemoryStore()
    outcome = verify_and_quarantine(target, store,
        scanner=lambda fd: {'status': 'SIGNATURE_MATCH', 'signature': 'Fixture.NotMalware'},
        mover=mover, protected=(str(tmp_path),))
    assert outcome['status'] == 'verified_match'
    assert len(calls) == 1 and calls[0]['sha256']
    assert target.exists()  # fake mover keeps fixture intact
    assert any(k == 'onaccess_rescan' for k, _ in store.events)


def test_clean_does_not_quarantine(tmp_path):
    target = tmp_path / 'clean'
    target.write_bytes(b'clean')
    outcome = verify_and_quarantine(target, MemoryStore(),
        scanner=lambda fd: {'status': 'NO_MATCH_IN_FILE'},
        mover=lambda *args: (_ for _ in ()).throw(AssertionError('moved')),
        protected=(str(tmp_path),))
    assert outcome['status'] == 'no_match'


def test_scan_error_does_not_quarantine(tmp_path):
    target = tmp_path / 'sample'
    target.write_bytes(b'harmless')
    def scanner(fd): raise ConnectionError('socket unavailable')
    outcome = verify_and_quarantine(target, MemoryStore(), scanner=scanner,
        mover=lambda *args: (_ for _ in ()).throw(AssertionError('moved')),
        protected=(str(tmp_path),))
    assert outcome['status'] == 'deferred'


def test_path_replaced_during_scan_does_not_quarantine(tmp_path):
    target = tmp_path / 'sample'
    target.write_bytes(b'old')
    def scanner(fd):
        target.rename(tmp_path / 'old')
        target.write_bytes(b'new')
        return {'status': 'SIGNATURE_MATCH', 'signature': 'Fixture.NotMalware'}
    outcome = verify_and_quarantine(target, MemoryStore(), scanner=scanner,
        mover=lambda *args: (_ for _ in ()).throw(AssertionError('moved')),
        protected=(str(tmp_path),))
    assert outcome['status'] == 'deferred'
    assert target.read_bytes() == b'new'


def test_symlink_rejected(tmp_path):
    target = tmp_path / 'sample'
    target.write_bytes(b'harmless')
    link = tmp_path / 'link'
    link.symlink_to(target)
    outcome = verify_and_quarantine(link, MemoryStore(),
        scanner=lambda fd: {'status': 'SIGNATURE_MATCH', 'signature': 'Fixture.NotMalware'},
        protected=(str(tmp_path),))
    assert outcome['status'] == 'deferred'


def test_outside_protected_scope_rejected(tmp_path):
    target = tmp_path / 'sample'
    target.write_bytes(b'harmless')
    outcome = verify_and_quarantine(target, MemoryStore(), protected=('/home',))
    assert outcome['status'] == 'rejected'


def test_unknown_verdict_not_quarantined(tmp_path):
    target = tmp_path / 'sample'
    target.write_bytes(b'harmless')
    outcome = verify_and_quarantine(target, MemoryStore(),
        scanner=lambda fd: {'status': 'ERROR'},
        mover=lambda *args: (_ for _ in ()).throw(AssertionError('moved')),
        protected=(str(tmp_path),))
    assert outcome['status'] == 'deferred'
