"""Simulated end-to-end on-access event-to-quarantine handoff.

This suite does NOT claim Fedora fanotify, real clamd or journald validation.
"""
import json
from pathlib import Path
from satsuma.onaccess_listener import process_json_line
from satsuma.onaccess_events import AdmissionGate


class Store:
    def __init__(self):
        self.entries = []
    def add(self, kind, entry):
        self.entries.append((kind, entry))


def record(path, *, moment=100, unit='satsuma-clamonacc.service', signature='Fixture.Signature'):
    return json.dumps({'_SYSTEMD_UNIT': unit, '_EXE': '/usr/bin/clamonacc', '_UID': '0',
                       '__REALTIME_TIMESTAMP': str(moment * 1000000),
                       'MESSAGE': f'Clamonacc: {path}: {signature} FOUND'})


def test_simulated_finding_reaches_verified_quarantine_handoff(tmp_path):
    file = tmp_path / 'sample.bin'
    file.write_bytes(b'harmless fixture')
    store = Store()
    moved = []
    def mover(target, audit):
        moved.append(target)
        audit({'status': 'REQUESTED', 'quarantine_id': 'fixture'})
        return {'status': 'quarantined', 'quarantine_id': 'fixture'}
    status = process_json_line(record(file), store, AdmissionGate(), now=100,
                               protected=(str(tmp_path),),
                               scanner=lambda fd: {'status': 'SIGNATURE_MATCH', 'signature': 'Fixture.Signature'},
                               mover=mover)
    assert status['status'] == 'verified_match'
    assert status['quarantine']['status'] == 'quarantined'
    assert len(moved) == 1 and moved[0]['path'] == str(file)
    assert moved[0]['sha256']
    assert [kind for kind, _ in store.entries] == ['quarantine_actions', 'onaccess_rescan']
    assert file.exists(), 'Fake mover must not touch a real file'


def test_simulated_clean_and_untrusted_never_quarantine(tmp_path):
    file = tmp_path / 'safe.bin'
    file.write_bytes(b'safe content')
    moved = []
    def mover(*args):
        moved.append(args)
        raise AssertionError('unexpected quarantine')
    store=Store()
    gate=AdmissionGate()
    clean = process_json_line(record(file), store, gate, now=100, protected=(str(tmp_path),),
                              scanner=lambda fd: {'status': 'NO_MATCH_IN_FILE'}, mover=mover)
    forged = process_json_line(record(file, unit='untrusted.service'), store, AdmissionGate(),
                               now=100, protected=(str(tmp_path),),
                               scanner=lambda fd: {'status':'SIGNATURE_MATCH','signature':'fake'}, mover=mover)
    assert clean['status'] == 'no_match'
    assert forged['status'] == 'ignored'
    assert not moved and not store.entries


def test_simulated_changed_file_never_quarantined(tmp_path):
    file=tmp_path/'sample.bin'
    file.write_bytes(b'old')
    def scanner(fd):
        file.write_bytes(b'new file content')
        return {'status':'SIGNATURE_MATCH','signature':'Fixture.Signature'}
    result=process_json_line(record(file), Store(), AdmissionGate(), now=100,
                             protected=(str(tmp_path),), scanner=scanner,
                             mover=lambda *_: (_ for _ in ()).throw(AssertionError('moved')))
    assert result['status']=='deferred'
