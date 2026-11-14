"""Unit tests use harmless fixtures; they never move host files."""
from satsuma.onaccess_events import AdmissionGate, candidate_from_trusted_journal_fields, process_record


class Store:
    def __init__(self): self.events = []
    def add(self, key, item): self.events.append((key, item))


def record(path, **changes):
    value = {'_SYSTEMD_UNIT': 'satsuma-clamonacc.service', '_EXE': '/usr/bin/clamonacc',
             '_UID': '0', 'MESSAGE': f'Clamonacc: {path}: Fixture.Test FOUND'}
    value.update(changes)
    return value


def test_rejects_untrusted_fields(tmp_path):
    file = tmp_path/'file'; file.write_text('safe')
    for field, replacement in (('_SYSTEMD_UNIT','other.service'),('_EXE','/bin/sh'),('_UID','1000')):
        assert candidate_from_trusted_journal_fields(record(file, **{field:replacement})) is None


def test_rejects_unknown_format_and_traversal():
    assert candidate_from_trusted_journal_fields(record('/home/me/a', MESSAGE='FOUND /home/me/a')) is None
    assert candidate_from_trusted_journal_fields(record('/home/me/../etc/passwd')) is None
    assert candidate_from_trusted_journal_fields(record('/home/a\n/b')) is None


def test_new_event_is_rescanned_before_quarantine(tmp_path):
    target=tmp_path/'sample'; target.write_bytes(b'fixture')
    store=Store(); moves=[]; gate=AdmissionGate()
    def move(data, audit):
        moves.append(data); return {'status':'quarantined'}
    result=process_record(record(target),store,gate,scanner=lambda fd:{'status':'SIGNATURE_MATCH','signature':'Fixture.Test'},mover=move, protected=(str(tmp_path),))
    assert result['status']=='verified_match' and len(moves)==1
    assert process_record(record(target),store,gate,scanner=lambda fd: (_ for _ in ()).throw(AssertionError('re-scanned')),mover=move, protected=(str(tmp_path),))['status']=='deferred'


def test_clean_rescan_does_not_move(tmp_path):
    target=tmp_path/'clean';target.write_text('ok')
    result=process_record(record(target),Store(),AdmissionGate(),scanner=lambda fd:{'status':'NO_MATCH_IN_FILE'},mover=lambda *x: (_ for _ in ()).throw(AssertionError('moved')),protected=(str(tmp_path),))
    assert result['status']=='no_match'


def test_rate_limit():
    now=[0.0]
    gate=AdmissionGate(max_seen=2,max_per_minute=2,clock=lambda:now[0])
    assert gate.accept('/home/a')
    assert not gate.accept('/home/a')
    assert gate.accept('/home/b')
    assert not gate.accept('/home/c')
    now[0]=61
    assert gate.accept('/home/c')


def test_invalid_cannot_invoke_scanner(tmp_path):
    target=tmp_path/'sample';target.write_text('safe')
    result=process_record(record(target,_UID='9'),Store(),AdmissionGate(),scanner=lambda fd: (_ for _ in ()).throw(AssertionError('scanned')))
    assert result['status']=='ignored'
