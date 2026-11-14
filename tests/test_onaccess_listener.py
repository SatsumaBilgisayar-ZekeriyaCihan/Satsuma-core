import json
import time
from satsuma.onaccess_listener import fresh_journal_record, process_json_line, MAX_RECORD
from satsuma.onaccess_events import AdmissionGate

class Store:
    def __init__(self): self.entries=[]
    def add(self,key,value): self.entries.append((key,value))

def event(path, now=100):
    return {'_SYSTEMD_UNIT':'satsuma-clamonacc.service','_EXE':'/usr/bin/clamonacc',
            '_UID':'0','__REALTIME_TIMESTAMP':str(int(now*1e6)),
            'MESSAGE':f'Clamonacc: {path}: Fixture FOUND'}

def test_old_and_future_events_rejected(tmp_path):
    target=tmp_path/'file';target.write_text('safe')
    for when in (1,101):
        row=event(str(target),when)
        assert not fresh_journal_record(row,now=100)
        out=process_json_line(json.dumps(row), Store(), AdmissionGate(),now=100,
                              scanner=lambda fd: (_ for _ in ()).throw(AssertionError()))
        assert out['status']=='ignored'

def test_valid_event_must_rescan(tmp_path):
    target=tmp_path/'file';target.write_text('safe');store=Store()
    outcome=process_json_line(json.dumps(event(str(target))),store,AdmissionGate(),now=100,
                              scanner=lambda fd:{'status':'NO_MATCH_IN_FILE'},protected=(str(tmp_path),))
    assert outcome['status']=='no_match' and not store.entries

def test_bad_metadata_and_oversize():
    gate=AdmissionGate()
    for line in (b'not json',b'x'*(MAX_RECORD+1),json.dumps({'MESSAGE':'fake'})):
        assert process_json_line(line,Store(),gate,now=100)['status']=='ignored'

def test_retired_ram_clamd_not_shipped():
    from pathlib import Path
    root=Path(__file__).resolve().parents[1]
    assert not (root/'systemd/satsuma-ram-clamd.service').exists()
    assert not (root/'packaging/root/etc/clamd.d/satsuma-ram.conf').exists()
    assert '%config(noreplace) /etc/clamd.d/satsuma-ram.conf' not in (root/'packaging/satsuma-core.spec').read_text()
