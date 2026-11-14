import importlib.util
import io
from pathlib import Path
import sqlite3
import pytest

spec=importlib.util.spec_from_file_location('outcome_guard',Path(__file__).parents[1]/'integrations/satsuma_guard.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)


@pytest.mark.parametrize('event,reason,expected',[
    ('suricata_alert','signature','DETECTED'),
    ('block','confirmed_incoming','BLOCKED'),
    ('would_block','policy_observe','OBSERVE_ONLY'),
    ('ACTION_UNSUPPORTED','connection_direction_unverified','UNVERIFIED'),
    ('ACTION_UNSUPPORTED','outbound_or_connection_direction_unverified','UNVERIFIED'),
    ('ACTION_UNSUPPORTED','operator_paused','OBSERVE_ONLY'),
    ('ACTION_FAILED','nft_readback_failed','FAILED'),
])
def test_normalized_outcome_preserves_detection_id_and_does_not_claim_packet_drop(event,reason,expected):
    service=object.__new__(guard.Guard)
    service.db=sqlite3.connect(':memory:')
    service.db.execute('CREATE TABLE events(ts TEXT,event TEXT,body TEXT)')
    service.events=io.StringIO()
    records=[]
    class Store:
        def add(self,kind,record):records.append(record)
    service.core_store=Store()
    try:
        service.write(event,reason=reason,detection_id='fixture')
        record=records[-1]
        assert record['response_outcome']==expected
        assert record['detection_id']=='fixture'
        assert record['traffic_drop_verified'] is False
        assert (record['evidence_scope']=='nft_set_and_rule_readback')==(event=='block')
    finally:service.db.close()
