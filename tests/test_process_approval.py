import time
import pytest
from satsuma.process_approval import enqueue, decide, pending, public_pending

class Store:
    def __init__(self):
        self.values = {}
        self.logs = []
    def get(self, key, default=None):
        return self.values.get(key, default)
    def set(self, key, value):
        self.values[key] = value
    def add(self, kind, data):
        self.logs.append((kind, data))

def finding(pid=123, start=1234):
    return {'finding_id': 'detection-1', 'rule_id': 'RULE-1',
            'team': 'smart_rules', 'event': {'pid': pid, 'starttime': start, 'timestamp': time.time()}}

def test_pending_is_non_destructive_and_strips_private_evidence():
    s = Store()
    req = enqueue(s, finding())
    assert req['status'] == 'approval_pending'
    assert req['signal_sent'] is False
    rows = public_pending(s)
    assert len(rows) == 1 and 'finding' not in rows[0]
    assert rows[0]['pid'] == 123

def test_reject_never_calls_handler():
    s=Store()
    req=enqueue(s, finding())
    result=decide(s, req['request_id'], 'reject', 1000,
                  process_handler=lambda *_: pytest.fail('executor must not run'))
    assert result['status'] == 'rejected'
    assert not result['signal_sent']
    assert pending(s) == []

def test_apply_passes_original_evidence_once():
    s=Store()
    request=enqueue(s, finding())
    seen=[]
    def executor(source, request_id):
        seen.append((source, request_id))
        return {'status':'terminated','signal_sent':True,'exit_verified':True}
    result=decide(s, request['request_id'], 'apply', 1000, process_handler=executor)
    assert result['status'] == 'executed'
    assert seen[0][0]['event']['starttime'] == 1234
    assert seen[0][1] == request['request_id']
    with pytest.raises(ValueError):
        decide(s,request['request_id'],'apply',1000,process_handler=executor)
    assert len(seen) == 1

def test_expiry_refuses_execution():
    s=Store()
    request=enqueue(s, finding(), now=1000)
    with pytest.raises(ValueError, match='expired'):
        decide(s,request['request_id'],'apply',1000,
               process_handler=lambda *_: pytest.fail('expired must not execute'),now=2000)

def test_missing_identity_and_queue_bound():
    s=Store()
    assert enqueue(s, {'event': {'pid':42}})['status'] == 'approval_unavailable'
    for n in range(64):
        assert enqueue(s,finding(pid=n+10))['status'] == 'approval_pending'
    assert enqueue(s, finding(pid=900))['status'] == 'approval_queue_full'

def test_distinct_simultaneous_requests_independent():
    s=Store()
    a=enqueue(s, finding(pid=100))['request_id']
    b=enqueue(s, finding(pid=200))['request_id']
    decide(s,a,'reject',1000)
    called=[]
    decide(s,b,'apply',1000,process_handler=lambda f,r:(called.append(f['event']['pid']) or {'signal_sent':False,'status':'policy_denied'}))
    assert called==[200]
    assert pending(s)==[]

def test_invalid_decisions_rejected():
    s=Store()
    request=enqueue(s,finding())
    with pytest.raises(ValueError):
        decide(s,request['request_id'],'unknown',1000)

def test_sqlite_two_connections_no_lost_pending_or_double_apply(tmp_path):
    from satsuma.store import Store as DatabaseStore
    first = DatabaseStore(tmp_path, test=True)
    second = DatabaseStore(tmp_path, test=True)
    try:
        a = enqueue(first, finding(pid=201))['request_id']
        b = enqueue(second, finding(pid=202))['request_id']
        assert {r['id'] for r in public_pending(first)} == {a,b}
        assert {r['id'] for r in public_pending(second)} == {a,b}
        seen = []
        decide(second, a, 'apply', 1000, process_handler=lambda f,r:(seen.append(f['event']['pid']) or {'status':'blocked','signal_sent':False}))
        with pytest.raises(ValueError, match='not pending'):
            decide(first, a, 'apply', 1000, process_handler=lambda *_:pytest.fail('double execute'))
        decide(first,b,'reject',1000)
        assert seen == [201]
        assert public_pending(second) == []
    finally:
        first.close()
        second.close()
