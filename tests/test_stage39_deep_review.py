"""Test-only deep findings must never execute an OS action, even on approval."""
import pytest
from satsuma.store import Store
from satsuma.deep_rule_review import enqueue, pending, decide, cancel_all
from satsuma.operator_service import weakens

@pytest.fixture
def store(tmp_path):
    db=Store(str(tmp_path), test=True)
    yield db
    db.close()

def evidence():
    return {'finding_id':'f-1','rule_id':'SATSUMA-C2-004','severity':'medium',
            'evidence_type':'deep_engine_observation','authorization':'none',
            'test_rule':True,'review_required':True,
            'cmd':'do not leak cmd', 'password':'not a real password', 'pid':22}

def test_mode_disabled_does_not_queue(store):
    assert enqueue(store,evidence())['status']=='test_mode_disabled'
    assert pending(store)==[]

def test_approval_labels_only_and_single_use(store):
    store.set('interactive_process_test_mode',True)
    r=enqueue(store,evidence(),now=1000)
    assert r['status']=='pending'
    req=pending(store,now=1001)[0]
    assert req['kind']=='deep_rule_review'
    assert 'cmd' not in req and 'pid' not in req and 'password' not in req
    result=decide(store,r['id'],'apply',1000,now=1002)
    assert result['status']=='operator_label_accepted'
    assert result['signal_sent'] is False and result['enforcement']=='none'
    with pytest.raises(ValueError): decide(store,r['id'],'apply',1000,now=1003)

def test_cancel_on_disable_prevents_replay(store):
    store.set('interactive_process_test_mode',True)
    r=enqueue(store,evidence(),now=1000)
    assert cancel_all(store)==1
    store.set('interactive_process_test_mode',False)
    store.set('interactive_process_test_mode',True)
    with pytest.raises(ValueError): decide(store,r['id'],'apply',1000,now=1001)

def test_invalid_evidence_rejected(store):
    store.set('interactive_process_test_mode',True)
    with pytest.raises(ValueError): enqueue(store,{**evidence(),'authorization':'kill'})
    with pytest.raises(ValueError): enqueue(store,{**evidence(),'test_rule':False})

def test_operator_decisions_require_fresh_password():
    assert weakens('deep_rule_review_decide',{}) is True
