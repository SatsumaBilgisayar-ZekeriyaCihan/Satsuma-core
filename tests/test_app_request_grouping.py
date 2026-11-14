import pytest
from satsuma import app_firewall as app

FLOW=(4,6,'192.0.2.2',4000,'198.51.100.2',443)
APP={'key':'a'*64,'application_key':'b'*64,'pid':123,'created_at':1,
     'uid':1000,'executable':'/fixture/brave','sha256':'c'*64,'cgroup':'/one'}


def test_browser_hundred_connections_are_one_visible_request_and_one_explicit_grant(monkeypatch):
    records=[]
    monkeypatch.setattr(app.RootDataStore,'replace',lambda self,value:records.append(value))
    monkeypatch.setattr(app,'trusted_dependency',lambda proc:False)
    engine=app.Decisions(clock=lambda:1)
    children=[]
    for n in range(100):
        child={**APP,'pid':123+n,'key':f'{n:064x}','cgroup':f'/child{n}'}
        children.append(child)
        assert not engine.decide(child,(*FLOW[:3],4000+n,*FLOW[4:]))
    engine.publish()
    assert len(records[-1]['pending'])==1
    assert records[-1]['pending'][0]['connection_count']==100
    request=records[-1]['pending'][0]['id']
    # The child shown originally has exited; a verified sibling can represent
    # only the explicitly application-wide decision.
    def identify(pid):
        if pid==123:raise ProcessLookupError('exited')
        return children[pid-123]
    monkeypatch.setattr(app,'identity',identify)
    monkeypatch.setattr(app,'policy',lambda:{'rules':{},'application_rules':{}})
    engine.answer(request,'allow','application')
    assert not engine.pending
    for child in children:assert engine.decide(child,FLOW)
    assert not engine.decide({**APP,'application_key':'d'*64},FLOW)
    engine.application_rules[APP['application_key']]='deny'
    assert not engine.decide(children[-1],FLOW)


def test_dead_child_cannot_transfer_connection_only_permission_to_sibling(monkeypatch):
    monkeypatch.setattr(app,'trusted_dependency',lambda proc:False)
    engine=app.Decisions(clock=lambda:1)
    engine.decide(APP,FLOW)
    request=next(iter(engine.pending))
    engine.decide({**APP,'pid':124,'key':'d'*64},FLOW)
    def identify(pid):
        if pid==123:raise ProcessLookupError('exited')
        return {**APP,'pid':124,'key':'d'*64}
    monkeypatch.setattr(app,'identity',identify)
    with pytest.raises(ValueError,match='changed'):engine.answer(request,'allow','once')
    assert not engine.once
