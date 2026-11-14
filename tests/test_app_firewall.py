"""Native App Control identity, ambiguity, expiry and deny precedence."""
import json
import socket
from types import SimpleNamespace as NS
import pytest
from satsuma import app_firewall as app

FLOW=(4,6,'192.0.2.2',4000,'198.51.100.2',443)
APP={'key':'a'*64,'pid':123,'created_at':1,'uid':1000,'executable':'/fixture/app','sha256':'b'*64}


def test_unknown_denied_and_pending_bounded():
    engine=app.Decisions(clock=lambda:1)
    for port in range(300):assert not engine.decide(APP,(*FLOW[:3],port,*FLOW[4:]))
    assert len(engine.pending)==256


def test_permanent_deny_overrides_temporary_allow(monkeypatch):
    engine=app.Decisions(clock=lambda:1)
    assert not engine.decide(APP,FLOW)
    request=next(iter(engine.pending));monkeypatch.setattr(app,'identity',lambda pid:APP)
    engine.answer(request,'allow','once');assert engine.decide(APP,FLOW)
    engine.rules[APP['key']]='deny';assert not engine.decide(APP,FLOW)


def test_temporary_grant_is_bound_to_flow_process_and_expiry(monkeypatch):
    now=[1];engine=app.Decisions(clock=lambda:now[0]);engine.decide(APP,FLOW)
    monkeypatch.setattr(app,'identity',lambda pid:APP)
    engine.answer(next(iter(engine.pending)),'allow','once')
    assert engine.decide(APP,FLOW)
    assert not engine.decide({**APP,'created_at':2},FLOW)
    assert not engine.decide(APP,(*FLOW[:-1],80))
    now[0]=302;assert not engine.decide(APP,FLOW)


def test_replaced_process_cannot_use_old_request(monkeypatch):
    engine=app.Decisions(clock=lambda:1);engine.decide(APP,FLOW)
    monkeypatch.setattr(app,'identity',lambda pid:{**APP,'created_at':2})
    with pytest.raises(ValueError,match='changed'):engine.answer(next(iter(engine.pending)),'allow','always')


def test_ambiguous_socket_owners_are_denied(monkeypatch):
    conn=lambda pid:NS(family=socket.AF_INET,type=socket.SOCK_STREAM,pid=pid,
        laddr=NS(ip=FLOW[2],port=FLOW[3]),raddr=NS(ip=FLOW[4],port=FLOW[5]))
    monkeypatch.setattr(app,'identity',lambda pid:APP)
    assert app.resolve(FLOW,[conn(1)])==APP
    with pytest.raises(ValueError,match='ambiguous'):app.resolve(FLOW,[conn(1),conn(2)])


@pytest.mark.parametrize('packet',[b'',b'\x45',b'\x60'+bytes(39),b'\x45'+bytes(19)])
def test_malformed_or_unsupported_packets_never_receive_identity(packet):
    with pytest.raises(ValueError):app.parse_packet(packet)


def test_queue_is_owned_and_has_no_bypass_or_global_flush():
    script=app.nft_script(True,True)
    assert 'queue num 201' in script and 'bypass' not in script
    assert 'flush ruleset' not in script and 'satsuma_core' not in script
    assert app.nft_script(False,False)==''


def test_disabled_or_active_report_expires(monkeypatch):
    monkeypatch.setattr(app,'policy',lambda:{'rules':{}})
    monkeypatch.setattr(app,'read_record',lambda name,default:{'status':'ACTIVE','updated_at':0} if name=='status.json' else {})
    assert app.status()['status']=='STALE'


def test_trusted_dependency_requires_exact_service_uid_and_rpm_hash(monkeypatch):
    app._RPM_DIGESTS.clear()
    binary='/usr/bin/python3'
    from pathlib import Path
    binary=str(Path(binary).resolve())
    process={**APP,'uid':0,'executable':binary,'cgroup':'/system.slice/satsuma-core.service'}
    runner=lambda *a,**k:NS(returncode=0,stdout=binary+'\t'+process['sha256']+'\n')
    assert app.trusted_dependency(process,runner)
    for changed in ({'uid':1000},{'cgroup':'/user.slice/desktop'},{'cgroup':'/system.slice/satsuma-core.service/child'},{'sha256':'0'*64}):
        assert not app.trusted_dependency({**process,**changed},runner)
    app._RPM_DIGESTS.clear()
