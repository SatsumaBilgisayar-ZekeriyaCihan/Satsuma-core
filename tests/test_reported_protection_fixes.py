"""Reported 20.1.4 regressions. No host firewall or remote API changes."""
import json
import time
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

from satsuma import otx
from satsuma.auto_action import AutoActionEngine, network_target
from satsuma.network_discovery import discover, WorkerNetworkDiscovery
from satsuma.response import ResponseWorker
from satsuma.store import Store
from satsuma.subnet_protection import evaluate
from network_fixture import table_json


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path/'data', test=True)
    yield value
    value.close()


def firewall(commands):
    def run(args, **kwargs):
        commands.append(args)
        return {'returncode': 0, 'stdout': table_json() if '-j' in args else '', 'stderr': ''}
    return run


@pytest.mark.parametrize('authorization', [
    {'subnet_limit_authorized': True}, {'otx_limit_authorized': True},
    {'auto_action_network_enabled': True, 'destructive_response_enabled': True,
     'destructive_allowed_actions': ['network_isolate']},
])
def test_operator_policies_reach_both_direction_drop_sets(store, monkeypatch, authorization):
    monkeypatch.setattr('satsuma.incoming_response.block', lambda *a: pytest.fail('incoming-only path'))
    commands=[]
    worker=ResponseWorker(store, {'response_enabled':True, **authorization}, runner=firewall(commands))
    result=worker.block_ip('45.33.32.10', 'authorized peer policy')
    assert result['status']=='set_membership_confirmed'
    assert result['scope']=='bidirectional_peer' and not result['traffic_drop_verified']
    assert any(cmd[1:3]==['add','element'] for cmd in commands)
    assert any(cmd[1:3]==['get','element'] for cmd in commands)
    assert '45.33.32.10' in store.get('persistent_blocks')


def test_generic_automatic_caller_keeps_direction_gate(store, monkeypatch):
    monkeypatch.setattr('satsuma.incoming_response.block', lambda *a: {'status':'outbound_or_direction_unverified'})
    worker=ResponseWorker(store, {'response_enabled':True}, runner=lambda *a:pytest.fail('not authorized'))
    assert worker.block_ip('45.33.32.10','unverified')['status']=='outbound_or_direction_unverified'


def test_subnet_sequential_peers_accumulate_and_expire(store):
    calls=[]
    fake=NS(block_ip=lambda ip,reason:calls.append(ip) or {'status':'set_membership_confirmed'})
    for n in range(1,10):
        assert evaluate(store,{f'45.33.32.{n}':1},{},fake,now=100+n,
                        boot_provider=lambda:{'response_unlocked':True})==[]
    results=evaluate(store,{'45.33.32.10':1},{},fake,now=110,
                     boot_provider=lambda:{'response_unlocked':True})
    assert len(results)==10 and len(set(calls))==10
    assert evaluate(store,{'45.33.32.11':1},{},fake,now=500,
                    boot_provider=lambda:{'response_unlocked':True})==[]


def test_k3_retired_any_pulse_is_judged_by_the_threshold_and_tls():
    # Audit K3: any_pulse used to block on one pulse; it is now threshold.
    cfg={'require_tls':True,'pulse_threshold':11,'recent_pulse_days':14,'match_mode':'any_pulse'}
    item={'tls':{'verified':True},'pulse_count':1,'latest_pulse_age_days':None}
    assert otx._should_block(item,cfg)==(False,'below_pulse_threshold')
    strong={**item,'pulse_count':11,'latest_pulse_age_days':1}
    assert otx._should_block(strong,cfg)[0]
    assert not otx._should_block({**strong,'tls':{}},cfg)[0]
    assert otx._should_block(strong,{**cfg,'match_mode':'threshold'})[0]


def test_otx_eligible_outgoing_peer_reaches_firewall(store, monkeypatch):
    commands=[]
    from satsuma import early_guard
    monkeypatch.setattr(early_guard,'read_verdict',lambda:{'response_unlocked':True})
    monkeypatch.setattr(otx,'load_config',lambda:{'api_key':'fixture','cache_ttl_seconds':3600,'max_queries_per_cycle':12})
    monkeypatch.setattr(otx,'load_with_policy',lambda:({'otx_enabled':True,'otx_blocker_mode':True},None,None))
    monkeypatch.setattr(otx,'run_domains',lambda *a:None)
    monkeypatch.setattr(otx,'request_ipv4',lambda *a:({}, {'verified':True,'version':'fixture','cipher':'fixture','host':otx.HOST}))
    monkeypatch.setattr(otx,'summarize',lambda ip,data,tls:{'ip':ip,'tls':tls,'pulse_count':11,'latest_pulse_age_days':1,'satsuma_otx_risk_score':11,'reason':'fixture'})
    real=ResponseWorker
    monkeypatch.setattr(otx,'ResponseWorker',lambda s,c:real(s,c,runner=firewall(commands)))
    monkeypatch.setattr('satsuma.incoming_response.block',lambda *a:pytest.fail('outgoing peer rejected'))
    store.set('operator_otx_policy',{'enabled':True,'blocker_mode':True,'match_mode':'any_pulse'})
    rows=otx._run_once(store=store,candidates=['45.33.32.10'])
    assert rows[0]['decision']=='block'
    assert store.get('otx_cache')['45.33.32.10']['match_mode']=='threshold'


@pytest.mark.parametrize('source',['dns_policy','expected_dns_servers'])
def test_otx_reputation_does_not_auto_block_selected_dns_resolver(store,monkeypatch,source):
    resolver='208.67.222.222'
    core={'otx_enabled':True,'otx_blocker_mode':True}
    if source=='dns_policy':store.set('dns_policy',{'upstream':resolver})
    else:core['expected_dns_servers']=[resolver]
    monkeypatch.setattr(otx,'load_config',lambda:{'api_key':'fixture','cache_ttl_seconds':3600,'max_queries_per_cycle':12})
    monkeypatch.setattr(otx,'load_with_policy',lambda:(core,None,None))
    monkeypatch.setattr(otx,'run_domains',lambda *a:None)
    monkeypatch.setattr(otx,'request_ipv4',lambda *a:({}, {'verified':True,'version':'fixture','cipher':'fixture','host':otx.HOST}))
    monkeypatch.setattr(otx,'summarize',lambda ip,data,tls:{'ip':ip,'tls':tls,'pulse_count':100,'latest_pulse_age_days':0,
        'satsuma_otx_risk_score':100,'reason':'fixture'})
    store.set('operator_otx_policy',{'enabled':True,'blocker_mode':True,'match_mode':'any_pulse'})
    response=NS(block_ip=lambda *a,**k:pytest.fail('resolver must not be blocked by reputation alone'))
    rows=otx._run_once(store=store,response=response,candidates=[resolver])
    assert rows[0]['decision']=='review' and rows[0]['block_reason']=='protected_dns_resolver'


def test_confirmed_multisensor_outgoing_finding_is_applied(store, monkeypatch):
    now=time.time();commands=[]
    store.set('network_discovery',{'updated_at':now,'interfaces':[{'addresses':['192.168.1.5/24']}]})
    config={'response_enabled':True,'destructive_response_enabled':True,
            'destructive_allowed_actions':['network_isolate'],'auto_action_network_enabled':True}
    finding={'finding_id':'confirmed-outgoing','classification':'confirmed','timestamp':now,
             'sources':['suricata','audit'], 'event':{'timestamp':now,'src_ip':'192.168.1.5','dest_ip':'45.33.32.10'}}
    monkeypatch.setattr('satsuma.incoming_response.block',lambda *a:pytest.fail('outgoing target rejected'))
    response=ResponseWorker(store,config,runner=firewall(commands))
    result=AutoActionEngine(store,config,response).process(finding)
    assert result['status']=='set_membership_confirmed'
    assert result['target']=='45.33.32.10'
    # 2.2.9 full protection: a single suspicious signal is enough.
    finding={**finding,'finding_id':'single-signal','classification':'suspicious','sources':['suricata'],
             'event':{'timestamp':now,'src_ip':'192.168.1.5','dest_ip':'45.33.32.11'}}
    assert AutoActionEngine(store,config,response).process(finding)['status']=='set_membership_confirmed'


def test_target_resolution_rejects_stale_or_ambiguous_inventory(store):
    now=time.time()
    store.set('network_discovery',{'updated_at':now-100,'interfaces':[{'addresses':['192.168.1.5/24']}]})
    finding={'event':{'src_ip':'192.168.1.5','dest_ip':'45.33.32.10'}}
    assert network_target(store,finding,now) is None
    store.set('network_discovery',{'updated_at':now,'interfaces':[{'addresses':['192.168.1.5/24']}]})
    finding['events']=[{'network':{'src_ip':'192.168.1.5','dst_ip':'1.1.1.1'}}]
    assert network_target(store,finding,now) is None


def test_passive_discovery_records_interfaces_routes_and_untrusted_neighbors():
    def read(args):
        assert args[:2]==['/usr/sbin/ip','-j']
        if args[2]=='address':return json.dumps([{'ifname':'eth0','operstate':'UP','addr_info':[{'local':'192.168.1.5','prefixlen':24}]}])
        if args[2]=='neigh':return json.dumps([{'dst':'192.168.1.1','dev':'eth0','lladdr':'02:00:00:00:00:01','state':['STALE']}])
        return json.dumps([{'dst':'default','dev':'eth0','gateway':'192.168.1.1'}])
    result=discover(read)
    assert result['status']=='RUNNING'
    assert result['interfaces'][0]['addresses']==['192.168.1.5/24']
    assert result['neighbors'][0]['trusted'] is False
    assert result['gateways'] and result['mode']=='passive'
    assert discover(lambda args:'{}')['status']=='DEGRADED'


def test_discovery_worker_persists_and_caches(store, monkeypatch):
    calls=[]
    def read():
        calls.append(1)
        return {'status':'RUNNING','updated_at':time.time(),'neighbors':[],'errors':{}}
    monkeypatch.setattr('satsuma.network_discovery.discover',read)
    worker=WorkerNetworkDiscovery(store)
    assert worker.tick()['ok'] and worker.tick()['cached']
    assert len(calls)==1 and store.get('network_discovery')['status']=='RUNNING'


def test_health_uses_repaired_service_state_and_keeps_original_evidence(monkeypatch):
    import importlib.util
    from satsuma import self_health as h, self_guard, store as sm, app_firewall
    from satsuma.protected_storage import RootDataStore
    reports=[]
    monkeypatch.setattr(h,'read_report',lambda:{})
    monkeypatch.setattr(h,'report',lambda row:reports.append(row))
    monkeypatch.setattr(h.time,'sleep',lambda *a:None)
    monkeypatch.setattr(self_guard,'verify',lambda:None)
    monkeypatch.setattr(RootDataStore,'append',lambda *a:None)
    good={u:{'ActiveState':'active','UnitFileState':'enabled'} for u in h.UNITS}
    bad={**good,'satsuma-core.service':{'ActiveState':'failed','UnitFileState':'enabled'}}
    reads=iter([bad,good])
    monkeypatch.setattr(h,'inspect_units',lambda:next(reads))
    now=time.time()
    values={'dns_policy':{'enabled':False},'integrity_runtime':{'status':'HEALTHY','checked_at':now},
            'network_identity':{'status':'MATCHED_USER_APPROVAL','updated_at':now},
            'subnet_health':{'status':'running','updated_at':now}}
    class DB:
        def execute(self,*a):
            return NS(fetchall=lambda:[('team.'+team+'.health',json.dumps({'updated_at':now,'status':'RUNNING'}))
                                      for team in ('network_team','host_team','file_team','identity_team')])
    class FakeStore:
        db=DB()
        def get(self,key,default=None):return values.get(key,default)
        def close(self):pass
    monkeypatch.setattr(sm,'Store',FakeStore)
    monkeypatch.setattr(h,'command',lambda args,timeout=8:json.dumps({'packet_drop_verified':True}) if args[0]=='/usr/bin/unshare' else '')
    monkeypatch.setattr(importlib.util,'module_from_spec',lambda *a:NS(Nft=lambda:NS(verify_layout=lambda:None)))
    monkeypatch.setattr(importlib.util,'spec_from_file_location',lambda *a:NS(loader=NS(exec_module=lambda module:None)))
    monkeypatch.setattr(app_firewall,'status',lambda:{'status':'ACTIVE','enabled':True})
    # A disabled DNS filter is now a reported protection gap; this test is about service repair.
    monkeypatch.setattr(h,'disabled_dns_check',lambda policy:{'ok':True,'status':'FIXTURE'})
    read=Path.read_text
    monkeypatch.setattr(Path,'read_text',lambda self,*a,**kw:'100 0\n201 0\n' if str(self)=='/proc/net/netfilter/nfnetlink_queue' else read(self,*a,**kw))
    h.run()
    result=reports[-1]
    assert result['status']=='PASSED'
    assert result['checks']['services']['before_repair']['satsuma-core.service']['ActiveState']=='failed'
    assert result['checks']['services']['states']['satsuma-core.service']['ActiveState']=='active'
    assert result['repairs'][0]['status']=='START_REQUESTED'


def test_otx_mode_change_requires_session_and_valid_mode(store, monkeypatch):
    from satsuma.operator_service import OperatorController
    class Auth:
        def login(self,*a,**kw):return {'ok':True,'token':'session'}
        def validate_session(self,t):return t=='session'
    monkeypatch.setattr(otx,'load_config',lambda:{'api_key':'fixture'})
    def run(*a,**kw):return NS(returncode=0,stdout=table_json())
    controller=OperatorController(store,auth=Auth(),runner=run,boot_provider=lambda:{'response_unlocked':True})
    with pytest.raises(PermissionError):controller.dispatch(1000,'otx_blocker',{'enabled':True,'match_mode':'threshold'})
    controller.dispatch(1000,'login',{})
    result=controller.dispatch(1000,'otx_blocker',{'token':'session','enabled':True,'match_mode':'threshold'})
    assert result['match_mode']=='threshold' and store.get('operator_otx_policy')['match_mode']=='threshold'
    # Audit K3: the one-pulse mode is refused, not stored.
    with pytest.raises(ValueError,match='K3'):controller.dispatch(1000,'otx_blocker',{'token':'session','enabled':True,'match_mode':'any_pulse'})
    assert store.get('operator_otx_policy')['match_mode']=='threshold'
    with pytest.raises(ValueError):controller.dispatch(1000,'otx_blocker',{'token':'session','enabled':True,'match_mode':'unsafe'})


def test_qt_discovery_and_otx_mode_controls_work_offscreen():
    from PyQt6.QtWidgets import QApplication,QPushButton
    from satsuma.dashboard_qt.panels.defense_sections import NetworkDefensePanel
    import sys
    from pathlib import Path
    sys.path.insert(0,str(Path(__file__).parents[1]/'tools'))
    from dashboard_fixture import FakeBackend
    from satsuma.dashboard_qt.panels.protection import FirewallSettingsPanel as ProtectionPanel
    app=QApplication.instance() or QApplication([])
    class Backend:
        def call(self,method,**kw):
            return {'items':[],'discovery':{'status':'RUNNING','updated_at':time.time(),
                    'interfaces':[{'interface':'eth0','state':'UP','addresses':['192.168.1.5/24']}],
                    'neighbors':[{'ip':'192.168.1.1','mac':'02:00:00:00:00:01','interface':'eth0','state':['STALE']}]}}
    panel=NetworkDefensePanel(Backend())
    admin=ProtectionPanel(FakeBackend())
    calls=[]
    admin.act=lambda action,refresh=True:calls.append((action['method'],action['params']))
    try:
        panel.refresh();app.processEvents()
        assert '192.168.1.5/24' in panel.discovery.toPlainText()
        assert '192.168.1.1' in panel.discovery.toPlainText()
        assert panel.discovery.isReadOnly()
        # Audit K3: no button blocks on a single OTX pulse any more.
        assert not [b for b in admin.findChildren(QPushButton) if b.text()=='OTX eşleşmesinde engelle']
        admin.reload()
        row=admin.switches['otx_blocker'];assert row.switch.known and not row.switch.isChecked()
        row.switch.click()
        assert calls[-1]==('otx_blocker',{'enabled':True})
    finally:panel.close();admin.close()
