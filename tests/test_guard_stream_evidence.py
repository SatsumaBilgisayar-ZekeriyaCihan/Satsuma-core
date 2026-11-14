"""Suricata engine noise is not attack intent. No live nft/OTX/service calls."""
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock,patch
import pytest
from satsuma.nft_inventory import parse_owned_sets,snapshot
from satsuma import dashboard_api as api
from satsuma.store import Store

spec=importlib.util.spec_from_file_location('stream_guard',Path(__file__).resolve().parents[1]/'integrations/satsuma_guard.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)


def service():
    result=object.__new__(guard.Guard)
    result.cfg={**guard.DEFAULT,'fast_block':True,'otx_enabled':True}
    result.own_ips={'192.168.1.10'}
    result.egress_eligible=lambda src,dst:src in result.own_ips
    result.eligible=lambda *a:True
    result.flow_checker=lambda *a:True;result.reply_checker=lambda *a:True
    result.write=Mock();result.block=Mock();result.otx_check=Mock(return_value=True)
    return result


@pytest.mark.parametrize('sid,label',[(2210020,'SURICATA STREAM 3way handshake SYN retransmission wrong seq'),
    (2210045,'SURICATA STREAM packet with invalid timestamp'),(2200070,'SURICATA DECODER anomaly')])
def test_priority_three_engine_events_never_create_persistent_blocks_even_with_otx(sid,label):
    svc=service()
    alert={'source_ip':'192.168.1.10','dest_ip':'45.33.32.10','priority':3,'rule_id':f'1:{sid}:1',
           'signature':label,'source_port':40000,'dest_port':443,'protocol':'TCP'}
    svc.on_alert(alert)
    svc.block.assert_not_called();svc.otx_check.assert_not_called()
    outcome=svc.write.call_args
    assert outcome.args[0]=='would_block'
    assert outcome.kwargs['evidence_class']=='engine_anomaly'
    assert outcome.kwargs['otx_role']=='reputation_not_attack_proof'


def test_genuine_signature_keeps_existing_fast_block_policy():
    svc=service();svc.cfg['otx_enabled']=False
    svc.on_alert({'source_ip':'192.168.1.10','dest_ip':'45.33.32.10','priority':3,
                  'rule_id':'1:2010935:1','signature':'ET MALWARE fixture C2', 'protocol':'TCP'})
    svc.block.assert_called_once()
    assert svc.block.call_args.args[1]=='suricata_priority_3'


def test_eve_and_fast_preserve_generator_identity_and_classification():
    eve={'event_type':'alert','src_ip':'45.33.32.10','dest_ip':'192.168.1.10','proto':'TCP',
         'alert':{'gid':1,'signature_id':2210045,'severity':3,'signature':'SURICATA STREAM invalid timestamp'}}
    alert=guard.parse_alert(json.dumps(eve),'eve')
    assert alert['generator_id']==1 and guard.alert_evidence_class(alert)=='engine_anomaly'


def test_kernel_set_union_is_not_truncated_database_record_count():
    data={'nftables':[{'set':{'family':'inet','table':'satsuma_core','name':'blocked_ips','elem':['45.33.32.10','45.33.32.11']}},
                     {'set':{'family':'inet','table':'satsuma_otx_guard','name':'blocked_v4','elem':['45.33.32.10','45.33.32.12']}},
                     {'set':{'family':'inet','table':'unrelated','name':'blocked_ips','elem':['45.33.32.13']}}]}
    report=parse_owned_sets(data)
    assert report['unique_ip_count']==3 and sum(s['element_count'] for s in report['sets'])==4
    assert not report['traffic_drop_verified']


def test_inventory_only_lists_and_failure_is_unknown_not_zero():
    calls=[]
    def runner(command,**kwargs):calls.append(command);return SimpleNamespace(returncode=1,stdout='')
    result=snapshot(runner)
    assert calls==[['/usr/sbin/nft','-j','list','ruleset']]
    assert result['data_state']=='UNKNOWN' and result['unique_ip_count'] is None


def test_unparsed_interval_elements_do_not_produce_a_complete_count():
    data={'nftables':[{'set':{'family':'inet','table':'satsuma_core','name':'blocked_ips','elem':[{'prefix':{'addr':'45.33.32.0','len':24}}]}}]}
    result=parse_owned_sets(data)
    assert result['data_state']=='PARTIAL' and result['unique_ip_count'] is None


def test_separate_otx_service_is_not_disabled_by_legacy_worker_toggle(tmp_path,monkeypatch):
    import time
    store=Store(tmp_path/'core',test=True)
    store.set('worker.otx.health',{'status':'disabled','updated_at':time.time()})
    store.set('policy_effective',{'workers':{'otx':{'enabled':False},'otx_service':{'enabled':False}}})
    store.set('otx_health',{'status':'active','updated_at':time.time()-70,'last_success':time.time()-70})
    monkeypatch.setattr(api,'DB_PATH',str(store.path));monkeypatch.setattr(api,'_connect_host',Mock(side_effect=FileNotFoundError))
    result=api.m_workers()
    assert result['otx']['status']=='DISABLED'
    assert result['otx_service']['status']=='RUNNING'
    assert result['otx_service']['configuration_enabled'] is False
    store.close()
