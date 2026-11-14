from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import importlib.util
import json
import subprocess
import sys
import pytest
from satsuma.integrity_monitor import assess_runtime, run_once
from satsuma.app import runtime_health
from satsuma.smart_rules import SmartRuleEngine
from test_worker_delivery import Store

spec=importlib.util.spec_from_file_location('inbound_guard',Path(__file__).parents[1]/'integrations/satsuma_guard.py')
guard=importlib.util.module_from_spec(spec);spec.loader.exec_module(guard)


def test_integrity_warning_does_not_stop_monitor_or_approve_baseline():
    def broken():raise RuntimeError('tamper')
    assert assess_runtime(broken)['status']=='UNTRUSTED'
    store=Store();verdict={'state':'WARNING','response_unlocked':False,'failure_reasons':[{'code':'APPLICATION_CHECK_FAILED'}], 'checks':{'application':{'ok':False}}}
    reports=[];written=[]
    result=run_once(store,guard=lambda:verdict,verdict_writer=written.append,
        report_writer=lambda *a:reports.append(a))
    assert result['approved_baseline_replaced'] is False
    assert store.get('integrity_runtime')['status']=='UNTRUSTED'
    assert written==[verdict] and reports
    assert any(k=='findings' for k,v in store.records)


@pytest.mark.parametrize('priority',[1,2,3])
def test_priorities_block_only_original_incoming(tmp_path,priority):
    cfg=dict(guard.DEFAULT,mode='observe',state_dir=str(tmp_path),otx_enabled=False,subnet_enabled=False)
    with patch.object(guard,'local_ips',return_value={'192.168.1.10'}):
        svc=guard.Guard(cfg,flow_checker=lambda a:True,alert_verifier=lambda a:{'verdict':'verified_live_process'})
    alert=dict(source_ip='45.33.32.10',dest_ip='192.168.1.10',source_port=40000,dest_port=443,protocol='TCP',priority=priority,signature='test',rule_id='1:2:3')
    try:
        svc.on_alert(alert)
        assert svc.db.execute("SELECT count(*) FROM events WHERE event='would_block'").fetchone()[0]==1
        svc.flow_checker=lambda a:False
        svc.on_alert(alert)
        assert svc.db.execute("SELECT count(*) FROM events WHERE event='would_block'").fetchone()[0]==1
        assert svc.db.execute("SELECT count(*) FROM events WHERE event='ACTION_UNSUPPORTED'").fetchone()[0]==1
    finally:svc.events.close();svc.db.close()


def test_conntrack_reply_is_not_incoming():
    alert=dict(source_ip='45.33.32.10',dest_ip='192.168.1.10',source_port=443,dest_port=50000,protocol='TCP')
    outgoing='tcp 6 100 ESTABLISHED src=192.168.1.10 dst=45.33.32.10 sport=50000 dport=443 src=45.33.32.10 dst=192.168.1.10 sport=443 dport=50000'
    with patch.object(guard,'command',return_value=SimpleNamespace(returncode=0,stdout=outgoing)):
        assert not guard.inbound_connection(alert)
    incoming='tcp 6 100 ESTABLISHED src=45.33.32.10 dst=192.168.1.10 sport=443 dport=50000 src=192.168.1.10 dst=45.33.32.10 sport=50000 dport=443 [ASSURED] use=1'
    with patch.object(guard,'command',return_value=SimpleNamespace(returncode=0,stdout=incoming)):
        assert guard.inbound_connection(alert)
    alert.pop('source_port')
    assert not guard.inbound_connection(alert)


def test_fast_ipv6_has_ports_and_signature_id():
    alert=guard.parse_alert('[**] [1:2:3] TeamViewer [**] [Priority: 2] {TCP} [2606:4700:4700::1111]:443 -> [fd00::1]:5000','fast')
    assert alert['source_port']==443 and alert['dest_port']==5000
    assert alert['rule_id']=='1:2:3' and alert['dest_ip']=='fd00::1'


def test_healthy_core_is_not_inferred_from_process_existence():
    result=runtime_health(Store(),{}, {'nfqueue_100_listener':False})
    assert result['status']=='degraded' and len(result['degraded_reasons'])>=4


def test_runtime_rule_error_is_not_no_match():
    engine=SmartRuleEngine()
    with patch.object(engine,'_matches_compiled',side_effect=RuntimeError('broken matcher')):
        with pytest.raises(RuntimeError,match='evaluation failed'):
            engine.match({'source':'audit','action':'file_access'})


@pytest.mark.parametrize('path,operation,rid',[
 ('/dev/mem','read','SATSUMA-DEV-001'),('/dev/input/event2','read','SATSUMA-DEV-002'),
 ('/dev/nvme0n1','write','SATSUMA-DEV-003')])
def test_device_access_is_indicator_without_destructive_action(path,operation,rid):
    findings=SmartRuleEngine().match(dict(source='audit',action='file_access',file_path=path,operation=operation))
    assert any(rid in f.get('matched_rules',[f['rule_id']]) for f in findings)
    assert all(f['classification']=='indicator' for f in findings)
    assert all(not {'kill_process','block_ip','quarantine_file'} & set(f['actions']) for f in findings)


def test_cache_prefix_avoids_loading_changed_local_bytecode(tmp_path):
    import py_compile
    import os
    module=tmp_path/'payload.py';module.write_text("VALUE='unsafe'\n")
    py_compile.compile(str(module),doraise=True)
    stamp=module.stat().st_mtime
    module.write_text("VALUE='trusted'\n")
    # Match source size/timestamp for a normal timestamp-based stale bytecode hit.
    module.write_text("VALUE='safe__'\n");os.utime(module,(stamp,stamp))
    command=[sys.executable,'-I','-B','-X','pycache_prefix='+str(tmp_path/'trusted-cache'),'-c',
             'import sys;sys.path.insert(0,sys.argv[1]);import payload;print(payload.VALUE)',str(tmp_path)]
    result=subprocess.run(command,capture_output=True,text=True,check=True)
    assert result.stdout.strip()=='safe__'


def test_original_223_rules_are_preserved_byte_for_byte():
    import hashlib
    root=Path(__file__).parents[1]
    old=json.loads((root/'tests/fixtures/candidate18-original-rules.json').read_text())
    assert old['original_rule_count']==223 and len(old['ids'])==223
    engine=SmartRuleEngine()
    assert set(old['ids']) <= {r['_id'] for r in engine.rules}
    for name,digest in old['file_sha256'].items():
        assert hashlib.sha256((root/name).read_bytes()).hexdigest()==digest
    assert len(engine.rules)==231


def test_udev_context_is_observation_not_automatic_response():
    from satsuma.udev_worker import UdevTracker,parse_properties
    from test_worker_delivery import Pipeline
    store=Store();pipeline=Pipeline()
    event=parse_properties(['ACTION=add','DEVPATH=/devices/virtual/input/input1','DEVNAME=/dev/input/event1','SEQNUM=12'])
    assert event
    assert parse_properties(['ACTION=add','DEVPATH=/devices/x','DEVNAME=/dev/../etc/passwd']) is None
    identity={'pid':123,'starttime':99,'boot_id':'test','exe':'/usr/bin/example','uid':1000}
    tracker=UdevTracker(store,pipeline,users=lambda targets:[{'identity':identity,'devices':['/dev/input/event1']}],clock=lambda:10)
    tracker.ingest(event);tracker.poll_processes();tracker.poll_processes()
    findings=[v for k,v in store.records if k=='findings']
    assert {v['rule_id'] for v in findings}=={'SATSUMA-UDEV-001','SATSUMA-UDEV-002'}
    assert len(findings)==2 and all(v['classification']=='indicator' for v in findings)
    assert not [v for k,v in store.records if k=='actions']


def test_device_inventory_does_not_follow_device_links_or_read_payload(tmp_path):
    from satsuma.host_diagnostics import device_inventory
    (tmp_path/'device').symlink_to('/dev/zero')
    (tmp_path/'plain').write_text('private')
    with patch.object(Path,'open',side_effect=AssertionError('must not read contents')):
        result=device_inventory(tmp_path)
    assert result['status']=='COMPLETED'
    assert next(x for x in result['items'] if x['path'].endswith('/device'))['type']=='symlink'


def test_shipped_policy_enables_supported_responses_without_bypassing_gates():
    from satsuma.policy import effective
    policy=json.loads((Path(__file__).parents[1]/'config_examples/policy.json').read_text())
    cfg=effective(policy)
    assert cfg['response_enabled'] and cfg['destructive_response_enabled'] and cfg['auto_action_network_enabled']
    assert cfg['scheduled_scans']['automatic_quarantine'] is False
