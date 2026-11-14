"""Regressions reproduced from the redacted 21 October VM evidence.

No host firewall, service manager or mount is changed by these tests.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time
from types import SimpleNamespace as NS
from unittest.mock import Mock

import pytest

from installer import image_runtime as image, integrity
from satsuma import app_firewall as firewall, config, early_guard, policy
from satsuma.configuration_status import ConfigurationError, entrypoint
from satsuma.integrity_monitor import run_once
from satsuma.maintenance_jobs import MaintenanceJobs
from satsuma.nfqueue import Queue
from satsuma.operator_service import OperatorController
from satsuma.presentation import action_outcome
from test_worker_delivery import Store

ROOT=Path(__file__).parents[1]
FLOW=(4,6,'192.0.2.2',4000,'198.51.100.2',443)
APP={'key':'a'*64,'application_key':'b'*64,'pid':123,'created_at':1,
     'uid':1000,'executable':'/fixture/browser','sha256':'c'*64,'cgroup':'/one'}


def test_invalid_fixed_policy_is_not_a_binary_integrity_failure(tmp_path,monkeypatch):
    document=policy.from_legacy(config.DEFAULT)
    document['scheduled_scans']['interval_seconds']=1
    path=tmp_path/'policy.json';path.write_text(json.dumps(document))
    monkeypatch.setattr(policy,'POLICY_PATH',path)
    monkeypatch.setattr(config,'_read_secure_json',lambda p:json.loads(p.read_text()))
    with pytest.raises(ConfigurationError,match='POLICY_INVALID'):
        config.load_with_policy()
    result=early_guard.run_guard(verifier=lambda:123,config_checker=config.load_with_policy)
    assert result['checks']['application']=={'ok':True,'files':123}
    assert result['state']=='POLICY_INVALID' and result['response_unlocked'] is False
    assert {reason['code'] for reason in result['failure_reasons']}=={'POLICY_INVALID'}
    store=Store()
    report=run_once(store,guard=lambda:result,verdict_writer=lambda _:None,report_writer=lambda *a:None)
    assert report['status']=='POLICY_INVALID' and report['approved_baseline_replaced'] is False
    findings=[record for kind,record in store.records if kind=='findings']
    assert findings[0]['rule_id']=='SATSUMA-CONFIG-001'
    assert 'dosya' not in findings[0]['title'].lower()


def test_code_manifest_never_loads_policy_and_still_detects_changed_bytes(tmp_path,monkeypatch):
    root=tmp_path/'app';root.mkdir();code=root/'a.py';code.write_text('trusted')
    manifest=tmp_path/'inventory.json';integrity.build(root,manifest)
    monkeypatch.setattr(integrity,'ROOT',root)
    monkeypatch.setattr(integrity,'REQUIRED',('a.py',))
    monkeypatch.setattr(config,'load_with_policy',Mock(side_effect=AssertionError('not a code check')))
    assert integrity.verify(root,manifest,ownership=False)==2
    code.write_text('altered')
    with pytest.raises(RuntimeError,match='Integrity mismatch'):
        integrity.verify(root,manifest,ownership=False)
    config.load_with_policy.assert_not_called()


def test_configuration_exit_stops_retry_but_does_not_hide_other_failures(capsys):
    def invalid():raise ConfigurationError('POLICY_INVALID','/etc/satsuma-core/policy.json','fixed field')
    assert entrypoint(invalid)==78
    assert json.loads(capsys.readouterr().err)['status']=='POLICY_INVALID'
    def corrupt():raise RuntimeError('image changed')
    with pytest.raises(RuntimeError,match='image changed'):entrypoint(corrupt)


def test_all_auto_restarting_services_have_bounded_retry_and_config_exit():
    for path in (ROOT/'systemd').glob('*.service'):
        text=path.read_text()
        # Restart=no never restarts itself; a timer-driven oneshot like the
        # security scan needs no start limit (see that unit).
        restarting=[l for l in text.splitlines() if l.startswith('Restart=') and l!='Restart=no']
        if path.name in ('satsuma-kernel-guard.service','satsuma-exec-guard.service','satsuma-ram-clamd.service',
                         'satsuma-clamonacc.service','satsuma-onaccess-listener.service'):
            # The deliberate exceptions: a guard that gives up after three
            # crashes protects nothing, so it restarts at once and never stops trying.
            # 2.2.37: the RAM scanner's ClamAV too (owner: attackers keep blocking the RAM module).
            # 2.2.37: on-access ClamAV scanning never gives up either (owner's decision 2026-11-14).
            assert restarting==['Restart=always'] and 'StartLimitIntervalSec=0' in text,path
            continue
        if restarting:
            assert 'StartLimitIntervalSec=300' in text,path
            assert 'StartLimitBurst=3' in text,path
            # Native clamd uses exit 1 for both configuration and runtime errors.
            # Its retry limit applies without a fictitious EX_CONFIG mapping.
            if path.name != 'satsuma-ram-clamd.service':
                assert 'RestartPreventExitStatus=78' in text,path


def test_started_boot_check_and_final_failure_share_id_not_false_success():
    store=Store();process=NS(poll=lambda:None)
    def popen(argv,**kwargs):
        kwargs['stdout'].write(b'POLICY_INVALID\n');return process
    jobs=MaintenanceJobs(store,popen=popen)
    class Auth:
        def login(self,*args,**kwargs):return {'ok':True,'token':'test'}
        def validate_session(self,*args):return True
    controller=OperatorController(store,auth=Auth(),jobs=jobs,boot_provider=lambda:{})
    controller.dispatch(1000,'login',{})
    started=controller.dispatch(1000,'boot_check',{'token':'test'})
    action=store.records[-1][1]
    assert action['status']=='RUNNING' and action['command_id']==started['command_id']
    process.poll=lambda:1
    final=jobs.status()
    assert final['status']=='FAILED' and final['command_id']==started['command_id']
    assert store.records[-1][1]['status']=='FAILED'
    assert jobs.status()==final


def test_explicit_application_grant_covers_browser_children_and_clears_prompts(monkeypatch):
    engine=firewall.Decisions(clock=lambda:1)
    child={**APP,'key':'d'*64,'pid':124,'cgroup':'/two'}
    assert not engine.decide(APP,FLOW) and not engine.decide(child,(*FLOW[:-1],80))
    monkeypatch.setattr(firewall,'identity',lambda pid:APP)
    monkeypatch.setattr(firewall,'policy',lambda:{'rules':{},'application_rules':{}})
    monkeypatch.setattr(firewall.RootDataStore,'replace',lambda *a:None)
    engine.answer(next(iter(engine.pending)),'allow','application')
    assert not engine.pending
    assert engine.decide(child,(*FLOW[:-1],80))
    changed={**child,'application_key':'e'*64}
    assert not engine.decide(changed,FLOW)
    engine.rules[child['key']]='deny'
    assert not engine.decide(child,FLOW)
    engine.rules.clear();engine.application_rules[APP['application_key']]='deny'
    engine.once[json.dumps([APP['key'],APP['pid'],APP['created_at'],list(FLOW)],separators=(',',':'))]={'action':'allow','expires':10}
    assert not engine.decide(APP,FLOW)


def test_revoked_application_grant_has_no_cached_allow(monkeypatch):
    engine=firewall.Decisions(clock=lambda:1)
    engine.application_rules[APP['application_key']]='allow'
    assert engine.decide(APP,FLOW)
    monkeypatch.setattr(firewall,'policy',lambda:{'rules':{},'application_rules':{},'enabled':True})
    engine.reload()
    assert not engine.decide(APP,FLOW)


def connection(pid=123,port=4000,udp=False):
    return NS(family=socket.AF_INET,type=socket.SOCK_DGRAM if udp else socket.SOCK_STREAM,
              pid=pid,laddr=NS(ip=FLOW[2],port=port),raddr=NS(ip=FLOW[4],port=FLOW[5]))


def test_indexed_packet_lookup_rechecks_each_identity_and_ambiguity(monkeypatch):
    owners=firewall.SocketOwners([connection(),*[connection(port=n) for n in range(10000,20000)]])
    live=[APP]
    identify=Mock(side_effect=lambda pid:live[0]);monkeypatch.setattr(firewall,'identity',identify)
    for _ in range(100):assert owners.resolve(FLOW)==APP
    assert identify.call_count==100
    live[0]={**APP,'created_at':2,'key':'f'*64}
    assert owners.resolve(FLOW)['created_at']==2
    ambiguous=firewall.SocketOwners([connection(),connection(pid=999,udp=True)])
    assert ambiguous.resolve(FLOW)==live[0] # Different transport does not create a false match.
    ambiguous=firewall.SocketOwners([connection(),connection(pid=999)])
    with pytest.raises(ValueError,match='ambiguous'):ambiguous.resolve(FLOW)


def test_queue_batches_only_already_received_packets_and_discards_snapshot(monkeypatch):
    import satsuma.nfqueue as module
    events=[];ready=iter([True]*4+[False])
    monkeypatch.setattr(module.select,'select',lambda *a:([1] if next(ready) else [],[],[]))
    monkeypatch.setattr(module.os,'read',lambda *a:b'packet')
    queue=object.__new__(Queue);queue.fd=1;queue.handle=None
    queue.prepare=lambda:events.append('snapshot')
    queue.finish=lambda:events.append('discard')
    queue.lib=NS(nfq_handle_packet=lambda *a:(events.append('verdict') or 0))
    queue.poll(.1)
    assert events==['snapshot',*['verdict']*4,'discard']


def test_dbus_burst_neither_backpressures_the_bus_nor_ends_coverage():
    # Field log 2026-10-25: a burst used to end the subscription and discard
    # the tick. Now the monitor keeps reading (no backpressure), drops and
    # counts what does not fit, and keeps delivering afterwards.
    from satsuma.dbus_stream import DbusStream, QUEUE_LIMIT
    readfd,writefd=os.pipe()
    class Process:
        stdout=os.fdopen(readfd,'rb');stopped=False
        def poll(self):return 0 if self.stopped else None
        def terminate(self):
            if not self.stopped:self.stopped=True;os.close(writefd)
        def wait(self,timeout=None):return 0
    monitor=DbusStream(popen=lambda *a,**k:Process())
    expected=[f'method call serial={i}' for i in range(2300)]
    writer=threading.Thread(target=lambda:[os.write(writefd,(line+'\n').encode()) for line in expected])
    writer.start()
    try:
        writer.join(timeout=5)
        assert not writer.is_alive()  # the bus side never blocked
        deadline=time.monotonic()+5
        while monitor.dropped<2300-QUEUE_LIMIT and time.monotonic()<deadline:time.sleep(.005)
        assert monitor.process.poll() is None  # subscription kept
        assert list(monitor.queue)==expected[:QUEUE_LIMIT]
        text=monitor.capture()
        assert text.splitlines()==expected[:QUEUE_LIMIT]  # the whole queue in one capture
        assert monitor.take_dropped()==2300-QUEUE_LIMIT and monitor.take_dropped()==0
        monitor.commit()
        os.write(writefd,b'signal serial=after\n')
        deadline=time.monotonic()+2
        while not monitor.queue and time.monotonic()<deadline:time.sleep(.01)
        assert monitor.capture()=='signal serial=after'
    finally:
        monitor.close()


def test_dbus_worker_reports_dropped_headers_as_degraded(monkeypatch):
    from satsuma.worker_systemd_dbus import WorkerSystemdDbus
    store=Store()
    worker=WorkerSystemdDbus(store)
    monkeypatch.setattr(worker,'collect',lambda dbus_duration=3:{'timestamp':1,'units':[],'timers':[],
        'dbus_services':[],'dbus_messages':[{'member':'X','interface':'y'}],'dbus_dropped':252})
    worker.tick(NS(ingest_host=lambda event:None))
    health=store.get(worker.health_key)
    assert health['status']=='DEGRADED' and health['dbus_dropped']==252 and '252' in health['degraded_reason']


def test_busy_unmount_preserves_evidence_and_reports_actual_reason(tmp_path,monkeypatch):
    active=tmp_path/'active.json';active.write_bytes(b'retained')
    monkeypatch.setattr(image.os.path,'ismount',lambda _:True)
    monkeypatch.setattr(image,'active',lambda:({},tmp_path/'runtime.squashfs'))
    monkeypatch.setattr(image,'check_mount',lambda _:None)
    monkeypatch.setattr(image,'run',Mock(side_effect=RuntimeError('umount: target is busy')))
    with pytest.raises(RuntimeError,match='target is busy'):image.unmount()
    assert active.read_bytes()==b'retained'
    image.run.assert_called_once_with(['/usr/bin/umount',str(image.MOUNT)])


def test_successful_unmount_is_read_back_and_foreign_mount_is_refused(monkeypatch):
    mounted=iter([True,False])
    monkeypatch.setattr(image.os.path,'ismount',lambda _:next(mounted))
    monkeypatch.setattr(image,'active',lambda:({},Path('/expected')))
    monkeypatch.setattr(image,'check_mount',lambda _:None)
    runner=Mock();monkeypatch.setattr(image,'run',runner)
    assert image.unmount()['status']=='UNMOUNTED'
    monkeypatch.setattr(image.os.path,'ismount',lambda _:True)
    monkeypatch.setattr(image,'check_mount',Mock(side_effect=RuntimeError('foreign mount')))
    with pytest.raises(RuntimeError,match='foreign mount'):image.unmount()
    assert runner.call_count==1


@pytest.mark.parametrize('foreign',[False,True])
def test_uninstall_firewall_cleanup_checks_owner_and_leaves_unknown_queues(foreign,monkeypatch):
    ours={'family':'inet','name':'satsuma_app_control'}
    unknown={'family':'inet','name':'satsuma_unmarked'}
    unrelated={'family':'inet','name':'user_firewall'}
    calls=[];deleted=False
    def runner(args,**kwargs):
        nonlocal deleted
        calls.append((args,kwargs))
        if args[-3:]==['list','table','inet']:raise AssertionError('bad query')
        if 'tables' in args:
            return NS(stdout=json.dumps({'nftables':[{'table':t} for t in ([unknown,unrelated] if deleted else [ours,unknown,unrelated])]}))
        if 'list' in args:
            return NS(stdout=json.dumps({'nftables':[{'table':{**ours,'comment':'foreign' if foreign else firewall.OWNER}}]}))
        if '--check' not in args:deleted=True
        return NS(stdout='')
    monkeypatch.setattr(image,'run',runner)
    if foreign:
        with pytest.raises(PermissionError,match='ownership mismatch'):image.cleanup_firewall()
        assert not deleted
    else:
        result=image.cleanup_firewall()
        assert result['retained_unmarked_tables']==['satsuma_unmarked']
        assert result['removed_tables']==['satsuma_app_control']
        assert result['queue_owners_changed'] is False
    assert not any('flush' in args or 'conntrack' in args for args,_ in calls)


def test_suricata_unknown_direction_is_visible_without_false_block_claim():
    record={'source':'suricata_guard','status':'ACTION_UNSUPPORTED',
            'reason':'outbound_or_connection_direction_unverified'}
    assert 'engellenmedi' in action_outcome(record)
    assert 'doğrulanamadı' in action_outcome(record)
    assert 'ölçülmedi' in action_outcome({**record,'status':'set_membership_confirmed'})


@pytest.mark.parametrize('failure',['none','service','unmount','cleanup'])
def test_real_rpm_removal_script_preserves_helper_on_stop_or_unmount_failure(tmp_path,failure):
    # Execute the real scriptlet against a fake service manager and mount helper.
    spec=(ROOT/'packaging/satsuma-core.spec').read_text()
    script=spec.split('%preun\n',1)[1].split('%posttrans\n',1)[0]
    systemd=tmp_path/'systemd';systemd.mkdir()
    script=script.replace('/run/systemd/system',str(systemd))
    helper=tmp_path/'helper'
    helper.write_text('#!/bin/sh\necho "helper $*" >> "$TEST_LOG"\ncase "$FAILURE:$1" in unmount:unmount|cleanup:cleanup-firewall) exit 32;; esac\n')
    helper.chmod(0o755)
    script=script.replace('/usr/bin/python3 -I -B /usr/libexec/satsuma-image',str(helper))
    manager=tmp_path/'systemctl'
    manager.write_text('#!/bin/sh\necho "$*" >> "$TEST_LOG"\nif [ "$FAILURE" = service ] && [ "$*" = "disable --now satsuma-core.service" ]; then exit 1; fi\n')
    manager.chmod(0o755)
    result=subprocess.run(['/bin/bash','-c',script,'scriptlet','0'],env={
        'PATH':str(tmp_path)+':/usr/bin:/bin','TEST_LOG':str(tmp_path/'log'),'FAILURE':failure},
        capture_output=True,text=True,timeout=5)
    calls=(tmp_path/'log').read_text()
    assert (result.returncode==0)==(failure=='none')
    if failure=='none':
        assert calls.index('stop satsuma-core-security-scan.timer')<calls.index('disable --now satsuma-core-security-scan.service')
        assert calls.index('helper unmount')<calls.index('helper cleanup-firewall')<calls.index('disable --now satsuma-image.service')
    else:assert 'disable --now satsuma-image.service' not in calls
