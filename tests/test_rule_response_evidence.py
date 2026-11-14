"""No real signal, firewall or service action: trusted SQLite evidence only."""
import copy
import json
import time
from unittest.mock import Mock
import pytest
from satsuma.store import Store
from satsuma.response_policy import authorize_destructive
from satsuma.rule_response import evidence_report,requirement_for,set_requirement,POLICY_KEY
from satsuma.auto_process import corroborate
from satsuma.response import ResponseWorker
from test_deepseek_secure_workflow import proposal

RULE='SATSUMA-EXEC-001'

@pytest.fixture
def store(tmp_path):
    value=Store(tmp_path/'data',test=True)
    yield value
    value.close()


def evidence(store,source='sys_proc',pid=4242,start=1234,exe='/opt/fixture/tool',age=0):
    event={'source':source,'pid':pid,'starttime':start,'exe':exe,'timestamp':time.time()-age,'cmd':'fixture'}
    raw_id=store.add('events',event)
    body={'raw_id':raw_id,'event':{'event':{'timestamp':event['timestamp'],'action':'new_process'},'source':{'type':source},'raw':{'data':event}}}
    cursor=store.db.execute("INSERT INTO records(kind,created,body) VALUES('normalized',?,?)",(time.time(),json.dumps(body)))
    store.db.commit();event['id']=cursor.lastrowid
    return {'rule_id':RULE if source=='sys_proc' else 'SATSUMA-EXEC-OTHER','classification':'suspicious','severity':'high','event':event}


def finding_with(store,**second):
    first=evidence(store);other=evidence(store,source='audit',**second)
    return {**first,'corroborating_findings':[other], 'independent_sources':['sys_proc','audit'],'multi_source_verified':True}


def gate(store,finding,minimum=2,**context):
    cfg={'response_enabled':True,'destructive_response_enabled':True,'destructive_allowed_actions':['process_kill'],
         'auto_action_process_enabled':True,'user_enforcement':True,
         POLICY_KEY:{RULE:{'minimum_sources':minimum,'freshness_seconds':60}}}
    return authorize_destructive('process_kill',finding,cfg,{'automated':True,'pid':4242,'user_enforcement':True,**context},evidence_store=store)


def test_distinct_fresh_same_process_sensor_records_pass_evidence_gate(store):
    finding=finding_with(store)
    report=evidence_report(store,finding,'process_kill',{'minimum_sources':2})
    assert report['passed'] and report['verified']==2 and report['source_families']==['audit','process']
    assert gate(store,finding).allowed


@pytest.mark.parametrize('change',['same_sensor','wrong_pid','wrong_start','wrong_exe','stale','future','names_only','forged_id','boolean_only'])
def test_claimed_or_wrong_target_evidence_cannot_satisfy_multisource_policy(store,change):
    values={'wrong_pid':{'pid':9999},'wrong_start':{'start':9999},'wrong_exe':{'exe':'/opt/other'},
            'stale':{'age':600},'future':{'age':-600}}
    finding=finding_with(store,**values.get(change,{}))
    if change=='same_sensor':finding['corroborating_findings']=[evidence(store,source='sys_proc')]
    if change in ('names_only','boolean_only'):finding['corroborating_findings']=[]
    if change=='forged_id':finding['corroborating_findings'][0]['event']['id']=9999999
    auth=gate(store,finding)
    assert not auth.allowed and 'insufficient_independent_fresh_same_target_evidence' in auth.reasons


def test_finding_event_payload_cannot_override_the_stored_original(store):
    finding=finding_with(store,pid=9999)
    finding['corroborating_findings'][0]['event']['pid']=4242
    assert not gate(store,finding).allowed


def test_enforcement_and_manual_flags_cannot_waive_required_evidence(store):
    finding=evidence(store)
    for overrides in ({'admin_session_valid':True,'manual':True},{'user_enforcement':True,'multi_source_verified':True}):
        assert not gate(store,finding,**overrides).allowed


def test_no_override_preserves_existing_single_source_behavior(store):
    finding=evidence(store)
    assert gate(store,finding,minimum=1).allowed
    assert not gate(store,finding,minimum=2).allowed


def test_missing_evidence_continues_recording_but_never_reaches_process_primitive(store):
    from satsuma.auto_process import respond
    finding=evidence(store)
    store.set(POLICY_KEY,{RULE:{'minimum_sources':2,'freshness_seconds':60}})
    response=Mock();config={'response_enabled':True,'destructive_response_enabled':True,
        'destructive_allowed_actions':['process_kill'],'auto_action_process_enabled':True}
    record=respond(store,config,finding,response)
    assert not record['signal_sent']
    response.terminate_process.assert_not_called()
    assert store.db.execute("SELECT count(*) FROM records WHERE kind='actions'").fetchone()[0]>0


def test_final_response_worker_rechecks_required_evidence_before_privileged_transport(store):
    finding=evidence(store)
    store.set(POLICY_KEY,{RULE:{'minimum_sources':2}})
    response=ResponseWorker(store,{'response_enabled':True});response._privd=Mock()
    result=response.terminate_process(4242,'isolated check',evidence=finding['event'],context={'finding':finding,'rule_id':RULE})
    assert not result['signal_sent']
    response._privd.assert_not_called()


def test_corroborator_keeps_actual_evidence_references_and_ignores_sensor_duplicates(store):
    first=evidence(store);second=evidence(store,source='audit')
    combined=corroborate([first,second]);assert len(combined)==1
    assert len(combined[0]['corroborating_findings'])==2
    assert gate(store,combined[0]).allowed
    duplicate={**first,'rule_id':'DIFFERENT-RULE'}
    assert not corroborate([first,duplicate])


def test_policy_cannot_be_downgraded_in_finding_or_config(store):
    store.set(POLICY_KEY,{RULE:{'minimum_sources':2}})
    finding=evidence(store);finding['required_sources']=1
    assert not gate(store,finding,minimum=1).allowed


def test_matched_rule_requirement_cannot_be_hidden_by_correlation_primary_id(store):
    finding=evidence(store);finding['rule_id']='OTHER';finding['matched_rules']=[RULE,'OTHER']
    assert not gate(store,finding).allowed


def test_policy_and_target_exemptions_still_required_when_evidence_passes(store):
    finding=finding_with(store)
    assert not gate(store,finding,fail_safe_ok=False).allowed
    finding['policy_allowed']=False
    assert not gate(store,finding,admin_session_valid=True).allowed


def test_inventory_all_233_are_distinct_and_no_baseline_actions_were_modified():
    from tools.build_rule_response_inventory import build
    from satsuma.smart_rules import SmartRuleEngine
    from satsuma.ai_rule_package import digest
    catalog=build()['rules'];rules=SmartRuleEngine().rules
    assert len(catalog)==len(rules)==233
    assert len({r['rule_id'] for r in catalog})==233
    for row,rule in zip(catalog,rules):
        assert row['current_actions']==rule['actions']
        assert row['match']==rule['base_match']
        assert row['detection_sha256']==digest({k:v for k,v in rule.items() if not k.startswith('_')})
        assert row['proposed_response']['applied'] is False


def test_one_rule_setting_leaves_other_227_unchanged(store):
    from tools.build_rule_response_inventory import build
    row=build()['rules'][0]
    set_requirement(store,row['rule_id'],2,1000,expected_hash=row['detection_sha256'])
    assert list(store.get(POLICY_KEY))==[row['rule_id']]


def test_same_raw_event_relabelled_cannot_become_two_independent_signals(store):
    first=evidence(store);second=evidence(store,source='audit')
    original=store.db.execute('SELECT body FROM records WHERE id=?',(first['event']['id'],)).fetchone()[0]
    second_outer=json.loads(store.db.execute('SELECT body FROM records WHERE id=?',(second['event']['id'],)).fetchone()[0])
    second_outer['raw_id']=json.loads(original)['raw_id']
    store.db.execute('UPDATE records SET body=? WHERE id=?',(json.dumps(second_outer),second['event']['id']));store.db.commit()
    finding={**first,'corroborating_findings':[second]}
    assert not gate(store,finding).allowed


def test_same_raw_content_with_two_labels_and_two_rows_is_not_independent(store):
    first=evidence(store);second=copy.deepcopy(first)
    raw=dict(first['event']);raw.pop('id');raw['source']='audit'
    raw_id=store.add('events',raw)
    body={'raw_id':raw_id,'event':{'event':{'timestamp':raw['timestamp'],'action':'new_process'},'source':{'type':'audit'},'raw':{'data':raw}}}
    rid=store.add('normalized',body);second['event']={**raw,'id':rid};second['rule_id']='OTHER'
    assert not gate(store,{**first,'corroborating_findings':[second]}).allowed


def test_rule_hash_binding_matches_operator_approved_content(store):
    finding=finding_with(store);finding['rule_content_hash']='a'*64
    store.set(POLICY_KEY,{RULE:{'minimum_sources':2,'detection_sha256':'a'*64}})
    assert gate(store,finding).allowed
    finding['rule_content_hash']='b'*64
    auth=gate(store,finding)
    assert not auth.allowed and 'rule_content_binding_mismatch' in auth.reasons


def test_matched_hash_binding_cannot_use_primary_rules_hash(store):
    finding=finding_with(store);finding['rule_id']='PRIMARY';finding['matched_rules']=[RULE,'PRIMARY']
    finding['rule_content_hash']='b'*64;finding['matched_rule_hashes']={RULE:'a'*64,'PRIMARY':'b'*64}
    store.set(POLICY_KEY,{RULE:{'minimum_sources':2,'detection_sha256':'a'*64}})
    assert gate(store,finding).allowed
    finding['matched_rule_hashes'][RULE]='b'*64
    assert not gate(store,finding).allowed


def test_action_target_cannot_be_substituted_after_evidence_is_validated(store):
    finding=finding_with(store);response=ResponseWorker(store,{'response_enabled':True})
    store.set(POLICY_KEY,{RULE:{'minimum_sources':2}})
    response._privd=Mock()
    changed={**finding['event'],'pid':9999}
    result=response.terminate_process(9999,'isolated wrong target',evidence=changed,context={'finding':finding,'rule_id':RULE})
    assert not result['signal_sent'] and 'finding_and_action_target_mismatch' in result['reasons']
    response._privd.assert_not_called()


@pytest.mark.parametrize('method',['kill_process','kill_process_tree','auto_kill','terminate_process'])
def test_every_process_primitive_refuses_missing_required_evidence(store,method):
    finding=evidence(store);store.set(POLICY_KEY,{RULE:{'minimum_sources':2}})
    response=ResponseWorker(store,{'response_enabled':True});response._privd=Mock()
    result=getattr(response,method)(4242,'isolated test',evidence=finding['event'],context={'finding':finding,'rule_id':RULE})
    assert result['status']=='policy_denied' and not result['signal_sent']
    response._privd.assert_not_called()


def test_required_sensor_family_cannot_be_replaced_by_another_valid_sensor(store):
    finding=finding_with(store)
    store.set(POLICY_KEY,{RULE:{'minimum_sources':2,'required_sources':['sys_proc','memory']}})
    auth=gate(store,finding)
    assert not auth.allowed and 'required_sensor_family_not_verified' in auth.reasons


# ---- 2.2.25: activated AI rules may stop a process (Satsuma DB + live /proc, never audit) ----
def _ai_finding(store, monkeypatch, *, action='process_kill', activate=True, source='sys_proc'):
    import copy as _copy
    from satsuma import ai_rule_package as pkg, process_identity as pid_mod, rule_adapter as adapter
    package = proposal('SATSUMA-AI-KILL-TEST-001')
    package['detection']['base_match'] = {'source': 'sys_proc', 'cmd_contains': ['satsuma-test-probe']}
    package['response_proposal'].update(requested_action=action, target_type='process' if action == 'process_kill' else 'none',
                                        required_sources=['sys_proc'], minimum_sources=2)
    package['response_proposal']['detection_sha256'] = pkg.digest(package['detection'])
    adapter._ensure_queue(store)
    store.db.execute("INSERT INTO rule_adapter_queue(rule_id,status,package_json,content_hash,created_at) VALUES(?,?,?,?,?)",
                     (package['rule_id'], 'activated' if activate else 'pending_review', pkg.canonical(package).decode(), pkg.digest(package), time.time()))
    store.db.commit()
    base = evidence(store, source=source)
    finding = {**base, 'rule_id': package['rule_id'], 'ai_package_digest': pkg.digest(package),
               'rule_content_hash': package['response_proposal']['detection_sha256'],
               'response_proposal': package['response_proposal']}
    monkeypatch.setattr(pid_mod, 'read_proc_starttime', lambda pid: 1234)
    monkeypatch.setattr(pid_mod, 'read_proc_exe', lambda pid: '/opt/fixture/tool')
    monkeypatch.setattr(pid_mod, 'read_proc_cmdline', lambda pid: 'satsuma-test-probe --live')
    return finding


def _ai_gate(store, finding):
    cfg = {'response_enabled': True, 'destructive_response_enabled': True, 'destructive_allowed_actions': ['process_kill'],
           'auto_action_process_enabled': True, 'user_enforcement': True}
    return authorize_destructive('process_kill', finding, cfg, {'automated': True, 'pid': 4242, 'user_enforcement': True}, evidence_store=store)


def test_activated_ai_kill_rule_passes_with_satsuma_record_and_live_match(store, monkeypatch):
    from satsuma.ai_enforcement import confirm
    finding = _ai_finding(store, monkeypatch)
    assert confirm(finding, store)['passed']
    assert _ai_gate(store, finding).allowed


def test_ai_kill_refused_when_live_command_no_longer_matches(store, monkeypatch):
    from satsuma import process_identity as pid_mod
    from satsuma.ai_enforcement import confirm
    finding = _ai_finding(store, monkeypatch)
    monkeypatch.setattr(pid_mod, 'read_proc_cmdline', lambda pid: 'harmless-program')
    assert confirm(finding, store)['missing'] == ['live_command_line_no_longer_matches_rule']
    monkeypatch.setattr(pid_mod, 'read_proc_cmdline', lambda pid: 'satsuma-test-probe')
    monkeypatch.setattr(pid_mod, 'read_proc_starttime', lambda pid: 9999)  # pid reused
    assert confirm(finding, store)['missing'] == ['live_process_changed_or_gone']


def test_ai_kill_never_counts_audit_and_needs_activation_and_kill_proposal(store, monkeypatch):
    from satsuma.ai_enforcement import confirm
    audit_only = _ai_finding(store, monkeypatch, source='audit')
    assert 'satsuma_database_confirmation_missing' in confirm(audit_only, store)['missing']
    assert not _ai_gate(store, audit_only).allowed


@pytest.mark.parametrize('kwargs,reason', [({'activate': False}, 'ai_rule_not_operator_activated'),
                                           ({'action': 'record'}, 'ai_proposal_is_not_process_kill')])
def test_ai_kill_refused_without_activation_or_kill_proposal(store, monkeypatch, kwargs, reason):
    from satsuma.ai_enforcement import confirm
    finding = _ai_finding(store, monkeypatch, **kwargs)
    assert confirm(finding, store)['missing'] == [reason]
    assert not _ai_gate(store, finding).allowed
