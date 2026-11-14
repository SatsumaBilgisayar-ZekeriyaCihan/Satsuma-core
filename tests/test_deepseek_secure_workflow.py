"""Isolated AI lifecycle. Real GPG uses a disposable test key, never Fedora keys."""
import copy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import uuid
from unittest.mock import Mock

import pytest
import yaml
from satsuma import ai_rule_package as pkg, rule_adapter as adapter, rule_signing as signing
from satsuma import deepseek_client as client
from satsuma.store import Store
from satsuma.smart_rules import SmartRuleEngine


def proposal(rule_id='SATSUMA-AI-TEST-001'):
    rule = {'schema_version':1, 'id':rule_id,'name':'Isolated probe', 'severity':'high',
            'classification':'suspicious','confidence':'medium','implementation_status':'CURRENT_TELEMETRY',
            'proof_level':'PUBLIC_RESEARCH','base_match':{'source':'sys_proc','cmd_contains':['satsuma-test-probe']},
            'actions':['record','evidence']}
    return {'package_version':1,'rule_id':rule_id,'rule_version':1,'detection':rule,
            'response_proposal':{'schema_version':1,'rule_id':rule_id,'rule_version':1,
                'detection_sha256':pkg.digest(rule),'requested_action':'process_kill','target_type':'process',
                'execution':'requires_policy_authorization','evidence_required':True,'operator_review':True,
                'minimum_sources':2,'required_sources':['sys_proc','audit'],'verification_level':'fresh_independent_same_target_records',
                'policy_preconditions':['operator_authorization','existing_response_policy','target_identity','protected_target_exemptions'],
                'conditions':['fresh process identity and independent evidence'],'impact':'Process could stop',
                'rollback':'Process termination cannot be undone'},
            'test_cases':{'positive':[{'source':'sys_proc','cmd':'satsuma-test-probe --fixture'}],
                          'negative':[{'source':'sys_proc','cmd':'harmless-fixture'}],
                          'wrong_source':[{'source':'dns','cmd':'satsuma-test-probe --fixture'}]}}


@pytest.fixture
def store(tmp_path):
    value=Store(tmp_path/'data',test=True)
    yield value
    value.close()


@pytest.fixture(scope='module')
def gpg_key(tmp_path_factory):
    root=tmp_path_factory.mktemp('ai-test-gpg');home=root/'home';home.mkdir(mode=0o700)
    def run(*args):
        return subprocess.run(['/usr/bin/gpg','--no-options','--homedir',str(home),'--batch',
                               '--pinentry-mode','loopback','--passphrase','',*args],
                              check=True,capture_output=True,timeout=30)
    run('--quick-generate-key','Satsuma isolated test <fixture@example.invalid>','ed25519','sign','0')
    public=root/'trusted.gpg';public.write_bytes(run('--export').stdout)
    def sign(payload):
        data=root/'payload.json';data.write_bytes(payload)
        return run('--armor','--detach-sign','--output','-',str(data)).stdout.decode()
    yield public,sign
    subprocess.run(['/usr/bin/gpgconf','--homedir',str(home),'--kill','gpg-agent'],capture_output=True)


@pytest.fixture
def trusted(tmp_path, monkeypatch, gpg_key):
    public,sign=gpg_key
    monkeypatch.setattr(signing,'TRUSTED_PUBLIC_KEY',public)
    monkeypatch.setattr(signing,'TRUSTED_OWNER',os.getuid())
    active=tmp_path/'active'
    monkeypatch.setattr(signing,'MANAGED_RULES_DIR',active)
    monkeypatch.setattr(adapter,'ACTIVE_RULES_DIR',active)
    return sign,active


def queued(store, package=None):
    package=package or proposal()
    assert adapter.queue_package(store,package,authorized=True,reviewer=1000)['queued']
    return package


def approved(store, package=None):
    package=queued(store,package)
    result=adapter.approve_rule(store,package['rule_id'],authorized=True,reviewer=1000)
    assert result['approved'] and not result['activated']
    return package,result['signing_payload']


def test_package_and_real_engine_functional_cases():
    package=proposal()
    assert pkg.validate_package(package)==[]
    result=pkg.test_package(package)
    assert result['passed'] and len(result['cases'])==4
    assert not pkg.evaluate_response(package)['allowed']
    assert not pkg.evaluate_response(package)['executed']


@pytest.mark.parametrize('change', ['identity','digest','missing_match','source','ticket','unsafe','extra','response_missing','conditions','matcher','type'])
def test_invalid_or_unsafe_generated_output_is_rejected(change):
    package=proposal()
    if change=='identity':package['response_proposal']['rule_id']='OTHER'
    if change=='digest':package['response_proposal']['detection_sha256']='0'*64
    if change=='missing_match':del package['detection']['base_match']
    if change=='source':package['detection']['base_match']['source']='unsupported'
    if change=='ticket':package['detection']['actions']=['ticket']
    if change=='unsafe':package['detection']['actions']=['process_kill']
    if change=='extra':package['command']='execute-me'
    if change=='response_missing':del package['response_proposal']
    if change=='conditions':package['response_proposal']['evidence_required']=False
    if change=='matcher':package['detection']['base_match']['cmd_contains']=[]
    if change=='type':package['detection']['severity']=[]
    assert pkg.validate_package(package)
    assert not pkg.test_package(package)['passed']


def test_wrong_command_and_false_positive_fail_functional_test():
    package=proposal();package['test_cases']['negative']=package['test_cases']['positive']
    assert not pkg.test_package(package)['passed']
    package=proposal();package['test_cases']['positive'][0]['cmd']='wrong-indicator'
    assert not pkg.test_package(package)['passed']


def test_sanitizer_never_invents_conditions_or_hides_unsafe_actions():
    rule={'name':'not-a-command','actions':['ticket','process_kill']}
    assert adapter._sanitize_rule(rule)==rule
    assert adapter.validate_generated_rule(rule)


def test_read_list_does_not_create_tables_or_commit(store):
    before=store.db.total_changes
    assert adapter.list_pending(store)==[] and adapter.list_rules(store)==[]
    assert not store.db.in_transaction and store.db.total_changes==before
    assert not store.db.execute("SELECT 1 FROM sqlite_master WHERE name='rule_adapter_queue'").fetchone()
    adapter._ensure_queue(store)
    ro=sqlite3.connect(f'file:{store.path}?mode=ro',uri=True)
    try:
        ro.execute('PRAGMA query_only=ON')
        assert adapter.list_pending(type('ReadOnly',(),{'db':ro})())==[]
    finally:ro.close()


def test_duplicate_submission_keeps_approval_history(store):
    package,payload=approved(store)
    before=store.db.execute('SELECT * FROM rule_adapter_queue').fetchall()
    assert not adapter.queue_package(store,package,authorized=True)['queued']
    assert before==store.db.execute('SELECT * FROM rule_adapter_queue').fetchall()
    assert store.db.execute('SELECT count(*) FROM rule_adapter_history').fetchone()[0]==2


def test_rejected_rule_cannot_be_approved_or_activated(store):
    package=queued(store)
    assert adapter.reject_rule(store,package['rule_id'],authorized=True,reviewer=1000,reason='review failed')['rejected']
    with pytest.raises(ValueError):adapter.approve_rule(store,package['rule_id'],authorized=True,reviewer=1000)
    assert not adapter.activate_rule(store,package['rule_id'],authorized=True)['activated']
    assert adapter._row(store,package['rule_id'])['status']=='rejected'


def test_unauthorized_approval_and_unsigned_activation_refused(store):
    package=queued(store)
    with pytest.raises(PermissionError):adapter.approve_rule(store,package['rule_id'])
    assert not adapter.activate_rule(store,package['rule_id'],authorized=True)['activated']
    assert adapter._row(store,package['rule_id'])['status']=='pending_review'


def test_real_gpg_signed_activation_and_loader(store,trusted):
    sign,active=trusted;package,payload=approved(store)
    signature=sign(payload.encode())
    assert adapter.verify_rule_signature(store,package['rule_id'],signature,authorized=True)['valid']
    result=adapter.activate_rule(store,package['rule_id'],authorized=True,reviewer=1000)
    assert result['activated'] and result['loader_verified'] and not result['runtime_loaded']
    engine=SmartRuleEngine(active)
    assert not engine.load_errors
    findings=engine.match(package['test_cases']['positive'][0])
    assert findings[0]['rule_id']==package['rule_id']
    assert findings[0]['ai_package_digest']==pkg.digest(package)
    assert findings[0]['rule_content_hash']==package['response_proposal']['detection_sha256']
    assert findings[0]['rule_content_hash']==pkg.digest(json.loads(payload)['package']['detection'])
    assert findings[0]['response_proposal']['requested_action']=='process_kill'
    store.set('deepseek_runtime',{'updated_at':time.time(),'loaded':{package['rule_id']:pkg.digest(package)}})
    assert adapter.activation_status(store,package['rule_id'])['runtime_loaded']
    assert not adapter.activation_status(store,package['rule_id'])['intervention_executed']


def test_signature_covers_response_and_cannot_be_replaced(store,trusted):
    sign,_=trusted;package,payload=approved(store)
    signature=sign(payload.encode())
    altered=json.loads(payload);altered['package']['response_proposal']['impact']='Changed response'
    assert not signing.verify_payload(pkg.canonical(altered),signature)['valid']
    assert not adapter.verify_rule_signature(store,package['rule_id'],'not-a-signature',authorized=True)['valid']
    assert adapter._row(store,package['rule_id'])['status']=='signing_failed'
    assert adapter.verify_rule_signature(store,package['rule_id'],signature,authorized=True)['valid']
    with pytest.raises(ValueError):adapter.approve_rule(store,package['rule_id'],authorized=True,reviewer=1000)


def test_tampered_queue_is_refused_before_activation(store,trusted):
    sign,_=trusted;package,payload=approved(store)
    adapter.verify_rule_signature(store,package['rule_id'],sign(payload.encode()),authorized=True)
    tampered=copy.deepcopy(package);tampered['response_proposal']['impact']='changed'
    store.db.execute('UPDATE rule_adapter_queue SET package_json=?',(json.dumps(tampered),));store.db.commit()
    assert not adapter.activate_rule(store,package['rule_id'],authorized=True)['activated']
    assert adapter._row(store,package['rule_id'])['status']=='activation_failed'


def test_filesystem_failure_never_records_success(store,trusted,monkeypatch):
    sign,active=trusted;package,payload=approved(store)
    adapter.verify_rule_signature(store,package['rule_id'],sign(payload.encode()),authorized=True)
    monkeypatch.setattr(adapter.os,'rename',Mock(side_effect=OSError('disk failure')))
    assert not adapter.activate_rule(store,package['rule_id'],authorized=True)['activated']
    assert adapter._row(store,package['rule_id'])['status']=='activation_failed'
    assert not (active/package['rule_id']).exists()
    assert not list(active.glob('.staging-*'))


@pytest.mark.parametrize('rule_id',['../../escape','/absolute','SATSUMA-AI-../ESCAPE','SATSUMA-PERSIST-001'])
def test_path_traversal_and_baseline_ids_refused(store,rule_id):
    assert not adapter.queue_package(store,proposal(rule_id),authorized=True)['queued']


def test_unsigned_and_changed_yaml_rejected_on_actual_loader(tmp_path):
    (tmp_path/'candidate.yaml').write_text(yaml.safe_dump([proposal()['detection']]))
    engine=SmartRuleEngine(tmp_path)
    assert not engine.rules and engine.load_errors


def test_signed_yaml_tamper_rejected(store,trusted):
    sign,active=trusted;package,payload=approved(store)
    adapter.verify_rule_signature(store,package['rule_id'],sign(payload.encode()),authorized=True)
    assert adapter.activate_rule(store,package['rule_id'],authorized=True)['activated']
    path=active/package['rule_id']/'rule.yaml'
    changed=copy.deepcopy(package['detection']);changed['actions']=['ticket']
    path.write_text(yaml.safe_dump([changed]))
    assert not SmartRuleEngine(active).rules


def test_ai_cannot_reach_auto_action_or_destructive_gate(store):
    from satsuma.action_contract import SafeActionBroker
    from satsuma.auto_action import AutoActionEngine
    from satsuma.response_policy import authorize_destructive
    finding={'rule_id':proposal()['rule_id'],'classification':'confirmed','event':{'pid':42}}
    assert SafeActionBroker(store,{}).dispatch('ticket',{'finding':finding})['status']=='blocked_ai_action'
    assert AutoActionEngine(store,{}).process(finding)['executed'] is False
    for action in ('process_kill','network_isolate','file_quarantine'):
        assert not authorize_destructive(action,finding,{'destructive_response_enabled':True},{'automated':True}).allowed


def test_operator_session_binding_consent_and_idempotency(store,monkeypatch):
    from satsuma.operator_service import OperatorController
    auth=Mock();auth.validate_session.return_value=True
    controller=OperatorController(store,auth=auth,config={'deepseek_enabled':True,'rule_adapter_enabled':True})
    controller.owners['fixture-session']=1000
    params={'token':'fixture-session','request_id':uuid.uuid4().hex,'confirmed':True}
    with pytest.raises(PermissionError):controller.dispatch(1001,'deepseek_test_connection',params)
    call=Mock(return_value={'connected':True});monkeypatch.setattr(client,'connection_test',call)
    first=controller.dispatch(1000,'deepseek_test_connection',params)
    assert first==controller.dispatch(1000,'deepseek_test_connection',params)
    assert call.call_count==1
    no_consent={**params,'request_id':uuid.uuid4().hex,'confirmed':False}
    with pytest.raises(ValueError):controller.dispatch(1000,'deepseek_test_connection',no_consent)
    with pytest.raises(ValueError):controller.dispatch(1000,'deepseek_test_connection',{**params,'request_id':uuid.uuid4().hex})
    assert call.call_count==1


@pytest.mark.parametrize('mutate', ['bool_version','list_severity','empty_match_values','dict_action','scoring_type','threshold_type'])
def test_stdlib_v1_validator_and_json_schema_both_reject_malformed_new_rules(mutate):
    from satsuma.rule_schema import validate_rule
    from jsonschema import Draft202012Validator
    rule=proposal()['detection']
    if mutate=='bool_version':rule['schema_version']=True
    if mutate=='list_severity':rule['severity']=[]
    if mutate=='empty_match_values':rule['base_match']['cmd_contains']=[]
    if mutate=='dict_action':rule['actions']=[{'always':'record'}]
    if mutate=='scoring_type':rule['scoring']=[{'if':'uid == 0','add':'invalid'}]
    if mutate=='threshold_type':rule['threshold']='invalid'
    schema=json.loads((Path(__file__).resolve().parents[1]/'schemas/rule-v1.schema.json').read_text())
    assert list(Draft202012Validator(schema).iter_errors(rule))
    assert validate_rule(rule)


def test_concurrent_approvals_have_one_winner_and_preserve_history(store):
    import threading
    package=queued(store)
    barrier=threading.Barrier(2);results=[]
    def approve():
        local=Store(store.directory,test=True)
        try:
            barrier.wait()
            try:results.append(adapter.approve_rule(local,package['rule_id'],authorized=True,reviewer=1000)['approved'])
            except ValueError:results.append(False)
        finally:local.close()
    workers=[threading.Thread(target=approve) for _ in range(2)]
    for worker in workers:worker.start()
    for worker in workers:worker.join(10)
    assert results.count(True)==1 and results.count(False)==1
    assert store.db.execute("SELECT count(*) FROM rule_adapter_history WHERE operation='approve'").fetchone()[0]==1


def test_activated_signature_recheck_does_not_rewrite_approval_history(store,trusted):
    sign,active=trusted;package,payload=approved(store)
    signature=sign(payload.encode())
    adapter.verify_rule_signature(store,package['rule_id'],signature,authorized=True)
    assert adapter.activate_rule(store,package['rule_id'],authorized=True)['activated']
    before=adapter._row(store,package['rule_id'])
    result=adapter.verify_rule_signature(store,package['rule_id'],'bad signature',authorized=True)
    after=adapter._row(store,package['rule_id'])
    assert not result['valid'] and after['status']=='activated'
    assert after['signature']==before['signature'] and after['approved_payload']==before['approved_payload']
    assert adapter.activation_status(store,package['rule_id'])['installed_integrity_valid']
