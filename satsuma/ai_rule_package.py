"""Versioned AI proposals: detection and response share an identity and digest.

Response metadata is never sent to an action executor. Existing v1 bundled
rules keep their legacy contract; AI packages are a strict, separate envelope.

Sürümlü yapay zekâ önerileri: tespit ve yanıt aynı kimliği ve özeti paylaşır.
Yanıt bilgisi hiçbir zaman eylem yürütücüye gönderilmez. Mevcut v1 kuralları
eski sözleşmesini korur; yapay zekâ paketleri katı ve ayrı bir zarftır.
"""
import hashlib
import json
import re
import tempfile
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parents[1] / 'schemas/ai-rule-package-v1.schema.json'
AI_ID = re.compile(r'SATSUMA-AI-[A-Z0-9][A-Z0-9_-]{0,79}\Z')
SAFE_ACTIONS = {'record', 'evidence', 'correlation_request'}
MAX_PACKAGE_BYTES = 32768


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def is_ai_finding(finding):
    finding = finding or {}
    ids = [finding.get('rule_id'), *(finding.get('matched_rules') or [])]
    return bool(finding.get('ai_package_digest')) or any(str(i).startswith('SATSUMA-AI-') for i in ids)


MEMORY_ACTIONS = ('memfd_executable', 'deleted_executable', 'anonymous_rwx', 'memfd_mapping', 'executable_code_mismatch',
                  'writable_dir_code_mapping', 'process_traced')


def bind_detection_digest(package):
    """Add the mechanical detection_sha256 a model is told to omit; never changes any other field.

    Modelin yazmaması istenen detection_sha256 özetini ekler; başka hiçbir alanı değiştirmez.
    """
    if (isinstance(package, dict) and isinstance(package.get('detection'), dict)
            and isinstance(package.get('response_proposal'), dict)
            and 'detection_sha256' not in package['response_proposal']):
        # Mechanical only: detection errors are still reported by validate_package.
        package['response_proposal']['detection_sha256'] = digest(package['detection'])
    return package


def observe_only_proposal(package):
    """A conservative response proposal for a reply that sent none: record only, no target.

    Models sometimes omit response_proposal. Satsuma never invents an action;
    it fills only the safe, no-intervention proposal so the detection can be
    reviewed. Model müdahale önerisi göndermezse Satsuma eylem uydurmaz;
    yalnızca kayıt yapan, hedefsiz güvenli öneriyi ekler.
    """
    source = ((package.get('detection') or {}).get('base_match') or {}).get('source')
    return {'schema_version': 1, 'rule_id': package.get('rule_id'), 'rule_version': package.get('rule_version'),
            'requested_action': 'record', 'target_type': 'none', 'execution': 'requires_policy_authorization',
            'evidence_required': True, 'operator_review': True,
            'conditions': ['Model müdahale önerisi göndermedi; Satsuma yalnızca kayıt önerir.'],
            'impact': 'Müdahale yok; yalnızca kayıt ve kanıt.', 'rollback': 'Geri alınacak işlem yok.',
            'minimum_sources': 1,
            'required_sources': [source if source in ('sys_proc', 'audit', 'memory', 'suricata', 'network') else 'sys_proc'],
            'verification_level': 'fresh_independent_same_target_records',
            'policy_preconditions': ['operator_authorization', 'existing_response_policy', 'target_identity',
                                     'protected_target_exemptions']}


def validate_detection(rule):
    from jsonschema import Draft202012Validator
    from .rule_schema import validate_rule
    schema = json.loads(SCHEMA_PATH.read_text())['properties']['detection']
    errors = [f'detection.{".".join(map(str,e.absolute_path))}: {e.validator}'
              for e in Draft202012Validator(schema).iter_errors(rule)]
    if isinstance(rule, dict):
        if not errors:
            errors.extend(validate_rule(rule))
        from .smart_rules import SmartRuleEngine
        # An unrecognised scoring condition is silently false in the engine, so a
        # threshold could never be reached and the rule would catch nothing.
        for item in rule.get('scoring') or []:
            if isinstance(item, dict) and not SmartRuleEngine.supported_condition(item.get('if')):
                errors.append('unsupported_scoring_condition: ' + str(item.get('if'))[:80])
        match = rule.get('base_match') or {}
        if match.get('source') == 'memory':
            # The schema allows one action or a list; every listed action must be implemented.
            actions = match.get('action')
            actions = actions if isinstance(actions, list) else [actions]
            if not actions or any(a not in MEMORY_ACTIONS for a in actions):
                errors.append('memory telemetry action is not implemented')
        elif not any(key in match for key in ('cmd_contains', 'cmd_arg_contains', 'exe_contains', 'file_path', 'parent_contains')):
            errors.append('detection requires a positive, supported indicator matcher')
    return errors[:30]


def validate_package(package):
    from jsonschema import Draft202012Validator
    try:
        if len(canonical(package)) > MAX_PACKAGE_BYTES:
            return ['package_too_large']
    except (ValueError, TypeError):
        return ['invalid_json_data']
    schema = json.loads(SCHEMA_PATH.read_text())
    errors = [f'{".".join(map(str,e.absolute_path))}: {e.validator}'
              for e in Draft202012Validator(schema).iter_errors(package)]
    if errors:
        return errors[:30]
    rule, response = package['detection'], package['response_proposal']
    errors.extend(validate_detection(rule))
    if not package['rule_id'] == rule['id'] == response['rule_id']:
        errors.append('rule_id_mismatch')
    if package['rule_version'] != response['rule_version']:
        errors.append('rule_version_mismatch')
    if response['minimum_sources'] < len(response['required_sources']):
        errors.append('required_source_count_conflicts_with_minimum')
    if response['detection_sha256'] != digest(rule):
        errors.append('detection_digest_mismatch')
    # Only an intervening action needs a matching target; record/evidence/correlation
    # requests execute nothing, so their target type is informational.
    target = {'process_kill': 'process', 'network_isolate': 'network', 'file_quarantine': 'file'}.get(response['requested_action'])
    if target is not None and response['target_type'] != target:
        errors.append('response_target_mismatch')
    return errors


def test_package(package):
    """Match synthetic data only: no Store, subprocess or response dispatch."""
    errors = validate_package(package)
    if errors:
        return {'passed': False, 'errors': errors, 'scope': 'schema'}
    from .smart_rules import SmartRuleEngine
    from .action_contract import canonical_action
    import yaml
    # Candidate validation uses the actual engine matcher, never a fake match.
    # _validate_rule is used on an empty engine to avoid treating unsigned test
    # data as an installed rule, or bypassing the production signed loader.
    with tempfile.TemporaryDirectory(prefix='satsuma-ai-test-') as folder:
        engine = SmartRuleEngine(folder)
        engine.load_errors.clear()
        try:
            rule = engine._validate_rule(package['detection'], Path(folder) / 'candidate.yaml', 1, 'research')
        except Exception:
            return {'passed': False, 'errors': ['engine_rejected_candidate'], 'scope': 'engine'}
        engine.rules = [rule]
        cases = []
        for kind, events in package['test_cases'].items():
            for index, event in enumerate(events):
                results = engine.match(dict(event, id=f'isolated-{kind}-{index}'))
                hit = any(r.get('rule_id') == package['rule_id'] for r in results)
                cases.append({'case': kind, 'index': index, 'passed': hit == (kind == 'positive')})
        repeated = package['test_cases']['positive'][0]
        cases.append({'case': 'repeat_determinism', 'passed': engine.match(repeated) == engine.match(repeated)})
        actions_safe = all(canonical_action(a) in SAFE_ACTIONS for a in package['detection']['actions'])
    return {'passed': actions_safe and all(c['passed'] for c in cases), 'cases': cases,
            'actions_safe': actions_safe, 'scope': 'isolated_engine_no_execution',
            'content_hash': digest(package), 'false_positive_scope': 'supplied_negative_cases_only'}


def evaluate_response(package):
    errors = validate_package(package)
    if errors:
        return {'allowed': False, 'executed': False, 'errors': errors}
    from .response_policy import authorize_destructive
    action = package['response_proposal']['requested_action']
    finding = {'rule_id': package['rule_id'], 'ai_package_digest': digest(package),
               'classification': package['detection']['classification']}
    decision = authorize_destructive(action, finding, {}, {'automated': True})
    return {'requested_action': action, 'rule_id': package['rule_id'], 'executed': False,
            'allowed': False, 'policy_reasons': list(decision.reasons),
            'status': 'proposal_only_operator_policy_evidence_required'}
