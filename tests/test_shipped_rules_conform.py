"""Every shipped rule conforms to both rule validators and the response catalog.

Gönderilen her kural iki kural doğrulayıcısına ve müdahale kataloğuna uyar.
"""
import glob
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from satsuma.rule_schema import validate_rule
from satsuma.smart_rules import SmartRuleEngine

ROOT = Path(__file__).parents[1]


def shipped_rules():
    for path in sorted(glob.glob(str(ROOT / 'rules/*.yaml'))):
        data = yaml.safe_load(Path(path).read_text())
        for rule in (data if isinstance(data, list) else data.get('rules', [])):
            yield Path(path).name, rule


def test_every_v1_rule_passes_the_json_schema_and_the_stdlib_validator():
    """rule-v1 covers schema_version 1 rules; older baseline rules are checked by the engine loader below."""
    schema = json.loads((ROOT / 'schemas/rule-v1.schema.json').read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    problems, checked = [], 0
    for name, rule in shipped_rules():
        if rule.get('schema_version') != 1:
            continue
        checked += 1
        errors = [e.message for e in validator.iter_errors(rule)] + list(validate_rule(rule))
        if errors:
            problems.append((name, rule.get('id'), errors[:3]))
    assert checked > 100 and problems == []


def test_engine_loads_all_rules_and_catalog_binds_each_one():
    engine = SmartRuleEngine()
    assert not engine.load_errors
    loaded = {r['_id']: r.get('_content_hash') for r in engine.rules}
    ids = [rule['id'] for _, rule in shipped_rules()]
    assert len(ids) == len(set(ids)) == len(loaded)
    catalog = {r['rule_id']: r['detection_sha256']
               for r in json.loads((ROOT / 'schemas/rule-response-catalog-v1.json').read_text())['rules']}
    assert catalog == loaded


def test_every_schema_file_is_a_valid_json_schema():
    for path in list((ROOT / 'schemas').glob('*.schema.json')) + list((ROOT / 'satsuma_engine/schemas').glob('*.json')):
        Draft202012Validator.check_schema(json.loads(path.read_text()))
