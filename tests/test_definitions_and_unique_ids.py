"""Definitions folder, unique rule ids and valid stop proposals (2.2.24).

Tanım klasörü, benzersiz kural kimlikleri ve geçerli durdurma önerileri (2.2.24).
"""
import copy
import json
import os
import shutil
from pathlib import Path

import pytest
import yaml

from satsuma import ai_rule_package as pkg, definitions, rule_adapter as adapter
from satsuma.store import Store

ROOT = Path(__file__).parents[1]
FIELD = json.loads((ROOT / 'tests/fixtures/deepseek-field-revshell-20261104.json').read_text())
FIELD['detection']['base_match']['cmd_arg_contains'] += ['/bin/sh', '/bin/bash']
FIELD['response_proposal'].pop('detection_sha256')


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / 'data', test=True)
    yield s
    s.close()


def package():
    return pkg.bind_detection_digest(copy.deepcopy(FIELD))


def test_same_id_new_content_gets_a_unique_id_and_identical_content_is_reported(store):
    first = package()
    assert adapter.queue_package(store, first, authorized=True, reviewer=1000)['queued']
    second = package()
    second['detection']['base_match']['cmd_arg_contains'].append('fsockopen(')
    second['response_proposal'].pop('detection_sha256'); pkg.bind_detection_digest(second)
    result = adapter.queue_package(store, second, authorized=True, reviewer=1000)
    assert result['queued'] and result['renamed'] == 'renamed_from:' + FIELD['rule_id']
    assert result['rule_id'].startswith(FIELD['rule_id'] + '-') and pkg.AI_ID.fullmatch(result['rule_id'])
    assert result['package']['detection']['id'] == result['package']['response_proposal']['rule_id'] == result['rule_id']
    assert pkg.validate_package(result['package']) == []
    assert adapter.queue_package(store, package(), authorized=True)['error'] == 'identical_rule_already_present'


def test_a_valid_process_kill_proposal_passes(store):
    p = package()
    p['response_proposal'].update(requested_action='process_kill', target_type='process',
                                  required_sources=['sys_proc', 'audit'], minimum_sources=2)
    assert pkg.validate_package(p) == []


def test_prompt_describes_the_stop_proposal_and_the_definition(tmp_path, monkeypatch):
    from satsuma import deepseek_client as client
    folder = tmp_path / 'tanim'; folder.mkdir()
    for name in definitions.FILES.values():
        shutil.copy(ROOT / 'data/tanim' / name, folder / name)
    monkeypatch.setattr(definitions, 'DIRECTORY', folder)
    monkeypatch.setattr(definitions, '_read', lambda path, owner=0, real=definitions._read: real(path, os.getuid()))
    sent = {}
    monkeypatch.setattr(client, '_request', lambda prompt, config, confirmed, **k: sent.setdefault('p', prompt))
    client.generate_rule('T1562.001', 'defense_evasion', adapter.SCHEMA_HINT, {}, confirmed=True)
    assert 'process_kill, target_type process' in sent['p']
    assert 'T1562.001 was revoked and replaced by T1685' in sent['p']


def test_definitions_are_read_only_from_trusted_files(tmp_path):
    folder = tmp_path / 'tanim'; folder.mkdir()
    for name in definitions.FILES.values():
        shutil.copy(ROOT / 'data/tanim' / name, folder / name)
    uid = os.getuid()
    assert definitions.technique('T1059', folder, uid)['name'] == 'Command and Scripting Interpreter'
    moved = definitions.technique('T1562.001', folder, uid)
    assert moved['id'] == 'T1685' and moved['revoked_from'] == 'T1562.001'
    assert definitions.kev('CVE-0000-0000', folder, uid) is None
    counts = definitions.status(folder, uid)
    assert counts['techniques'] == 706 and counts['kev'] == 1767
    os.chmod(folder / definitions.FILES['techniques'], 0o666)  # writable by others: ignored
    assert definitions.technique('T1059', folder, uid) is None


def test_shipped_definition_files_are_valid():
    for name in definitions.FILES.values():
        data = yaml.safe_load((ROOT / 'data/tanim' / name).read_text())
        assert data['schema'] == 'satsuma/definitions-v1' and data['count'] > 0
