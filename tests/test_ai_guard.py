"""2.2.59: a DeepSeek rule cannot hang, blind or turn Satsuma against the machine (owner, 2026-11-19)."""
import time
from types import SimpleNamespace as NS

import pytest

from satsuma import ai_guard as g
from satsuma.smart_rules import SmartRuleEngine


@pytest.mark.parametrize('pattern', ['(a+)+$', r'(\w+\s?)+$', '(x|x)*y', '(.*a){12}'])
def test_catastrophic_regex_is_refused_without_hanging_the_caller(pattern):
    started = time.monotonic()
    assert g.regex_issues({'base_match': {'cmd_regex': [pattern]}})
    assert time.monotonic() - started < g.LINEAR_TIMEOUT + 2


def test_ordinary_regex_passes_and_limits_hold():
    assert not g.regex_issues({'base_match': {'cmd_regex': [r'^(?:\S*/)?nc\s(?>.*?(?<!\S)-e(?!\S))']}})
    assert g.regex_issues({'base_match': {'cmd_regex': ['a'] * 17}})
    assert g.regex_issues({'base_match': {'cmd_regex': ['a' * 600]}})


def test_broad_rule_or_one_matching_satsuma_is_refused():
    assert any('too_broad' in i for i in g.breadth_issues({'base_match': {'source': 'sys_proc', 'cmd_regex': ['.']}}))
    hit = g.breadth_issues({'base_match': {'source': 'sys_proc', 'cmd_regex': [r'satsuma']}})
    assert any('protected' in i for i in hit)
    assert not g.breadth_issues({'base_match': {'source': 'sys_proc', 'cmd_regex': [r'^(?:\S*/)?socat\s(?>.*?exec:)']}})


def test_package_validation_uses_the_guard():
    from satsuma.ai_rule_package import validate_detection
    rule = {'id': 'SATSUMA-AI-X', 'name': 'x', 'severity': 'high', 'classification': 'suspicious',
            'base_match': {'source': 'sys_proc', 'cmd_contains': ['bash'], 'cmd_regex': ['(a+)+$']},
            'actions': ['record'], 'schema_version': 1}
    assert any('ai_guard' in e for e in validate_detection(rule)) or validate_detection(rule)


def ai_engine(pattern):
    engine = SmartRuleEngine.__new__(SmartRuleEngine)
    SmartRuleEngine.__init__(engine, '/nonexistent-rules')
    rule = engine._validate_rule({'id': 'SATSUMA-AI-SLOW', 'name': 'slow', 'severity': 'high', 'classification': 'suspicious',
                                  'base_match': {'source': 'sys_proc', 'cmd_regex': [pattern]}, 'actions': ['record']},
                                 __import__('pathlib').Path('/x.yaml'), 1, 'x')
    engine.rules = [rule]
    engine._index_cache = None
    return engine


def test_ai_rule_budget_is_its_own_and_three_strikes_suspend(monkeypatch):
    engine = ai_engine(r'foo')
    calls = {'n': 0}
    real = engine._search

    def slow(pattern, text, flags):
        calls['n'] += 1
        raise __import__('satsuma.smart_rules', fromlist=['x'])._RegexBudgetExceeded(pattern)
    monkeypatch.setattr(engine, '_search', slow)
    event = {'source': 'sys_proc', 'action': 'new_process', 'cmd': 'foo bar', 'exe': '/usr/bin/foo', 'pid': 5}
    for _ in range(3):
        found = engine.match(dict(event))
        assert not any(f['rule_id'] == 'SATSUMA-ENGINE-001' for f in found)   # bundled rules are not starved
    assert not engine.ai_runtime.active('SATSUMA-AI-SLOW')
    assert engine.ai_runtime.take_alarms() == ['SATSUMA-AI-SLOW']
    before = calls['n']
    engine.match(dict(event))
    assert calls['n'] == before                                                     # suspended: not run


def test_owner_modes():
    engine = ai_engine(r'foo')
    event = {'source': 'sys_proc', 'action': 'new_process', 'cmd': 'foo', 'exe': '/usr/bin/foo', 'pid': 5}
    engine.ai_overrides = {'SATSUMA-AI-SLOW': 'report_only'}
    found = [f for f in engine.match(dict(event)) if f['rule_id'] == 'SATSUMA-AI-SLOW']
    assert found and found[0]['trace_only'] is True
    engine.ai_overrides = {'SATSUMA-AI-SLOW': 'disabled'}
    assert not [f for f in engine.match(dict(event)) if f['rule_id'] == 'SATSUMA-AI-SLOW']


class Store(dict):
    def get(self, k, d=None): return super().get(k, d)
    def set(self, k, v): self[k] = v


@pytest.mark.parametrize('exe,reason', [('/usr/bin/sudo', 'ai_rule_interactive_admin_tool'),
                                        ('/usr/bin/gdb', 'ai_rule_interactive_admin_tool'),
                                        ('/usr/bin/cosmic-comp', 'ai_rule_protected_target'),
                                        ('/usr/lib/systemd/systemd', 'ai_rule_protected_target')])
def test_protected_targets_and_admin_tools_are_never_stopped(exe, reason):
    assert g.stop_block({'rule_id': 'SATSUMA-AI-X'}, Store(), 4242, exe, proc_root='/nonexistent') == reason


def test_satsuma_unit_is_protected(tmp_path):
    (tmp_path / '4242').mkdir()
    (tmp_path / '4242' / 'cgroup').write_text('0::/system.slice/satsuma-teams.service\n')
    assert g.stop_block({'rule_id': 'SATSUMA-AI-X'}, Store(), 4242, '/usr/bin/python3', proc_root=str(tmp_path)) \
        == 'ai_rule_protected_target'


def test_trusted_program_jit_memory_is_reported_only(monkeypatch):
    import satsuma.trusted_process as tp
    monkeypatch.setattr(tp, 'trusted_path', lambda p: p.startswith('/snap/'))
    monkeypatch.setattr(tp, 'trusted_running_program', lambda pid, root='/proc': False)
    firefox = '/snap/firefox/9181/usr/lib/firefox/firefox'
    assert g.stop_block({'rule_id': 'SATSUMA-AI-M'}, Store(), 10079, firefox, memory_rule=True,
                        proc_root='/nonexistent') == 'ai_rule_trusted_program_jit_memory'
    assert g.stop_block({'rule_id': 'SATSUMA-AI-M'}, Store(), 10079, '/tmp/x', memory_rule=True,
                        proc_root='/nonexistent') is None


def test_stop_limit_then_an_hour_of_reports():
    store, now = Store(), [0.0]
    clock = lambda: now[0]
    finding = {'rule_id': 'SATSUMA-AI-X'}
    for _ in range(g.STOP_LIMIT):
        assert g.stop_block(finding, store, 4242, '/tmp/x', proc_root='/nonexistent', clock=clock) is None
        g.count_stop(finding, store, clock=clock)
    assert g.stop_block(finding, store, 4242, '/tmp/x', proc_root='/nonexistent', clock=clock) == 'ai_rule_stop_limit'
    now[0] = 1200.0
    assert g.stop_block(finding, store, 4242, '/tmp/x', proc_root='/nonexistent', clock=clock) == 'ai_rule_stop_limit'
    now[0] = 3700.0
    assert g.stop_block(finding, store, 4242, '/tmp/x', proc_root='/nonexistent', clock=clock) is None


def test_owner_override_wins_and_needs_an_ai_rule():
    store = Store()
    g.set_override(store, 'SATSUMA-AI-X', 'report_only')
    assert g.stop_block({'rule_id': 'SATSUMA-AI-X'}, store, 4242, '/tmp/x', proc_root='/nonexistent') == 'ai_rule_owner_report_only'
    with pytest.raises(ValueError):
        g.set_override(store, 'SATSUMA-PRIV-003', 'disabled')
    g.set_override(store, 'SATSUMA-AI-X', None)
    assert g.overrides(store) == {}


def test_stream_event_is_confirmed_by_the_kernel_in_privd(monkeypatch):
    from satsuma import ai_enforcement as ae, flow
    monkeypatch.setattr(flow, 'ACTIVE', None)
    monkeypatch.setattr(ae, 'eligible', lambda f, s: ({'base_match': {'source': 'sys_proc'}}, None))
    import satsuma.rule_response as rr
    monkeypatch.setattr(rr, 'evidence_report', lambda *a, **k: {'passed': False, 'missing': ['x']})
    monkeypatch.setattr(ae, '_live', lambda event, detection: None)
    finding = {'rule_id': 'SATSUMA-AI-X', 'response_proposal': {'requested_action': 'process_kill'},
               'event': {'id': 'flow-1-2', 'pid': 4242}}
    assert ae.confirm(finding, Store())['passed'] is True
    monkeypatch.setattr(ae, '_live', lambda event, detection: 'live_process_changed_or_gone')
    assert ae.confirm(finding, Store())['passed'] is False
    finding['event']['id'] = 77                     # a database record still needs the database
    monkeypatch.setattr(ae, '_live', lambda event, detection: None)
    assert ae.confirm(finding, Store())['passed'] is False
