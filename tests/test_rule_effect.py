"""2.2.49: the rules page says what a rule does and what the stops really did.

Field question 2026-11-19 "why don't the rules stop?": the page counted only
kill actions written in rule files (none) and said "0 can stop".
"""
import json
import sqlite3
import time

import pytest

from satsuma import rule_effect


def test_effect_follows_the_central_policy_and_the_ai_proposal():
    attack = {'id': 'SATSUMA-C2-001', 'classification': 'likely', 'severity': 'critical'}
    indicator = {'id': 'SATSUMA-COLL-002', 'classification': 'indicator', 'severity': 'medium'}
    assert rule_effect.effect(attack, True) == (True, 'Programı durdurur')
    stops, text = rule_effect.effect(attack, False)
    assert not stops and 'otomatik durdurma kapalı' in text
    stops, text = rule_effect.effect(indicator, True)
    assert not stops and 'bilerek durdurulmaz' in text
    ai_kill = {'id': 'SATSUMA-AI-X', '_ai_package_digest': 'd', '_response_proposal': {'requested_action': 'process_kill'}}
    ai_watch = {'id': 'SATSUMA-AI-Y', '_ai_package_digest': 'd', '_response_proposal': {'requested_action': 'observe_only'}}
    assert rule_effect.effect(ai_kill, True)[0] and not rule_effect.effect(ai_watch, True)[0]


def test_outcomes_tell_a_stop_from_a_program_that_was_already_gone():
    records = [
        {'action': 'process.terminate', 'status': 'terminated', 'exit_verified': True},
        {'status': 'process_killed'},
        {'status': 'identity_verification_failed', 'reason': 'live_process_not_found'},
        {'status': 'identity_verification_failed', 'reason': 'starttime_mismatch'},
        {'action': 'process.terminate', 'status': 'identity_recheck_failed'},
        {'status': 'policy_denied'},
        {'action': 'process.terminate', 'status': 'termination_pending', 'exit_verified': False},
        {'action': 'process.terminate', 'status': 'terminated', 'source': 'unhide'},     # the user's own button
        {'status': 'file_quarantined'},
    ]
    assert rule_effect.stop_summary(records) == {'stopped': 2, 'gone': 3, 'denied': 1, 'failed': 1}


def test_summary_text_is_plain():
    text = rule_effect.summary_text(251, 136, 115, True, {'stopped': 3, 'gone': 12, 'denied': 0, 'failed': 0}, ai_total=20)
    assert text == ('251 etkin kural · 136 tanesi eşleşince programı durdurur · 115 tanesi yalnızca bildirir. '
                    'Otomatik durdurma: açık. DeepSeek kuralı: 20. Son 24 saat: 3 program durduruldu, '
                    '12 eşleşmede program sinyal gitmeden zaten kapanmıştı.')
    assert 'KAPALI' in rule_effect.summary_text(1, 0, 1, False, None)


def test_reader_counts_real_stops_and_follows_the_switch(tmp_path, monkeypatch):
    from satsuma import dashboard_api
    from contextlib import contextmanager
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE records (id INTEGER PRIMARY KEY, created REAL, kind TEXT, body TEXT)')
    db.execute('CREATE TABLE state (key TEXT PRIMARY KEY, value TEXT)')
    now = time.time()
    for body in ({'action': 'process.terminate', 'status': 'terminated', 'exit_verified': True},
                 {'status': 'identity_verification_failed', 'reason': 'live_process_not_found'}):
        db.execute('INSERT INTO records(created,kind,body) VALUES(?,?,?)', (now, 'actions', json.dumps(body)))
    db.execute('INSERT INTO records(created,kind,body) VALUES(?,?,?)', (now - 90000, 'actions', json.dumps({'status': 'process_killed'})))

    @contextmanager
    def connect():
        yield db
    states = {}
    monkeypatch.setattr(dashboard_api, '_connect', connect)
    monkeypatch.setattr(dashboard_api, '_state', lambda conn, key, default=None: states.get(key, default))
    report = dashboard_api.m_rules()
    assert report['enforcement_enabled'] is True and report['stop_total'] == 183  # 2.2.54: +47 coverage_gaps rules that stop
    assert report['stop_outcomes_24h'] == {'stopped': 1, 'gone': 1, 'denied': 0, 'failed': 0}
    assert '1 program durduruldu, 1 eşleşmede program sinyal gitmeden zaten kapanmıştı' in report['summary_text']
    row = next(r for r in report['rules'] if r['rule_id'] == 'SATSUMA-C2-001')
    assert row['what_happens'] == 'Programı durdurur' and row['severity_label'] == 'Kritik'
    states['enforcement_policy'] = {'enabled': False}
    off = dashboard_api.m_rules()
    assert off['stop_total'] == 0 and 'KAPALI' in off['summary_text']


def test_rules_page_shows_the_plain_columns():
    pytest.importorskip('PyQt6.QtWidgets')
    from satsuma.dashboard_qt.panels.rules import RulesPanel
    assert [c for c, _ in RulesPanel.COLUMNS][:2] == ['Kural', 'Ne yapar']
