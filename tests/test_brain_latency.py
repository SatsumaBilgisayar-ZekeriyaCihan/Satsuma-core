"""Stopping decisions are not held behind investigation or the round timer (2.2.32).

Field 2026-11-04: decisions came up to 38 minutes after the events.

Durdurma kararları incelemenin ya da tur bekleme süresinin arkasında kalmaz.
"""
from pathlib import Path

SOURCE = (Path(__file__).parents[1] / 'run_satsuma_teams.py').read_text()


def test_actions_run_before_investigation():
    for name, batch in (('def _run_once(', 'all_findings'), ('def _flow_tick(', 'fresh')):
        body = SOURCE[SOURCE.index(name):]
        body = body[:body.index('\ndef ', 1)]
        assert body.index(f"_automatic_actions(store, config, {batch})") < body.index("investigate_and_record(store, finding, config)")
        assert body.index(f"_confirmed_actions(pipeline, {batch})") < body.index("investigate_and_record(store, finding, config)")


def test_backlog_skips_the_wait():
    loop = SOURCE[SOURCE.index('def main():'):]
    assert "get('backlog_remaining')" in loop
    assert loop.index("backlog_remaining") < loop.index("time.monotonic() - start < interval")
    assert 'health = None' in loop


def test_team_collectors_do_not_hold_every_rule_round(monkeypatch, tmp_path):
    import run_satsuma_teams as brain
    calls = []
    monkeypatch.setattr(brain, '_run_teams', lambda *a: calls.append('teams') or {'ok': True, 'findings_list': []})
    monkeypatch.setattr(brain, '_run_smart_rules', lambda store, engine, cursor: (calls.append('smart') or [], {'processed_events': 0, 'event_errors': 0, 'cursor_start': 0, 'cursor_end': 0}))
    class Store:
        def __init__(self): self.state = {}
        def get(self, k, d=None): return self.state.get(k, d)
        def set(self, k, v): self.state[k] = v
        def add(self, *a): pass
    class Engine:
        def refresh_managed_rules(self): pass
        def stats(self): return {}
    monkeypatch.setattr('satsuma.process_followup.tick', lambda store: None)
    monkeypatch.setattr(brain, '_dispatch_safe_actions', lambda *a: {})
    monkeypatch.setattr(brain, '_automatic_actions', lambda *a: (0, 0, 0))
    monkeypatch.setattr(brain, '_sudo_autoblock', lambda *a: 0)
    monkeypatch.setattr(brain, '_confirmed_actions', lambda *a: ([], 0))
    brain._run_once(Store(), {'investigation_enabled': False}, object(), Engine(), {}, run_teams=False)
    assert calls == ['smart']
