"""Every brain turn reports how long each phase took, so a slow turn can be traced.

On a loaded machine a turn took 30-41 s for ~3,600 events (against 3 s when quiet), which
is the floor of the delay between a command and the decision about it. Without a
per-phase breakdown nobody can tell which phase is slow.

Her beyin turu her aşamanın ne kadar sürdüğünü bildirir; yavaş tur izlenebilir.
Yük altında bir tur ~3.600 olay için 30-41 sn sürdü (sakinken 3 sn); bu, bir komut ile
ona verilen karar arasındaki gecikmenin tabanıdır. Aşama dökümü olmadan hangisinin
yavaş olduğu bilinemez.
"""
import time
from types import SimpleNamespace

import pytest

import run_satsuma_teams as brain
from satsuma.store import Store


class FakeEngine:
    def refresh_managed_rules(self):
        pass

    def stats(self):
        return {'managed_packages': {}, 'load_errors': [], 'total_rules': 0, 'classifications': {}}


@pytest.fixture
def quiet(tmp_path, monkeypatch):
    store = Store(tmp_path, test=True)
    monkeypatch.setattr(brain, '_run_teams', lambda *a: {'ok': True, 'teams': 4, 'findings_list': []})
    monkeypatch.setattr(brain, '_run_smart_rules', lambda *a: ([], {'processed_events': 0, 'event_errors': 0}))
    monkeypatch.setattr(brain, '_dispatch_safe_actions', lambda p, f: {})
    monkeypatch.setattr(brain, '_automatic_actions', lambda *a: (0, 0, 0))
    monkeypatch.setattr(brain, '_sudo_autoblock', lambda *a: 0)
    monkeypatch.setattr(brain, '_confirmed_actions', lambda *a: ([], []))
    monkeypatch.setattr(brain, 'CorrelationEngine', lambda *a: SimpleNamespace(correlate=lambda: []))
    yield store
    store.close()


def run(store):
    return brain._run_once(store, {'investigation_enabled': False}, None, FakeEngine(), {})


def test_each_phase_is_reported_and_saved_with_the_health(quiet):
    health = run(quiet)
    assert {'followup', 'teams', 'correlation', 'smart_rules', 'safe_dispatch', 'automatic_actions',
            'confirmed_actions'} <= set(health['phase_ms'])
    assert all(type(v) is int and v >= 0 for v in health['phase_ms'].values())
    assert quiet.get('brain.health')['phase_ms'] == health['phase_ms']


def test_a_slow_phase_shows_up_under_its_own_name(quiet, monkeypatch):
    def slow_actions(*a):
        time.sleep(0.06)
        return (0, 0, 0)
    monkeypatch.setattr(brain, '_automatic_actions', slow_actions)
    health = run(quiet)
    assert health['phase_ms']['automatic_actions'] >= 55
    assert health['phase_ms']['teams'] < 55
    assert sum(health['phase_ms'].values()) <= health['elapsed_ms'] + 50


def test_investigation_is_timed_when_it_runs(quiet, monkeypatch):
    finding = {'finding_id': 'f1'}
    monkeypatch.setattr(brain, '_run_teams', lambda *a: {'ok': True, 'teams': 4, 'findings_list': [finding]})
    import satsuma.investigation as inv
    monkeypatch.setattr(inv, 'investigate_and_record', lambda *a: time.sleep(0.05))
    health = brain._run_once(quiet, {'investigation_enabled': True}, None, FakeEngine(), {})
    assert health['phase_ms']['investigation'] >= 45


def test_a_phase_that_fails_is_still_timed_and_does_not_break_the_turn(quiet, monkeypatch):
    def broken(*a):
        time.sleep(0.03)
        raise RuntimeError('boom')
    monkeypatch.setattr(brain, '_run_teams', broken)
    health = run(quiet)
    assert health['phase_ms']['teams'] >= 25 and health['teams'] == 0
