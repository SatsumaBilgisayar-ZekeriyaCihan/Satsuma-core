"""SIGTERM ends the brain cycle early instead of waiting for it.

Field log 2026-10-25: "Stopping satsuma-teams" at 18:42:46, exit at 18:43:07
after one more full cycle; self-health saw it stuck in "deactivating".

SIGTERM beyin turunu beklemeden erken bitirir.

Saha kaydı 2026-10-25: 18:42:46'da "Stopping satsuma-teams", çıkış bir tam
tur daha sonra 18:43:07'de; self-health onu "deactivating"de takılı gördü.
"""
import os
import signal
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1]))

from satsuma import shutdown
from satsuma.correlation_manager import CorrelationManager
from satsuma.store import Store
from satsuma.teams.base import BaseTeamLead
import run_satsuma_teams as brain


@pytest.fixture(autouse=True)
def _clear():
    shutdown.clear()
    yield
    shutdown.clear()


class Team:
    def __init__(self, name, calls, stop=False):
        self.name, self.calls, self.stop = name, calls, stop

    def tick(self):
        self.calls.append(self.name)
        if self.stop:
            os.kill(os.getpid(), signal.SIGTERM)
        return {'ok': True, 'findings': 0, 'findings_list': []}


def test_sigterm_during_a_team_skips_the_remaining_teams(tmp_path):
    previous = signal.signal(signal.SIGTERM, lambda *_: shutdown.request())
    store = Store(tmp_path, test=True)
    try:
        calls = []
        manager = CorrelationManager(store, {})
        for team in (Team('host', calls, stop=True), Team('identity', calls), Team('file', calls)):
            manager.register_team(team)
        result = manager.tick()
        assert calls == ['host'] and result['ok']
    finally:
        signal.signal(signal.SIGTERM, previous)
        store.close()


def test_a_team_stops_between_workers(tmp_path):
    store = Store(tmp_path, test=True)
    try:
        calls = []

        class Worker:
            def __init__(self, name):
                self.name = name

            def tick(self, pipeline=None):
                calls.append(self.name)
                shutdown.request()
                return {'ok': True}

        team = BaseTeamLead(store, {})
        team.worker_instances = [Worker('a'), Worker('b')]
        results = team.run_workers()
        assert calls == ['a'] and results['b'] == {'ok': True, 'stopped': True}
    finally:
        store.close()


def test_stopping_cycle_skips_slow_phases_and_keeps_the_cursor(tmp_path, monkeypatch):
    store = Store(tmp_path, test=True)
    try:
        store.set(brain.SMART_CURSOR_KEY, 41)
        monkeypatch.setattr(brain, '_run_teams', lambda *a: (shutdown.request(), {'ok': True, 'teams': 4, 'findings_list': []})[1])

        def forbidden(*a, **k):
            raise AssertionError('runs after SIGTERM')
        monkeypatch.setattr(brain, 'CorrelationEngine', forbidden)
        monkeypatch.setattr(brain, '_run_smart_rules', forbidden)
        dispatched = []
        monkeypatch.setattr(brain, '_dispatch_safe_actions', lambda p, f: dispatched.append(f) or {})
        monkeypatch.setattr(brain, '_automatic_actions', lambda *a: (0, 0, 0))
        monkeypatch.setattr(brain, '_sudo_autoblock', lambda *a: 0)
        monkeypatch.setattr(brain, '_confirmed_actions', lambda *a: ([], []))
        # The managed-rule refresh runs every cycle; the smart-rule evaluation must not.
        engine = type('Engine', (), {'refresh_managed_rules': lambda self, **k: None, 'stats': lambda self: {}})()
        health = brain._run_once(store, {'investigation_enabled': False}, None, engine, {})
        assert health['status'] == 'STOPPING'
        assert store.get(brain.SMART_CURSOR_KEY) == 41
        assert dispatched == [[]]  # findings already written are still dispatched
    finally:
        store.close()
