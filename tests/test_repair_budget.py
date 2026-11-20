"""Faz 3: one restart ledger for every watcher; restarts never stop (owner: "ürün zayıflıyor")."""
import importlib.util
from pathlib import Path

from satsuma import repair_budget as rb


def test_watchers_cannot_fight_but_a_unit_is_never_left_down(tmp_path):
    ledger = tmp_path / 'ledger.json'
    unit = 'satsuma-teams.service'
    assert rb.claim([unit], 'self-health', now=1000, ledger=ledger) == (True, '')
    ok, why = rb.claim([unit], 'flow-guard', now=1010, ledger=ledger)
    assert not ok and 'self-health' in why                      # one minute apart: watchers cannot fight
    now, granted = 1000, 1
    for _ in range(40):                                          # someone kills it over and over
        now += 60
        if rb.claim([unit], 'maintenance', now=now, ledger=ledger)[0]:
            granted += 1
    assert granted >= 6                                          # still restarted after the old cap of 3
    assert unit in rb.storms(now=now, ledger=ledger)
    assert max(rb.gap(n) for n in range(50)) == rb.MAX_GAP       # the gap never exceeds 10 minutes


def test_a_group_claim_is_all_or_nothing(tmp_path):
    ledger = tmp_path / 'ledger.json'
    assert rb.claim(['a.service'], 'x', now=100, ledger=ledger)[0]
    assert not rb.claim(['b.service', 'a.service'], 'y', now=110, ledger=ledger)[0]
    assert rb.claim(['b.service'], 'y', now=111, ledger=ledger)[0]


def test_a_unit_that_keeps_falling_is_a_critical_finding(monkeypatch):
    spec = importlib.util.spec_from_file_location('teams_storm', Path(__file__).resolve().parents[1] / 'run_satsuma_teams.py')
    teams = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(teams)
    recorded = []
    monkeypatch.setattr('satsuma.finding_store.record_finding', lambda store, f, src: recorded.append(f))

    class Mem:
        def __init__(self): self.d = {}
        def get(self, k, default=None): return self.d.get(k, default)
        def set(self, k, v): self.d[k] = v
    store = Mem()
    storms = {'satsuma-privd.service': {'count': 5, 'last': 1000, 'actor': 'self-health'}}
    assert teams._restart_storms(store, now=1000, storms=storms) == ['satsuma-privd.service']
    assert recorded[-1]['severity'] == 'critical'
    assert teams._restart_storms(store, now=1500, storms=storms) == []          # at most hourly per unit
