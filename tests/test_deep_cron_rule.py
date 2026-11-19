"""2.2.59: the deep engine's cron rule takes a write only (field 2026-11-19: hourly cron.hourly runs)."""
from pathlib import Path

from satsuma_engine.engine import Engine
from satsuma_engine.live_lane import load_rules

RULES = Path(__file__).resolve().parents[1] / 'satsuma_engine' / 'rules'


def fired(event):
    event = {'event': event, **event}
    report = load_rules([RULES], strict=True)
    result = Engine(report.rules).scan([(1, event)])
    return {r.finding.get('rule_id') for r in result.reported}


def test_running_cron_hourly_is_not_a_write():
    assert 'SATSUMA-PERSIST-001' not in fired({'kind': 'process', 'file_path': '/etc/cron.hourly/0anacron',
                                               'operation': 'execute', 'cmd': 'run-parts /etc/cron.hourly'})


def test_writing_cron_is_still_caught():
    assert 'SATSUMA-PERSIST-001' in fired({'kind': 'file', 'file_path': '/etc/cron.d/evil', 'operation': 'write',
                                           'cmd': 'tee /etc/cron.d/evil'})
