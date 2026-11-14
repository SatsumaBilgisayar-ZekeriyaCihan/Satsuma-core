"""Stopping a process may be confirmed from the event flow (2.2.32 fix).

Field 2026-11-04: with raw events no longer stored, every evidence check
looked for database rows and every evidence-gated stop was denied
("satsuma_database_confirmation_missing"). The check now reads the
stream event from the rule engine's in-memory flow.

Sürecin durdurulması akıştaki olayla teyit edilebilir. Ham olaylar artık
saklanmadığı için her kanıt denetimi veritabanında satır arıyor ve kanıt
isteyen her durdurma reddediliyordu; denetim artık akıştaki olayı okur.
"""
import time
from datetime import datetime, timezone

import pytest

from satsuma import flow as F
from satsuma.pipeline import Pipeline
from satsuma.rule_response import evidence_report
from satsuma.store import Store
import run_satsuma_teams as T


@pytest.fixture
def active_flow():
    previous = F.ACTIVE
    F.ACTIVE = F.ProcessFlow()
    yield F.ACTIVE
    F.ACTIVE = previous


def stream_event(flow, raw_id):
    raw = {'source': 'memory', 'action': 'memfd_executable', 'pid': 4321, 'starttime': 99887,
           'exe': '/memfd:x (deleted)', 'uid': 1000, 'timestamp': datetime.now(timezone.utc).isoformat()}
    body = {'raw_id': raw_id, 'event': Pipeline.__new__(Pipeline)._build_host_normalized(dict(raw)), 'raw': raw}
    flow.add(body)
    import json
    return T._smart_event(raw_id, json.dumps({'raw_id': raw_id, 'event': body['event']}))


def test_stream_event_confirms_the_same_process(tmp_path, active_flow):
    event = stream_event(active_flow, 'flow-1-1')
    report = evidence_report(Store(tmp_path, test=True), {'rule_id': 'R', 'event': event}, 'process_kill',
                             {'rule_id': 'R', 'minimum_sources': 1, 'required_sources': ['memory'], 'freshness_seconds': 60},
                             {'pid': 4321})
    assert report['passed'], report
    assert report['source_families'] == ['memory'] and report['record_ids'] == ['flow-1-1']


def test_event_outside_the_flow_is_not_evidence(tmp_path, active_flow):
    event = stream_event(F.ProcessFlow(), 'flow-1-2')  # never reached the engine's flow
    report = evidence_report(Store(tmp_path, test=True), {'rule_id': 'R', 'event': event}, 'process_kill',
                             {'rule_id': 'R', 'minimum_sources': 1, 'required_sources': [], 'freshness_seconds': 60},
                             {'pid': 4321})
    assert not report['passed']


def test_flow_forgets_ids_with_the_window():
    now = [100.0]
    flow = F.ProcessFlow(window=10, clock=lambda: now[0])
    flow.add({'raw_id': 'flow-a', 'event': {}, 'raw': {'pid': 1}})
    assert flow.get('flow-a')
    now[0] += 20
    flow.prune()
    assert flow.get('flow-a') is None
