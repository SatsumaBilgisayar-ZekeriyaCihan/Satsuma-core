"""Satsuma 39: test-mode detections never authorize a response."""
import time
from pathlib import Path
from satsuma_engine.rule_model import load_rules
from satsuma_engine.live_lane import DeepEvidenceLane
from satsuma_engine.process_ipc import _compact_event

ROOT=Path(__file__).resolve().parents[1]/'satsuma_engine'

def _rules():
    return load_rules([ROOT/'rules'], strict=True).rules, load_rules([ROOT/'rules_test'], strict=True).rules

def _wait(lane):
    end=time.monotonic()+2
    while time.monotonic()<end:
        if lane.health()['scans']:
            time.sleep(.05)
            break
        time.sleep(.01)

def test_trial_catalog_is_schema_valid_and_never_has_destructive_actions():
    base,trial=_rules()
    assert len(trial)>=150
    assert not ({r.id for r in base}&{r.id for r in trial})
    assert all(r.enabled and r.actions==['create_ticket','ask_user'] for r in trial)

def test_test_mode_flag_controls_lab_rules():
    base,trial=_rules()
    rule=next(r for r in trial if r.id=='SATSUMA-C2-004')
    e={'id':'x','source':'sys_proc','cmd':'curl -X POST https://example.invalid','timestamp':'2026-11-14T12:00:00Z'}
    lane=DeepEvidenceLane([],test_rules=[rule],batch=1).start()
    try:
        assert lane.submit(e)
        _wait(lane)
        assert not lane.drain()
    finally: lane.close()
    lane=DeepEvidenceLane([],test_rules=[rule],batch=1).start()
    try:
        assert lane.submit({**e,'lab_test_mode':True})
        _wait(lane)
        rows=lane.drain()
        assert rows and all(x['authorization']=='none' and x['review_required'] is True for x in rows)
        assert all('actions' not in x and 'pid' not in x and 'cmd' not in x for x in rows)
    finally: lane.close()

def test_lab_mode_not_forwarded_as_executable_command():
    obj=_compact_event({'id':'x','lab_test_mode':True,'kill_process':True,'password':'secret'})
    assert obj['lab_test_mode'] is True
    assert 'kill_process' not in obj and 'password' not in obj

def test_missing_source_does_not_activate_audit_only_rule():
    _,trial=_rules()
    audit=next(r for r in trial if r.logsource.get('source')=='audit')
    lane=DeepEvidenceLane([],test_rules=[audit],batch=1).start()
    try:
        lane.submit({'id':'x','source':'sys_proc','file_path':'/etc/shadow','lab_test_mode':True})
        _wait(lane)
        assert lane.drain()==[]
    finally: lane.close()
