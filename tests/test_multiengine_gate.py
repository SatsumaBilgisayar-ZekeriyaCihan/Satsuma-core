import importlib.util
from pathlib import Path
import os
import stat
import time

spec = importlib.util.spec_from_file_location('multiengine_scan', Path(__file__).parents[1] / 'tools/multiengine_scan.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_valid_rpm_hash(tmp_path):
    rpm = tmp_path / 'a.rpm'
    rpm.write_bytes(b'\xed\xab\xee\xdb' + b'hello')
    digest, size = m.checked_rpm(rpm)
    assert len(digest) == 64 and size == 9


def test_reject_symlink_hardlink_and_fake_rpm(tmp_path):
    f = tmp_path / 'f.rpm'
    f.write_bytes(b'not really an rpm')
    import pytest
    with pytest.raises(m.GateError): m.checked_rpm(f)
    f.write_bytes(b'\xed\xab\xee\xdb123')
    (tmp_path / 'other.rpm').hardlink_to(f)
    with pytest.raises(m.GateError): m.checked_rpm(f)
    (tmp_path / 'other.rpm').unlink()
    (tmp_path / 'link.rpm').symlink_to(f)
    with pytest.raises(m.GateError): m.checked_rpm(tmp_path / 'link.rpm')


def test_vt_fails_closed(tmp_path):
    import pytest
    now = time.time()
    payload = {'data':{'attributes':{'last_analysis_date':int(now),
               'last_analysis_stats':{'malicious':0,'suspicious':0,'undetected':21,'harmless':0}}}}
    assert m.inspect_vt(payload, now=now)['non_detections'] == 21
    payload['data']['attributes']['last_analysis_stats']['suspicious'] = 1
    with pytest.raises(m.GateError): m.inspect_vt(payload, now=now)
    payload['data']['attributes']['last_analysis_stats']['suspicious'] = 0
    with pytest.raises(m.GateError): m.inspect_vt(payload, now=now + 9 * 86400)
    with pytest.raises(m.GateError): m.inspect_vt({}, now=now)


def test_missing_key_writes_private_blocked_report(tmp_path):
    import json
    rpm = tmp_path/'ok.rpm'
    rpm.write_bytes(b'\xed\xab\xee\xdbhello')
    path = tmp_path/'evidence.json'
    assert not m.run(rpm, path)
    result = json.loads(path.read_text())
    assert result['status'] == 'BLOCKED'
    assert result['submission'] is False
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with __import__('pytest').raises(m.GateError): m.atomic_report(path, result)
