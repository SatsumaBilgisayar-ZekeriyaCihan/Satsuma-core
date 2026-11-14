import hashlib
import json
from types import SimpleNamespace

from satsuma.tpm_integrity_guard import (collect, _parse_handles,
                                          compare_with_pinned_baseline, CAPABILITIES)


def fake_runner(cmd, **kw):
    assert cmd[0] == '/usr/bin/tpm2_getcap'
    assert cmd[1] in CAPABILITIES
    assert kw['timeout'] == 8 and kw['capture_output'] and not kw['check']
    payload = b'- 0x81000001\n' if cmd[1] == 'handles-persistent' else b'- 0x01000001\n'
    return SimpleNamespace(returncode=0, stdout=payload)


def test_read_only_capabilities_and_no_authorization():
    commands=[]
    def capture(cmd, **kw):
        commands.append(cmd)
        return fake_runner(cmd, **kw)
    result = collect(runner=capture)
    assert result['status'] == 'LOCAL_INVENTORY_OBSERVED'
    assert result['verified'] is False
    assert result['tpm_modified'] is False
    assert commands == [['/usr/bin/tpm2_getcap','handles-persistent'],
                        ['/usr/bin/tpm2_getcap','handles-nv-index']]


def test_strict_parser_and_ranges():
    assert _parse_handles(' - 0x81000002\n- 0x81000001\n', 'handles-persistent') == ['0x81000001','0x81000002']
    for payload, cap in [('- 0x01000001\n','handles-persistent'),
                         ('- 0x81000001\n','handles-nv-index'),
                         ('- 0x81000001\n- 0x81000001\n','handles-persistent'),
                         ('injected output','handles-nv-index'),
                         ('- 0x81000001\x1b[31m','handles-persistent')]:
        import pytest
        with pytest.raises(ValueError):
            _parse_handles(payload, cap)


def test_failure_is_not_zero_inventory():
    def bad(cmd, **kw):
        return SimpleNamespace(returncode=1,stdout=b'')
    assert collect(runner=bad)['status'] == 'UNAVAILABLE'


def test_baseline_pinned_match_and_change(tmp_path):
    baseline = {'schema':1,'handles-persistent':['0x81000001'],
                'handles-nv-index':['0x01000001']}
    path=tmp_path/'baseline.json'
    raw=json.dumps(baseline).encode()
    path.write_bytes(raw)
    pin=hashlib.sha256(raw).hexdigest()
    inv=collect(runner=fake_runner)
    matched=compare_with_pinned_baseline(inv,path,pin)
    assert matched['status']=='HANDLES_MATCH_PINNED_BASELINE'
    assert matched['baseline_authenticated'] is False
    assert matched['trusted_boot_verified'] is False
    inv['capabilities']['handles-persistent']['handles']=['0x81000002']
    changed=compare_with_pinned_baseline(inv,path,pin)
    assert changed['status']=='HANDLE_CHANGE_OBSERVED'
    assert changed['changes']['handles-persistent']['added']==['0x81000002']
    assert changed['changes']['handles-persistent']['removed']==['0x81000001']


def test_tampered_or_unpinned_baseline_rejected(tmp_path):
    path=tmp_path/'baseline.json'
    path.write_text('{"schema":1,"handles-persistent":[],"handles-nv-index":[]}')
    inv=collect(runner=fake_runner)
    assert compare_with_pinned_baseline(inv,path,'not-a-pin')['status']=='INVALID_EXTERNAL_BASELINE_PIN'
    assert compare_with_pinned_baseline(inv,path,'0'*64)['status']=='BASELINE_PIN_MISMATCH'
    link=tmp_path/'symlink.json'
    link.symlink_to(path)
    assert compare_with_pinned_baseline(inv,link,'0'*64)['status']=='INVALID_BASELINE'
    # Correct pin against a symlink must also be refused.
    pin=hashlib.sha256(path.read_bytes()).hexdigest()
    assert compare_with_pinned_baseline(inv,link,pin)['status']=='INVALID_BASELINE'


def test_partial_inventory_does_not_get_compared():
    def half(cmd,**kw):
        if cmd[1]=='handles-nv-index':
            return SimpleNamespace(returncode=1,stdout=b'')
        return fake_runner(cmd,**kw)
    inv=collect(runner=half)
    assert inv['status']=='PARTIAL_INVENTORY'
    assert compare_with_pinned_baseline(inv,'missing','0'*64)['status']=='INVENTORY_INCOMPLETE'
