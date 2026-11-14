"""Application-only replacement for the retired host AIDE enrollment tests."""
import json
import os
import time
from pathlib import Path
import pytest
from installer import integrity, boot_setup
from satsuma import early_guard, integrity_monitor


def test_signed_inventory_ignores_unrelated_files_but_rejects_application_tamper(tmp_path):
    root=tmp_path/'application';root.mkdir();code=root/'main.py';code.write_text('original')
    outside=tmp_path/'unrelated';outside.write_text('old')
    manifest=tmp_path/'manifest';key=tmp_path/'key';key.write_bytes(b'k'*32);key.chmod(0o600)
    integrity.build(root,manifest);integrity.sign(manifest,key.read_bytes())
    outside.write_text('changed')
    assert integrity.verify(root,manifest,False,key)==2
    code.write_text('tampered')
    with pytest.raises(RuntimeError,match='Integrity mismatch'):integrity.verify(root,manifest,False,key)


@pytest.mark.parametrize('change',['extra','missing','symlink','mode','manifest'])
def test_inventory_rejects_structure_or_manifest_changes(tmp_path,change):
    root=tmp_path/'code';root.mkdir();code=root/'main.py';code.write_text('original')
    manifest=tmp_path/'manifest';key=tmp_path/'key';key.write_bytes(b'k'*32);key.chmod(0o600)
    integrity.build(root,manifest);integrity.sign(manifest,key.read_bytes())
    if change=='extra':(root/'injected.py').write_text('x')
    elif change=='missing':code.unlink()
    elif change=='symlink':code.unlink();code.symlink_to(key)
    elif change=='mode':code.chmod(0o666)
    else:manifest.write_text('{}')
    with pytest.raises((RuntimeError,PermissionError,OSError)):
        integrity.verify(root,manifest,False,key)


def test_boot_verification_never_unlocks_after_failure():
    def failed():raise PermissionError('modified application')
    result=early_guard.run_guard(verifier=failed,boot_id='boot')
    assert result['state']=='FAILED' and not result['response_unlocked']
    assert 'aide' not in result['checks']
    assert early_guard.run_guard(verifier=lambda:12,boot_id='boot')['response_unlocked']


@pytest.mark.parametrize('change',['old_boot','stale','future','writable','symlink','forged_check'])
def test_boot_verdict_rejects_stale_or_unsafe_evidence(tmp_path,monkeypatch,change):
    monkeypatch.setattr(early_guard,'current_boot_id',lambda:'boot')
    value=early_guard.run_guard(verifier=lambda:1,boot_id='boot')
    if change=='old_boot':value['boot_id']='old'
    elif change=='stale':value['generated_monotonic']=time.monotonic()-1000
    elif change=='future':value['generated_monotonic']=time.monotonic()+1000
    elif change=='forged_check':value['checks']['application']['ok']=False
    path=tmp_path/'verdict';path.write_text(json.dumps(value));path.chmod(0o600)
    if change=='writable':path.chmod(0o666)
    elif change=='symlink':link=tmp_path/'link';link.symlink_to(path);path=link
    assert early_guard.read_verdict(path)['response_unlocked'] is False


def test_database_failure_cannot_prevent_integrity_report():
    writes=[];verdicts=[]
    def unavailable():raise RuntimeError('database corrupt')
    result=integrity_monitor.run_once(guard=lambda:early_guard.run_guard(verifier=lambda:3,boot_id='boot'),
        verdict_writer=verdicts.append,report_writer=lambda p,r:writes.append((p,dict(r))),store_factory=unavailable)
    assert result['status']=='HEALTHY' and result['database']['status']=='UNAVAILABLE'
    assert len(writes)==2 and verdicts[0]['response_unlocked']
    assert result['approved_baseline_replaced'] is False


def test_enrollment_checks_before_account_changes(monkeypatch):
    import pwd
    from types import SimpleNamespace
    monkeypatch.setattr(pwd,'getpwnam',lambda user:SimpleNamespace(pw_uid=1000))
    def fail():raise RuntimeError('untrusted image')
    monkeypatch.setattr(boot_setup,'provision',fail)
    calls=[]
    with pytest.raises(RuntimeError):boot_setup.enroll_user('desktop',lambda *a,**k:calls.append(a))
    assert not calls
