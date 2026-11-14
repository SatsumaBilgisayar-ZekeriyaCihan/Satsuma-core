"""Installer tests use isolated files and simulated root ownership."""
import hashlib
import os
from pathlib import Path
from types import SimpleNamespace
import pytest
from installer import boot_setup, integrity, runtime_check
from satsuma import aide_support, early_guard, protected_storage

@pytest.fixture
def files(tmp_path, monkeypatch):
    lstat, fstat = Path.lstat, os.fstat
    def owned(info):
        parts=list(info);parts[4:6]=[0,0];return os.stat_result(parts)
    monkeypatch.setattr(Path,'lstat',lambda p:owned(lstat(p)))
    monkeypatch.setattr(os,'fstat',lambda fd:owned(fstat(fd)))
    monkeypatch.setattr(protected_storage,'open_directory',lambda p:os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW))
    config=tmp_path/'aide.conf';config.write_text('fixture');config.chmod(0o600)
    key=tmp_path/'key';key.write_bytes(b'k'*32);key.chmod(0o600)
    monkeypatch.setattr(integrity,'KEY',key)
    return SimpleNamespace(config=config,key=key,database=tmp_path/'db.gz',new=tmp_path/'new.gz')








@pytest.mark.parametrize('change',['none','extra_file','extra_dir','content','symlink','writable'])
def test_rpm_inventory_rejects_unexpected_payload(files,change):
    root=files.config.parent/'payload';root.mkdir(mode=0o755)
    p=root/'main.py';p.write_text('trusted');p.chmod(0o644)
    listing=''.join(f'{x}\t{x.lstat().st_mode:o}\t{hashlib.sha256(x.read_bytes()).hexdigest() if x.is_file() else ""}\n' for x in (root,p))
    if change=='extra_file':(root/'stale.py').write_text('stale')
    elif change=='extra_dir':(root/'stale').mkdir()
    elif change=='content':p.write_text('bad')
    elif change=='symlink':p.unlink();p.symlink_to(files.config)
    elif change=='writable':p.chmod(0o666)
    run=lambda *a,**kw:SimpleNamespace(stdout=listing)
    if change=='none':assert boot_setup.verify_payload(root,run)==2
    else:
        with pytest.raises((RuntimeError,PermissionError)):boot_setup.verify_payload(root,run)

@pytest.mark.parametrize('state,code',[('FULL_CHECKED',0),('WARNING',1),('FAILED',1)])
def test_boot_failure_is_visible_to_installer(monkeypatch,state,code):
    monkeypatch.setattr(early_guard.os,'geteuid',lambda:0)
    result={'state':state,'mode':'test','response_unlocked':state=='FULL_CHECKED',
            'failure_reasons':[],'warning_reasons':[], 'checks':{'aide':{'status':'test'}}}
    monkeypatch.setattr(early_guard,'run_guard',lambda:result)
    written=[]
    monkeypatch.setattr(early_guard,'write_verdict',written.append)
    assert early_guard.main()==code
    assert written==[result]







@pytest.mark.parametrize('state,unlocked,error,warning', [
    ('FULL_CHECKED',True,False,False),
    ('FULL_CHECKED',False,True,False),
    ('WARNING',False,False,True),
    ('WARNING',True,True,False),
    ('FAILED',False,True,False),
    ('UNKNOWN',False,True,False),
])
def test_runtime_reports_aide_drift_separately(state,unlocked,error,warning):
    snapshot={'errors':[], 'warnings':[]}
    runtime_check.record_boot_verdict(
        snapshot, {'state':state,'response_unlocked':unlocked})
    assert bool(snapshot['errors']) == error
    assert bool(snapshot['warnings']) == warning
    assert snapshot['boot_response_unlocked'] == (state == 'FULL_CHECKED' and unlocked)
