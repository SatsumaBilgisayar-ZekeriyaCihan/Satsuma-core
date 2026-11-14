"""Offline /proc fixtures for the read-only evidence script.

Salt okunur kanıt betiği için çevrimdışı /proc örnekleri.
"""
import importlib.util
import hashlib
import json
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('ram_snapshot',Path(__file__).parents[1]/'tools/satsuma_ram_snapshot.py')
snapshot=importlib.util.module_from_spec(spec);spec.loader.exec_module(snapshot)


def fixture(tmp_path):
    root=tmp_path/'proc';pid=root/'4242';pid.mkdir(parents=True)
    (pid/'stat').write_text('4242 (firefox) '+' '.join(['S','1']+['0']*17+['1234']))
    (pid/'exe').symlink_to('/usr/lib64/firefox/firefox')
    (pid/'maps').write_text('1000-1100 rwxp 00000000 00:00 0\n')
    with (pid/'mem').open('wb') as f:f.seek(4096);f.write(b'x'*256)
    task=pid/'task/4243';task.mkdir(parents=True);(task/'comm').write_text('DOM Worker\n')
    return root,pid


def test_real_reads_in_fixture_are_not_raw_dumps_or_malware_verdicts(tmp_path):
    root,pid=fixture(tmp_path);result=snapshot.collect(root)
    assert result['bytes_read']==result['valid_snapshot_read_bytes']==256
    assert result['processes'][0]['threads']['worker_name_hints']==1
    assert result['malware_verdict']=='NOT_DETERMINED' and not result['signals_sent']
    assert 'x'*32 not in json.dumps(result)
    row=result['processes'][0]['regions'][0]
    assert row['sample_sha256']==hashlib.sha256(b'x'*256).hexdigest()
    assert not result['processes'][0]['malicious_code_verified']


def test_mapping_change_invalidates_read_hash(tmp_path,monkeypatch):
    root,pid=fixture(tmp_path);original=snapshot.os.pread
    def read(*args):
        value=original(*args);(pid/'maps').write_text('1000-1100 r-xp 00000000 00:00 0\n');return value
    monkeypatch.setattr(snapshot.os,'pread',read)
    result=snapshot.collect(root);row=result['processes'][0]
    assert row['status']=='INVALIDATED' and row['valid_snapshot_read_bytes']==0
    assert all('sample_sha256' not in r for r in row['regions'])


def test_denial_does_not_weaken_access_policy(tmp_path,monkeypatch):
    root,pid=fixture(tmp_path);original=Path.open
    def opening(path,*args,**kwargs):
        if path==pid/'mem':raise PermissionError('fixture denial')
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'open',opening)
    result=snapshot.collect(root)
    assert result['processes'][0]['status']=='ACCESS_DENIED' and result['bytes_read']==0
    assert not result['system_changes']


def test_output_private_unique_and_symlinks_refused(tmp_path):
    target=tmp_path/'evidence';first=snapshot.save({'test':True},target);second=snapshot.save({'test':False},target)
    assert first!=second and first.stat().st_mode&0o777==0o600
    link=tmp_path/'symlink';link.symlink_to(target,target_is_directory=True)
    with pytest.raises(PermissionError):snapshot.save({},link)
