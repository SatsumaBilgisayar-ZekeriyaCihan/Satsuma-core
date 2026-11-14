import hashlib
from pathlib import Path
import pytest
from installer import service_setup as s


def test_only_verified_current_masks_are_removed_and_evidence_precedes_removal(tmp_path,monkeypatch):
    vendor=tmp_path/'vendor';vendor.mkdir();overrides=tmp_path/'system';overrides.mkdir()
    monkeypatch.setattr(s,'UNITS',('satsuma-core.service','satsuma-network.service'))
    digests={}
    for unit in s.UNITS:
        path=vendor/unit;path.write_text('[Service]\nExecStart=/usr/bin/true\n')
        digests[str(path)]=hashlib.sha256(path.read_bytes()).hexdigest()
        (overrides/unit).symlink_to('/dev/null')
    (overrides/'sshd.service').symlink_to('/dev/null')
    (overrides/'satsuma-retired.service').symlink_to('/dev/null')
    records=[]
    def writer(record):assert Path(record['path']).is_symlink();records.append(record)
    result=s.recover(vendor,[overrides],digests,writer,ownership=False)
    assert len(result['restored'])==2 and len(records)==2
    assert (overrides/'sshd.service').is_symlink() and (overrides/'satsuma-retired.service').is_symlink()


def test_digest_mismatch_does_not_remove_mask(tmp_path,monkeypatch):
    vendor=tmp_path/'vendor';vendor.mkdir();directory=tmp_path/'overrides';directory.mkdir()
    monkeypatch.setattr(s,'UNITS',('satsuma-core.service',))
    source=vendor/s.UNITS[0];source.write_text('modified')
    mask=directory/s.UNITS[0];mask.symlink_to('/dev/null')
    with pytest.raises(RuntimeError):s.recover(vendor,[directory],{str(source):'0'*64},lambda r:None,ownership=False)
    assert mask.is_symlink()




def test_containment_never_masks_current_satsuma_services():
    from installer.remote_containment import server_unit
    assert all(not server_unit(name) for name in s.UNITS)


def test_real_systemctl_enable_after_owned_mask_recovery(tmp_path,monkeypatch):
    import shutil,subprocess
    binary='/usr/bin/systemctl' if Path('/usr/bin/systemctl').exists() else shutil.which('systemctl')
    if binary is None:pytest.skip('systemctl required for offline enable integration')
    vendor=tmp_path/'usr/lib/systemd/system';vendor.mkdir(parents=True)
    overrides=tmp_path/'etc/systemd/system';overrides.mkdir(parents=True)
    unit='satsuma-core.service'
    monkeypatch.setattr(s,'UNITS',(unit,))
    source=vendor/unit
    source.write_text('[Unit]\nDescription=Fixture\n[Service]\nExecStart=/usr/bin/true\n[Install]\nWantedBy=multi-user.target\n')
    (overrides/unit).symlink_to('/dev/null')
    command=[binary,'--root='+str(tmp_path),'enable',unit]
    before=subprocess.run(command,capture_output=True,text=True,timeout=10)
    assert before.returncode!=0 and 'masked' in before.stderr.lower()
    s.recover(vendor,[overrides],{str(source):hashlib.sha256(source.read_bytes()).hexdigest()},lambda record:None,ownership=False)
    after=subprocess.run(command,capture_output=True,text=True,timeout=10)
    assert after.returncode==0,after.stderr
    assert (overrides/'multi-user.target.wants'/unit).is_symlink()
