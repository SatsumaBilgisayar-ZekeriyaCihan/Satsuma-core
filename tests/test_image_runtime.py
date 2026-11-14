"""Image transactions tested without mounting or changing the host firewall."""
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from installer import image_runtime as image


@pytest.fixture
def bundle(tmp_path,monkeypatch):
    images=tmp_path/'images';images.mkdir();key=tmp_path/'key';key.write_bytes(b'k'*32)
    monkeypatch.setattr(image,'IMAGES',images);monkeypatch.setattr(image,'ACTIVE',images/'active.json')
    monkeypatch.setattr(image,'KEY',key);monkeypatch.setattr(image,'MOUNT',tmp_path/'mount')
    # File-security behavior is tested separately. Transaction tests use disposable pytest directories.
    monkeypatch.setattr(image,'read',lambda path,limit=0:Path(path).read_bytes())
    def candidate(content):
        digest=hashlib.sha256(content).hexdigest();directory=images/digest;directory.mkdir(exist_ok=True)
        (directory/'runtime.squashfs').write_bytes(content)
        data={'schema':1,'sha256':digest,'manifest':'manifest.json'}
        return image.authenticated(data)
    return images,candidate


def test_activation_preserves_old_image_and_reference(bundle,monkeypatch):
    images,candidate=bundle;old=candidate(b'old');new=candidate(b'new')
    image.ACTIVE.write_bytes(old);(images/'pending.json').write_bytes(new)
    monkeypatch.setattr(image.os.path,'ismount',lambda p:False)
    observed=[];monkeypatch.setattr(image,'mount',lambda:observed.append(image.active()[0]['sha256']))
    image.activate()
    assert image.ACTIVE.read_bytes()==new and (images/'previous.json').read_bytes()==old
    assert len(list(images.glob('*/runtime.squashfs')))==2 and len(observed)==1
    assert not (images/'pending.json').exists()


def test_failed_activation_restores_old_reference_and_retains_candidate(bundle,monkeypatch):
    images,candidate=bundle;old=candidate(b'old');new=candidate(b'new')
    image.ACTIVE.write_bytes(old);(images/'pending.json').write_bytes(new)
    monkeypatch.setattr(image.os.path,'ismount',lambda p:False)
    def mount():
        if image.ACTIVE.read_bytes()==new:raise RuntimeError('mount failed')
    monkeypatch.setattr(image,'mount',mount)
    with pytest.raises(RuntimeError,match='mount failed'):image.activate()
    assert image.ACTIVE.read_bytes()==old and (images/'pending.json').read_bytes()==new


@pytest.mark.parametrize('damage',['image','signature','path'])
def test_untrusted_candidate_never_replaces_active(bundle,monkeypatch,damage):
    images,candidate=bundle;old=candidate(b'old');new=candidate(b'new')
    image.ACTIVE.write_bytes(old)
    envelope=json.loads(new)
    if damage=='image':(images/envelope['data']['sha256']/'runtime.squashfs').write_bytes(b'tampered')
    elif damage=='signature':envelope['hmac']='0'*64;new=json.dumps(envelope).encode()
    else:envelope['data']['sha256']='../../outside';new=image.authenticated(envelope['data'])
    (images/'pending.json').write_bytes(new)
    calls=[];monkeypatch.setattr(image,'mount',lambda:calls.append(True))
    with pytest.raises((RuntimeError,PermissionError,ValueError)):image.activate()
    assert image.ACTIVE.read_bytes()==old and not calls


@pytest.mark.parametrize('owned',[True,False])
def test_legacy_cleanup_removes_only_owned_table(monkeypatch,owned):
    calls=[]
    def run(args):
        calls.append(args)
        table={'family':'inet','name':'satsuma_apps','comment':'Satsuma application egress' if owned else 'foreign'}
        return SimpleNamespace(stdout=json.dumps({'nftables':[{'table':table}]}))
    monkeypatch.setattr(image,'run',run)
    if owned:image.legacy_check()
    else:
        with pytest.raises(PermissionError):image.legacy_check()
    assert any('delete' in args for args in calls)==owned
    assert not any('flush' in args for args in calls)


def test_mount_requires_correct_readonly_backing_image(monkeypatch):
    responses=iter([{'filesystems':[{'fstype':'squashfs','options':'ro,nodev,nosuid','source':'/dev/loop1'}]},
                    {'loopdevices':[{'name':'/dev/loop1','back-file':'/unexpected'}]}])
    monkeypatch.setattr(image,'run',lambda args:SimpleNamespace(stdout=json.dumps(next(responses))))
    with pytest.raises(RuntimeError,match='unexpected backing'):image.check_mount(Path('/expected'))


@pytest.mark.parametrize('name,backing,accepted',[
    ('/dev/loop1 (lost)','/expected',True),
    ('/dev/loop1 (lost)','/foreign',False),
    ('/dev/loop2 (lost)','/expected',False),
    ('/dev/loop1 (lost) extra','/expected',False),
])
def test_private_devices_annotation_does_not_invalidate_verified_mount(monkeypatch,name,backing,accepted):
    responses=iter([{'filesystems':[{'fstype':'squashfs','options':'ro,nodev,nosuid','source':'/dev/loop1'}]},
                    {'loopdevices':[{'name':name,'back-file':backing}]}])
    monkeypatch.setattr(image,'run',lambda args:SimpleNamespace(stdout=json.dumps(next(responses))))
    if accepted:image.check_mount(Path('/expected'))
    else:
        with pytest.raises(RuntimeError,match='unexpected backing'):image.check_mount(Path('/expected'))


def test_payload_verification_rejects_modified_external_launcher(tmp_path,monkeypatch):
    root=tmp_path/'payload';root.mkdir();main=root/'main.py';main.write_text('trusted')
    launcher=Path('/usr/bin/satsuma-test-fixture')
    rows=''.join(f'{p}\t{p.stat().st_mode:o}\t{hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else ""}\n' for p in (root,main))
    rows+=f'{launcher}\t100755\t'+hashlib.sha256(b'original').hexdigest()+'\n'
    original=Path.lstat
    def lstat(path):
        if path==launcher:return SimpleNamespace(st_mode=0o100755,st_uid=0,st_gid=0)
        info=original(path)
        return SimpleNamespace(st_mode=info.st_mode,st_uid=0,st_gid=0)
    monkeypatch.setattr(Path,'lstat',lstat)
    monkeypatch.setattr(image,'read',lambda path,limit=0:b'tampered' if path==launcher else path.read_bytes())
    with pytest.raises(RuntimeError,match='hash mismatch'):
        image.validate_payload(root,lambda args:SimpleNamespace(stdout=rows))
