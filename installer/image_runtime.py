"""Standalone RPM-verified SquashFS activation and boot mount helper.

Installed outside the mounted payload; never executes code from an unverified image.
Old content-addressed images remain available. No overlay or writable code fallback.
"""
import argparse
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile

PAYLOAD=Path('/usr/lib/satsuma-core/payload')
IMAGES=Path('/var/lib/satsuma-core/images')
ACTIVE=IMAGES/'active.json'
MOUNT=Path('/opt/satsuma-core')
KEY=Path('/etc/satsuma-core/trust/manifest.key')
OWNED_TABLES={
    'satsuma_app_control':'Satsuma process firewall v1',
    'satsuma_core':'Satsuma Core managed',
    'satsuma_lan':'Satsuma Core managed',
    'satsuma_dns':'Satsuma Core managed',
    'satsuma_identity':'Satsuma interface identity guard',
    'satsuma_loopback':'Satsuma loopback validation',
    'satsuma_apps':'Satsuma application egress',
    'satsuma_dns_ns':'Satsuma DNS namespace',
    'satsuma_netblock':'Satsuma manual network blocks',
}


def run(args,**kwargs):
    result=subprocess.run(args,check=False,capture_output=True,text=True,timeout=300,**kwargs)
    if result.returncode:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: {result.stderr[-2000:].strip()}')
    return result


def unmount():
    """Unmount only our verified image; retain all evidence on failure."""
    if not os.path.ismount(MOUNT):
        return {'status':'NOT_MOUNTED','mount':str(MOUNT)}
    _,image=active()
    check_mount(image)
    try:
        run(['/usr/bin/umount',str(MOUNT)])
    except Exception as exc:
        raise RuntimeError('Satsuma image remains mounted; stop its users and retry removal. '
                           'Image and key retained. '+str(exc)) from exc
    if os.path.ismount(MOUNT):
        raise RuntimeError('Satsuma image is still mounted after umount; evidence retained')
    return {'status':'UNMOUNTED','mount':str(MOUNT),'image_retained':True}


def cleanup_firewall():
    """Delete only exact-name, ownership-marked tables; never flush queues."""
    def tables():
        return [row['table'] for row in json.loads(run(
            ['/usr/sbin/nft','-j','list','tables']).stdout).get('nftables',[]) if 'table' in row]
    present=tables();remove=[];retained=[]
    for table in present:
        name=table.get('name','')
        if table.get('family')!='inet' or not name.startswith('satsuma'):continue
        if name not in OWNED_TABLES:
            retained.append(name);continue
        readback=json.loads(run(['/usr/sbin/nft','-j','list','table','inet',name]).stdout)
        headers=[row['table'] for row in readback.get('nftables',[]) if 'table' in row]
        if len(headers)!=1 or headers[0].get('family')!='inet' or headers[0].get('name')!=name or headers[0].get('comment')!=OWNED_TABLES[name]:
            raise PermissionError('Removal refused: firewall table ownership mismatch: '+name)
        remove.append(name)
    if remove:
        script=''.join('delete table inet '+name+'\n' for name in remove)
        run(['/usr/sbin/nft','--check','-f','-'],input=script)
        run(['/usr/sbin/nft','-f','-'],input=script)
        if any(t.get('family')=='inet' and t.get('name') in remove for t in tables()):
            raise RuntimeError('Owned firewall tables remain after removal')
    return {'status':'REVIEW_REQUIRED' if retained else 'CLEANED', 'removed_tables':remove,
            'retained_unmarked_tables':retained,'queue_owners_changed':False,
            'images_and_keys_retained':True}


def read(path,limit=32*1024*1024):
    for parent in [*path.parents][::-1]:
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise PermissionError('Unsafe image parent: '+str(parent))
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as f:
        info=os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o022:
            raise PermissionError('Unsafe image file: '+str(path))
        raw=f.read(limit+1)
        if len(raw)>limit:raise ValueError('Image metadata exceeds capacity')
        return raw


def encoded(data):return json.dumps(data,sort_keys=True,separators=(',',':')).encode()


def atomic(path,raw):
    fd,temp=tempfile.mkstemp(prefix='.image-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.chmod(temp,0o600);os.replace(temp,path)
        directory=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
    finally:
        if os.path.exists(temp):os.unlink(temp)


def authenticated(data):
    return encoded({'data':data,'hmac':hmac.new(read(KEY,32),encoded(data),hashlib.sha256).hexdigest()})


def active():
    envelope=json.loads(read(ACTIVE,65536));data=envelope['data']
    if not hmac.compare_digest(envelope['hmac'],hmac.new(read(KEY,32),encoded(data),hashlib.sha256).hexdigest()):
        raise PermissionError('Image activation signature mismatch')
    if not re.fullmatch('[a-f0-9]{64}',data.get('sha256','')):raise ValueError('Invalid image digest')
    image=IMAGES/data['sha256']/'runtime.squashfs'
    raw=read(image,512*1024*1024)
    if hashlib.sha256(raw).hexdigest()!=data['sha256']:raise PermissionError('SquashFS image changed')
    return data,image


def validate_payload(root=PAYLOAD,runner=run):
    rows=runner(['/usr/bin/rpm','-q','--qf','[%{FILENAMES}\t%{FILEMODES:octal}\t%{FILEDIGESTS}\n]','satsuma-core']).stdout
    records={}
    external={}
    for line in rows.splitlines():
        name,mode,digest=line.split('\t');path=Path(name)
        if path==root or root in path.parents:records[path]=(int(mode,8),digest)
        elif (name.startswith('/usr/bin/satsuma-') or name.startswith('/usr/lib/systemd/system/satsuma')
              or name in ('/usr/libexec/satsuma-image','/usr/share/applications/satsuma-dashboard.desktop')):
            external[path]=(int(mode,8),digest)
    actual={root,*root.rglob('*')}
    if not records or actual!=set(records):raise RuntimeError('Staging payload differs from RPM inventory')
    for path,(mode,digest) in {**records,**external}.items():
        info=path.lstat()
        if info.st_mode!=mode or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022:
            raise PermissionError('Unsafe RPM payload: '+str(path))
        if stat.S_ISREG(mode):
            if not hmac.compare_digest(hashlib.sha256(read(path)).hexdigest(),digest):
                raise RuntimeError('RPM payload hash mismatch: '+str(path))
        elif not stat.S_ISDIR(mode):raise PermissionError('Unexpected payload type: '+str(path))
    return len(records)


def build():
    validate_payload()
    # Import only after independently validating every staged file against RPM metadata.
    sys.path.insert(0,str(PAYLOAD))
    from installer.integrity import provision_key,build as manifest_build,sign,verify
    key=provision_key()
    IMAGES.mkdir(parents=True,exist_ok=True,mode=0o700)
    with tempfile.TemporaryDirectory(prefix='.candidate-',dir=IMAGES) as temporary:
        work=Path(temporary);image=work/'runtime.squashfs'
        run(['/usr/bin/mksquashfs',str(PAYLOAD),str(image),'-noappend','-all-root','-comp','gzip','-processors','1','-no-progress'])
        run(['/usr/bin/unsquashfs','-s',str(image)])
        # Re-extract and compare *all* bytes/modes before selecting the image.
        extracted=work/'verify'
        run(['/usr/bin/unsquashfs','-no-progress','-d',str(extracted),str(image)])
        def inventory(root):
            result={}
            for path in [root,*root.rglob('*')]:
                info=path.lstat()
                result[str(path.relative_to(root))]=(info.st_mode,info.st_uid,info.st_gid,
                    hashlib.sha256(read(path)).hexdigest() if stat.S_ISREG(info.st_mode) else None)
            return result
        if inventory(extracted)!=inventory(PAYLOAD):raise RuntimeError('SquashFS readback differs from verified source')
        digest=hashlib.sha256(read(image,512*1024*1024)).hexdigest()
        bundle=IMAGES/digest
        if bundle.exists():
            if hashlib.sha256(read(bundle/'runtime.squashfs',512*1024*1024)).hexdigest()!=digest:
                raise RuntimeError('Existing image bundle is corrupt')
        else:
            bundle.mkdir(mode=0o700)
            os.chmod(image,0o600);os.replace(image,bundle/'runtime.squashfs')
        if not (bundle/'manifest.json').exists():
            manifest_build(PAYLOAD,bundle/'manifest.json')
            sign(bundle/'manifest.json',key)
        verify(PAYLOAD,bundle/'manifest.json',key_path=KEY)
        result={'schema':1,'sha256':digest,'manifest':'manifest.json'}
        atomic(IMAGES/'pending.json',authenticated(result))
        return result


def mount():
    data,image=active()
    MOUNT.mkdir(parents=True,exist_ok=True,mode=0o755)
    info=MOUNT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise PermissionError('Unsafe runtime mount point')
    if os.path.ismount(MOUNT):
        check_mount(image);return
    run(['/usr/bin/mount','-t','squashfs','-o','loop,ro,nodev,nosuid',str(image),str(MOUNT)])
    check_mount(image)


def check_mount(image):
    # 2.2.38: on Fedora Atomic /opt is a link to var/opt and the kernel records
    # the mount at /var/opt/satsuma-core; ask for the real path. Normal Fedora: same path.
    # ostree'de /opt -> var/opt bağıdır; bağlama noktası gerçek yoluyla sorulur.
    data=json.loads(run(['/usr/bin/findmnt','--json','--mountpoint',os.path.realpath(MOUNT),'-o','FSTYPE,OPTIONS,SOURCE']).stdout)
    entry=data['filesystems'][0]
    if entry['fstype']!='squashfs' or not {'ro','nodev','nosuid'}.issubset(set(entry['options'].split(','))):
        raise RuntimeError('Runtime is not a read-only SquashFS mount')
    loops=json.loads(run(['/usr/sbin/losetup','--json','--list','--output','NAME,BACK-FILE']).stdout)['loopdevices']
    def device_name(value):
        # util-linux marks a loop node hidden by systemd PrivateDevices as
        # "(lost)" even while its mounted kernel device and sysfs backing file
        # remain valid. Strip only that exact annotation on numeric loop names.
        if isinstance(value,str) and re.fullmatch(r'/dev/loop[0-9]+ \(lost\)',value):
            return value.removesuffix(' (lost)')
        return value
    if not any(device_name(item['name'])==entry['source'] and item['back-file']==str(image) for item in loops):
        raise RuntimeError('Runtime mount uses an unexpected backing image')


def activate():
    pending=read(IMAGES/'pending.json',65536)
    envelope=json.loads(pending);data=envelope['data']
    if not hmac.compare_digest(envelope['hmac'],hmac.new(read(KEY,32),encoded(data),hashlib.sha256).hexdigest()):
        raise PermissionError('Untrusted candidate image')
    if not re.fullmatch('[a-f0-9]{64}',data.get('sha256','')):raise ValueError('Invalid candidate path')
    candidate=IMAGES/data['sha256']/'runtime.squashfs'
    if hashlib.sha256(read(candidate,512*1024*1024)).hexdigest()!=data['sha256']:raise RuntimeError('Candidate image changed')
    previous=read(ACTIVE,65536) if ACTIVE.exists() else None
    if previous:atomic(IMAGES/'previous.json',previous)
    # Package transaction stops application services before calling activate.
    if os.path.ismount(MOUNT):run(['/usr/bin/umount',str(MOUNT)])
    try:
        atomic(ACTIVE,pending);mount()
    except Exception:
        if os.path.ismount(MOUNT):run(['/usr/bin/umount',str(MOUNT)])
        if previous:
            atomic(ACTIVE,previous);mount()
        else:ACTIVE.unlink(missing_ok=True)
        raise
    (IMAGES/'pending.json').unlink()
    return data


def legacy_check():
    """Remove only the retired Satsuma-owned egress table, atomically."""
    tables=json.loads(run(['/usr/sbin/nft','-j','list','tables']).stdout).get('nftables',[])
    if any(row.get('table',{}).get('family')=='inet' and row['table'].get('name')=='satsuma_apps' for row in tables):
        table=json.loads(run(['/usr/sbin/nft','-j','list','table','inet','satsuma_apps']).stdout)
        if not any(row.get('table',{}).get('comment')=='Satsuma application egress' for row in table.get('nftables',[])):
            raise PermissionError('Retired table ownership mismatch')
        run(['/usr/sbin/nft','delete','table','inet','satsuma_apps'])


def main():
    if os.geteuid()!=0:raise PermissionError('Root required')
    parser=argparse.ArgumentParser();parser.add_argument('action',choices=['build','activate','mount','verify','unmount','cleanup-firewall','legacy-check']);args=parser.parse_args()
    if args.action!='verify':IMAGES.mkdir(parents=True,exist_ok=True,mode=0o700)
    for parent in (IMAGES,*IMAGES.parents):
        info=parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:
            raise PermissionError('Unsafe image directory')
    flags=os.O_RDONLY if args.action=='verify' else os.O_CREAT|os.O_RDWR
    fd=os.open(IMAGES/'.lock',flags|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1 or info.st_mode&0o077:
            raise PermissionError('Unsafe image lock')
        fcntl.flock(fd,fcntl.LOCK_EX)
        if args.action=='build':print(json.dumps(build()))
        elif args.action=='activate':print(json.dumps(activate()))
        elif args.action=='mount':mount()
        elif args.action=='legacy-check':legacy_check()
        elif args.action=='verify':_,image=active();check_mount(image)
        elif args.action=='unmount':print(json.dumps(unmount()))
        elif args.action=='cleanup-firewall':
            result=cleanup_firewall();atomic(IMAGES/'removal.json',encoded(result))
            print(json.dumps(result))
            if result['retained_unmarked_tables']:
                print('SATSUMA: unmarked tables retained for operator review; see '+str(IMAGES/'removal.json'),file=sys.stderr)
    finally:os.close(fd)


if __name__=='__main__':main()
