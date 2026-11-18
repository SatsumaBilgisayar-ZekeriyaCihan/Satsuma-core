"""Authenticated local application inventory. A trusted kernel/root remains required.

Since 2.2.36 provision_key() always creates a fresh key; no key of the pre-2.2 product is adopted.
Yerel uygulama envanteri doğrulaması; güvenilir çekirdek/root gerekir. 2.2.36'dan beri
provision_key() her zaman yeni anahtar üretir; 2.2 öncesi ürünün hiçbir anahtarı benimsenmez.
"""
from pathlib import Path
import hashlib, json, os, stat, hmac, secrets
KEY=Path('/etc/satsuma-core/trust/manifest.key')
ROOT=Path('/opt/satsuma-core')
PAYLOAD=Path('/usr/lib/satsuma-core/payload')
MANIFEST=Path('/usr/share/satsuma-core/installation-sha256.json')
REQUIRED=('main.py','installer/integrity.py','satsuma/early_guard.py',
          'satsuma/integrity_monitor.py','satsuma/app_firewall.py',
          'satsuma/config.py','satsuma/operator_service.py','satsuma/dashboard_api.py')


class ApplicationTampered(RuntimeError):
    code='APPLICATION_TAMPERED'


class ApplicationSignatureMismatch(PermissionError):
    code='APPLICATION_TAMPERED'


LINK_HOPS=8


def _root_link(directory_fd, name):
    """Target of a link only root could have placed, else None.

    2.2.39 (owner's Fedora Atomic report 2026-11-18: "Not a directory: 'opt'",
    every Satsuma service down): on Fedora Atomic /opt, /home, /root, /srv,
    /mnt and /usr/local are links into /var, so a walk that refused every link
    failed at its first step. A link is followed only when it is owned by root
    and sits in a root-owned folder no one else can write: nobody but root can
    have put it there, and root is the trust anchor anyway. A substituted link
    in a folder others can write, or a link owned by another user, is refused
    as before; the file itself is never a link.
    Atomic'te /opt, /home, /root ... /var'a bağdır. Bağ yalnızca root'a aitse ve
    başkasının yazamadığı root klasöründeyse izlenir; başka her bağ reddedilir.
    """
    try:
        info=os.stat(name,dir_fd=directory_fd,follow_symlinks=False)
    except OSError:
        return None
    folder=os.fstat(directory_fd)
    if not stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or folder.st_uid!=0 or folder.st_mode&0o022:
        return None
    return os.readlink(name,dir_fd=directory_fd)


def open_parent(path, ownership=True):
    """(folder fd, final name) for path; the caller closes the fd.

    Parents are opened one descriptor at a time. ownership=True also requires
    every folder to be root's and not writable by group or others.
    """
    path=Path(path)
    import errno
    fd=os.open(path.anchor or '.',os.O_RDONLY|os.O_DIRECTORY)
    pending=list(path.parts[1:-1] if path.is_absolute() else path.parts[:-1])
    hops=0
    try:
        while pending:
            part=pending.pop(0)
            try:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            except OSError as exc:
                target=_root_link(fd,part) if exc.errno in (errno.ENOTDIR,errno.ELOOP) else None
                if target is None or hops>=LINK_HOPS:
                    raise
                hops+=1
                if target.startswith('/'):
                    os.close(fd);fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
                pending=[x for x in Path(target).parts if x!='/']+pending
                continue
            os.close(fd);fd=child
            st=os.fstat(fd)
            if ownership and (st.st_uid!=0 or st.st_mode&0o022):
                raise PermissionError('Unsafe parent: '+str(path))
        return fd,path.name
    except BaseException:
        os.close(fd);raise


def safe_read(path, ownership=True, limit=128*1024*1024):
    path=Path(path)
    # Walk parent descriptors; never follow a substituted directory symlink
    # (only links root alone could have placed, see _root_link).
    fd,name=open_parent(path,ownership)
    try:
        stream=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=fd)
        with os.fdopen(stream,'rb') as f:
            info=os.fstat(f.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1
                or (ownership and (info.st_uid!=0 or info.st_mode&0o022))):
                raise PermissionError('Unsafe file: '+str(path))
            value=f.read(limit+1)
            if len(value)>limit:raise ValueError('File exceeds capacity: '+str(path))
            after=os.fstat(f.fileno())
            if (info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
                raise RuntimeError('File changed while checking: '+str(path))
            return value,info
    finally:os.close(fd)


def paths(root):
    found={'.':root}
    for directory,dirs,names in os.walk(root,followlinks=False):
        dirs[:]=[n for n in dirs if n!='__pycache__']
        for name in dirs+names:
            p=Path(directory)/name
            if p.suffix not in ('.pyc','.pyo'):
                found[str(p.relative_to(root))]=p
    return found


def record(path, ownership=True):
    info=path.lstat()
    if stat.S_ISDIR(info.st_mode):
        if ownership and (info.st_uid!=0 or info.st_mode&0o022):raise PermissionError(str(path))
        return {'kind':'directory','mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid}
    raw,info=safe_read(path,ownership)
    return {'kind':'file','mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,
            'sha256':hashlib.sha256(raw).hexdigest()}


def external_files():
    import subprocess
    query=subprocess.run(['/usr/bin/rpm','-q','--qf','[%{FILENAMES}\n]','satsuma-core'],
                         capture_output=True,text=True,check=True,timeout=30)
    return [Path(x) for x in query.stdout.splitlines()
            if x.startswith('/usr/bin/satsuma-') or x.startswith('/usr/lib/systemd/system/satsuma')
            or x=='/usr/share/applications/satsuma-dashboard.desktop' or x=='/usr/libexec/satsuma-image']


def build(root=ROOT,target=MANIFEST):
    data={'schema':2,'files':{name:record(p,root in (ROOT,PAYLOAD)) for name,p in paths(root).items()},'external':{}}
    if root in (ROOT,PAYLOAD):
        if not set(REQUIRED).issubset(data['files']):raise RuntimeError('Required protection component missing')
        data['external']={str(p):record(p) for p in external_files()}
    target.parent.mkdir(parents=True,exist_ok=True)
    import tempfile
    fd,temp=tempfile.mkstemp(prefix='.inventory-',dir=target.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(data,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
        os.chmod(temp,0o644);os.replace(temp,target)
    finally:
        if os.path.exists(temp):os.unlink(temp)


def verify(root=ROOT,target=MANIFEST,ownership=True,key_path=None):
    if target==MANIFEST:
        envelope=json.loads(safe_read(Path('/var/lib/satsuma-core/images/active.json'),ownership,65536)[0])
        data=envelope['data'];key=read_key(KEY,ownership)
        encoded=json.dumps(data,sort_keys=True,separators=(',',':')).encode()
        if not hmac.compare_digest(envelope['hmac'],hmac.new(key,encoded,hashlib.sha256).hexdigest()):
            raise ApplicationSignatureMismatch('Image activation signature mismatch')
        import re
        if not re.fullmatch('[a-f0-9]{64}',data.get('sha256','')):raise ValueError('Invalid image digest')
        target=Path('/var/lib/satsuma-core/images')/data['sha256']/'manifest.json'
        key_path=KEY
        if root==ROOT:
            import subprocess
            subprocess.run(['/usr/bin/python3','-I','-B','/usr/libexec/satsuma-image','verify'],check=True,capture_output=True,timeout=60)
    raw,_=safe_read(target,ownership,16*1024*1024)
    signed_key=Path(key_path) if key_path is not None else (KEY if target==MANIFEST else None)
    if signed_key is not None:
        key=read_key(signed_key,ownership)
        signature,_=safe_read(Path(str(target)+'.sig'),ownership,128)
        if not hmac.compare_digest(hmac.new(key,raw,hashlib.sha256).digest(),signature):
            raise ApplicationSignatureMismatch('Installation manifest signature mismatch')
    manifest=json.loads(raw)
    if manifest.get('schema')!=2:raise RuntimeError('Application inventory migration required through RPM installation')
    expected=manifest.get('files',{})
    if not expected:raise RuntimeError('Empty installation inventory')
    actual=paths(root)
    if set(actual)!=set(expected):
        raise ApplicationTampered('Installation inventory mismatch: missing='+str(sorted(set(expected)-set(actual)))+' extra='+str(sorted(set(actual)-set(expected))))
    if root in (ROOT,PAYLOAD) and not set(REQUIRED).issubset(expected):raise RuntimeError('Required protection files missing')
    for name,p in actual.items():
        if record(p,ownership)!=expected[name]:raise ApplicationTampered('Integrity mismatch: '+str(p))
    for name,entry in manifest.get('external',{}).items():
        if not (name.startswith('/usr/bin/satsuma-') or name.startswith('/usr/lib/systemd/system/satsuma') or name=='/usr/share/applications/satsuma-dashboard.desktop' or name=='/usr/libexec/satsuma-image'):
            raise ValueError('Out-of-scope manifest entry')
        if record(Path(name),ownership)!=entry:raise ApplicationTampered('Integrity mismatch: '+name)
    return len(expected)+len(manifest.get('external',{}))


def read_key(path=KEY, ownership=True):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o077 or (ownership and info.st_uid != 0):
            raise PermissionError('Unsafe manifest key')
        key = os.read(fd, 4096)
        if len(key) != 32:raise ValueError('Expected a 32-byte HMAC key')
        return key
    finally:os.close(fd)


def provision_key(path=KEY):
    from satsuma.protected_storage import open_directory
    if path.exists() or path.is_symlink():return read_key(path)
    directory = open_directory(path.parent)
    try:
        # 2.2.36: always a fresh key. A key left by the pre-2.2 product is never
        # adopted: if it leaked while that product ran, it would keep signing
        # the manifest and the DNS configuration.
        # 2.2.36: her zaman yeni anahtar. 2.2 öncesi üründen kalan anahtar asla
        # benimsenmez; o ürün çalışırken sızmışsa manifestoyu ve DNS
        # yapılandırmasını imzalamaya devam ederdi.
        key = secrets.token_bytes(32)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        try:
            os.write(fd,key);os.fsync(fd)
        finally:os.close(fd)
        return key
    finally:os.close(directory)


def file_hmac(key,path):
    digest=hmac.new(key,digestmod=hashlib.sha256)
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b""):digest.update(chunk)
    return digest.digest()


def sign(target, key):
    import tempfile
    signature = file_hmac(key,target)
    fd, temp = tempfile.mkstemp(prefix='.signature-',dir=target.parent)
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(signature);stream.flush();os.fsync(stream.fileno())
        os.chmod(temp,0o644)
        os.replace(temp,str(target)+'.sig')
    finally:
        if os.path.exists(temp):os.unlink(temp)


if __name__=='__main__':
    print('Application inventory verified:',verify())
