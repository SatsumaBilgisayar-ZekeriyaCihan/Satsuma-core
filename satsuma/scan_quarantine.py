"""Quarantine of a specific, unchanged ClamAV scan target.

Used from the dashboard and, since 2.2.11, automatically after every scan
(satsuma.security_scan). The file is moved into a private directory with
its identity checked before and after; it is never deleted. When the file
lives on another filesystem (/tmp, /dev/shm, a separate /home), it is copied,
the copy is verified, and only then is the original unlinked, provided it is
still the same inode. System directories (/usr/bin, /etc…) are never touched
here, except a program in /usr/bin or /usr/sbin that satsuma.binary_audit
confirmed as malware (system_ok). Since 2.2.15 every quarantine is
restorable (restore_target puts the file back with its mode, owner and
SELinux label), and a file taken from a program directory is put back
automatically by /usr/libexec/satsuma-quarantine-rollback if the next boot
does not complete.

Belirli ve değişmemiş bir ClamAV tarama hedefinin karantinası.

Panelden ve 2.2.11'den beri her taramadan sonra otomatik olarak
(satsuma.security_scan) kullanılır. Dosya, kimliği öncesinde ve sonrasında
denetlenerek özel bir klasöre taşınır; asla silinmez. Dosya başka bir
dosya sistemindeyse (/tmp, /dev/shm, ayrı /home) kopyalanır, kopya
doğrulanır ve ancak ondan sonra, hâlâ aynı inode ise asıl dosya kaldırılır.
Sistem klasörlerine (/usr/bin, /etc…) burada dokunulmaz; satsuma.binary_audit'in
zararlı olduğunu doğruladığı /usr/bin ya da /usr/sbin programı hariç (system_ok).
2.2.15'ten beri her karantina geri alınabilir (restore_target dosyayı izni,
sahibi ve SELinux etiketiyle geri koyar); program klasöründen alınan dosya,
bir sonraki açılış tamamlanmazsa /usr/libexec/satsuma-quarantine-rollback
tarafından otomatik olarak yerine konur.
"""
import base64
import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

MAX_FILE_BYTES=64*1024*1024
QUARANTINE=Path('/var/lib/satsuma-core/scan-quarantine')
# 2.2.39: Fedora Atomic keeps these under /var (/home -> var/home and so
# on); scanners report the real path. Atomic'te bu kökler /var altındadır.
ALLOWED_ROOTS=(Path('/home'),Path('/opt'),Path('/root'),Path('/tmp'),Path('/var/tmp'),Path('/dev/shm'),
               Path('/usr/local'),Path('/srv'),
               Path('/var/home'),Path('/var/opt'),Path('/var/roothome'),Path('/var/usrlocal'),Path('/var/srv'))
# Program directories, only for malware confirmed by satsuma.binary_audit.
SYSTEM_ROOTS=(Path('/usr/bin'),Path('/usr/sbin'),Path('/usr/local/bin'),Path('/usr/local/sbin'),
              Path('/var/usrlocal/bin'),Path('/var/usrlocal/sbin'),Path('/var/usrlocal/share'),
              # Media checked by satsuma.media_audit (2.2.15).
              Path('/usr/share/icons'),Path('/usr/share/pixmaps'),Path('/usr/share/fonts'),Path('/usr/share/man'),
              Path('/usr/local/share'))
# A file taken from a program directory waits here until a boot completes;
# /usr/libexec/satsuma-quarantine-rollback puts it back if the next boot
# does not finish (2.2.15, user decision 2026-10-26).
PENDING=Path('/var/lib/satsuma-core/quarantine-pending')


def _metadata(fd,path):
    info=os.fstat(fd)
    xattrs={}
    try:
        for name in os.listxattr(fd):
            try:xattrs[name]=base64.b64encode(os.getxattr(fd,name)).decode()
            except OSError:continue
    except OSError:pass
    return {'path':str(path),'mode':stat.S_IMODE(info.st_mode),'uid':info.st_uid,'gid':info.st_gid,'xattrs':xattrs}


def _write_private(directory_fd,name,text):
    out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600,dir_fd=directory_fd)
    try:
        os.write(out,text.encode());os.fsync(out)
    finally:os.close(out)


def _mark_pending(ident,meta,stored,pending=PENDING):
    """Plain files the shell rollback can read without Python."""
    entry=Path(pending)/ident
    entry.mkdir(parents=True,mode=0o700)
    for name,value in (('original',meta['path']),('stored',str(stored)),
                       ('mode','%o'%meta['mode']),('owner','%d:%d'%(meta['uid'],meta['gid']))):
        (entry/name).write_text(value)
        os.chmod(entry/name,0o600)
    return str(entry)


def open_parent(path):
    path=Path(path)
    if not path.is_absolute() or '..' in path.parts or path.name in ('', '.', '..'):
        raise ValueError('An absolute file path is required')
    # 2.2.39: the same walk as the integrity check: a link is followed only
    # when root alone could have placed it (Fedora Atomic /home -> var/home).
    # User folders are not required to be root's here.
    from installer.integrity import open_parent as walk
    return walk(path, ownership=False)


def fingerprint(fd):
    before=os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_size>MAX_FILE_BYTES:
        raise ValueError('Only a bounded regular file with one link may be quarantined')
    digest=hashlib.sha256();os.lseek(fd,0,os.SEEK_SET);total=0
    while True:
        chunk=os.read(fd,65536)
        if not chunk:break
        total+=len(chunk)
        if total>MAX_FILE_BYTES:raise ValueError('File grew beyond capacity')
        digest.update(chunk)
    after=os.fstat(fd)
    keys=('st_dev','st_ino','st_size','st_mtime_ns','st_ctime_ns')
    if any(getattr(before,k)!=getattr(after,k) for k in keys):
        raise ValueError('File changed while hashing; scan again')
    return {'sha256':digest.hexdigest(),'device':after.st_dev,'inode':after.st_ino,
            'size':after.st_size,'mtime_ns':after.st_mtime_ns}


def inspect_target(path):
    parent,name=open_parent(path)
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:return {'path':str(path),**fingerprint(fd)}
        finally:os.close(fd)
    finally:os.close(parent)


def _copy_then_unlink(fd,actual,name,parent,ident,destfd):
    """Cross-filesystem move: verified copy first, then unlink the same inode."""
    out=os.open(ident,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=destfd)
    try:
        os.lseek(fd,0,os.SEEK_SET)
        while True:
            chunk=os.read(fd,65536)
            if not chunk:break
            os.write(out,chunk)
        os.fsync(out)
    finally:os.close(out)
    copy=os.open(ident,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=destfd)
    try:
        digest=hashlib.sha256()
        while True:
            chunk=os.read(copy,65536)
            if not chunk:break
            digest.update(chunk)
    finally:os.close(copy)
    if digest.hexdigest()!=actual['sha256']:
        os.unlink(ident,dir_fd=destfd)
        raise RuntimeError('Quarantine copy differs from the scanned file; original left in place')
    current=os.stat(name,dir_fd=parent,follow_symlinks=False)
    if (current.st_dev,current.st_ino)!=(actual['device'],actual['inode']):
        raise RuntimeError('Original was replaced during quarantine; copy kept, original left for review')
    # Checking only the inode misses in-place modification after scanning.
    # Rehash the still-open original immediately before unlink.  A changed
    # file must stay at its source, even if the quarantine copy was valid.
    try:
        final=fingerprint(fd)
    except (OSError, ValueError) as exc:
        raise RuntimeError('Original changed during quarantine; source preserved') from exc
    if any(final[k]!=actual[k] for k in ('sha256','device','inode','size','mtime_ns')):
        raise RuntimeError('Original changed during quarantine; source preserved')
    os.unlink(name,dir_fd=parent)


def quarantine_target(target, audit, *, directory=QUARANTINE, system_ok=False, pending=PENDING, extra_roots=()):
    path=Path(target['path'])
    # System configuration and Satsuma's own payload need a repair workflow,
    # not a file-removal button; program directories only for confirmed malware.
    # extra_roots: satsuma.remediation's persistence files (/etc...), already checked
    # against its own allow and protect lists (2.2.56).
    roots=ALLOWED_ROOTS+(SYSTEM_ROOTS if system_ok else ())+tuple(extra_roots)
    if not any(path.is_relative_to(root) for root in roots) or path.is_relative_to('/opt/satsuma-core') \
            or path.is_relative_to('/var/opt/satsuma-core'):
        raise PermissionError('System or unsupported target path requires manual repair')
    parent,name=open_parent(path)
    try:
        fd=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=parent)
        try:
            actual=fingerprint(fd)
            if any(actual[k]!=target.get(k) for k in actual):
                raise ValueError('Scan target changed; scan again before quarantine')
            meta={**_metadata(fd,path),'sha256':actual['sha256']}
            directory=Path(directory)
            from .protected_storage import check,open_directory
            base=open_directory(directory.parent)
            try:
                try:os.mkdir(directory.name,0o700,dir_fd=base)
                except FileExistsError:pass
                destfd=os.open(directory.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=base)
            finally:os.close(base)
            try:
                info=os.fstat(destfd);check(info,True)
                if info.st_mode & 0o077:raise PermissionError('Quarantine directory must be private')
                ident=uuid.uuid4().hex
                audit({'status':'REQUESTED','quarantine_id':ident,'target':target})
                copied=False
                try:
                    # rename is atomic within one filesystem.
                    os.rename(name,ident,src_dir_fd=parent,dst_dir_fd=destfd)
                except OSError as exc:
                    if exc.errno!=errno.EXDEV:raise
                    _copy_then_unlink(fd,actual,name,parent,ident,destfd);copied=True
                moved=os.open(ident,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=destfd)
                try:
                    current=fingerprint(moved)
                    # A copied file has a new inode and timestamps; content must match.
                    keys=('sha256','size') if copied else tuple(actual)
                    if any(current[k]!=actual[k] for k in keys):
                        audit({'status':'IDENTITY_MISMATCH','quarantine_id':ident,'source':str(path)})
                        raise RuntimeError('Moved file identity mismatch; retained for administrator review')
                    os.fchmod(moved,0o600)
                    os.fchown(moved,os.geteuid(),os.getegid())
                    os.fsync(moved)
                finally:os.close(moved)
                _write_private(destfd,ident+'.json',json.dumps({**meta,'quarantine_id':ident},ensure_ascii=False))
                os.fsync(parent);os.fsync(destfd)
                system=any(path.is_relative_to(root) for root in SYSTEM_ROOTS)
                result={'status':'quarantined','quarantine_id':ident,'source':str(path),
                        'sha256':actual['sha256'],'scope':'local_file','permanently_deleted':False,
                        'method':'verified_copy' if copied else 'rename','restorable':True}
                if system:
                    result['boot_verification']=_mark_pending(ident,meta,directory/ident,pending)
                audit(result)
                return result
            finally:os.close(destfd)
        finally:os.close(fd)
    finally:os.close(parent)


def restore_target(ident, audit, *, directory=QUARANTINE, pending=PENDING):
    """Put a quarantined file back with its mode, owner and extended attributes."""
    if not ident or not all(c in '0123456789abcdef' for c in ident) or len(ident)!=32:
        raise ValueError('Invalid quarantine id')
    directory=Path(directory)
    meta=json.loads((directory/(ident+'.json')).read_text())
    if meta.get('kind')=='ssh_authorized_key':
        # An authorized_keys entry (satsuma.ssh_keys): put its lines back.
        from .ssh_keys import restore_authorized
        result=restore_authorized(meta,audit)
        (directory/(ident+'.json')).unlink()
        return result
    path=Path(meta['path'])
    stored=directory/ident
    fd=os.open(stored,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        if fingerprint(fd)['sha256']!=meta['sha256']:
            raise RuntimeError('Quarantined copy changed; not restored')
        parent,name=open_parent(path)
        try:
            try:
                os.stat(name,dir_fd=parent,follow_symlinks=False)
                raise FileExistsError('A file already exists at '+str(path)+'; not overwritten')
            except FileNotFoundError:
                pass
            try:
                os.rename(stored,name,dst_dir_fd=parent)
            except OSError as exc:
                if exc.errno!=errno.EXDEV:raise
                out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                try:
                    os.lseek(fd,0,os.SEEK_SET)
                    for chunk in iter(lambda:os.read(fd,65536),b''):os.write(out,chunk)
                    os.fsync(out)
                finally:os.close(out)
                os.unlink(stored)
            back=os.open(name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
            try:
                os.fchown(back,meta['uid'],meta['gid'])
                os.fchmod(back,meta['mode'])
                for key,value in meta.get('xattrs',{}).items():
                    try:os.setxattr(back,key,base64.b64decode(value))
                    except OSError:continue
                os.fsync(back)
            finally:os.close(back)
            os.fsync(parent)
        finally:os.close(parent)
    finally:os.close(fd)
    (directory/(ident+'.json')).unlink()
    entry=Path(pending)/ident
    if entry.is_dir():
        for child in entry.iterdir():child.unlink()
        entry.rmdir()
    result={'status':'restored','quarantine_id':ident,'path':str(path),'sha256':meta['sha256']}
    audit(result)
    return result


def list_quarantine(directory=QUARANTINE, pending=PENDING):
    """Every restorable quarantined file, newest first."""
    rows=[]
    for meta_path in sorted(Path(directory).glob('*.json'),key=lambda p:p.stat().st_mtime,reverse=True):
        try:meta=json.loads(meta_path.read_text())
        except (OSError,ValueError):continue
        ident=meta_path.stem
        label=meta.get('path') if meta.get('kind')!='ssh_authorized_key' else \
            str(meta.get('path'))+' · SSH anahtarı '+str(meta.get('fingerprint'))
        rows.append({'quarantine_id':ident,'path':label,'sha256':meta.get('sha256'),
                     'boot_verification_pending':(Path(pending)/ident).is_dir()})
    return rows
