"""Stop known remote servers/shares while preserving TeamViewer/AnyDesk clients.

Standalone so the exact script can run in RPM pre-install before payload extraction.
Vendor relay session direction cannot be inferred from TCP connection direction.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import tempfile
import time

ROOT=Path('/var/lib/satsuma-core/containment')
STATUS=ROOT/'status.json'
_USER_RELOADS={}
EXACT={'sshd','ssh','xrdp','xrdp-sesman','gnome-remote-desktop','gnome-remote-desktop-headless',
       'krdpserver','x11vnc','wayvnc','x2goserver','rustdesk','nxserver','meshagent','dwagent',
       'smb','smbd','nmb','nmbd','samba','samba-ad-dc','nfs-server','nfs-mountd','rpcbind','cockpit','webmin',
       'wsdd','wsdd2','ksmbd','vsftpd','proftpd','pure-ftpd','gnome-user-share','rygel','minidlna','gerbera'}
BINARIES={'sshd','sshd-session','sshd-auth','xrdp','xrdp-sesman','gnome-remote-desktop-daemon',
          'krdpserver','x11vnc','wayvnc','x2goagent','rustdesk','nxserver.bin','meshagent','dwagent',
          'smbd','nmbd','rpc.mountd','rpc.nfsd','wsdd','wsdd2','ksmbd.mountd',
          'vsftpd','proftpd','pure-ftpd','gnome-user-share','rygel','minidlnad','gerbera'}

def server_unit(name):
    if not re.fullmatch(r'[A-Za-z0-9_.:@-]+\.(?:service|socket)',name): return False
    base=name.rsplit('.',1)[0]
    return base in EXACT or base.split('@',1)[0] in {'sshd','ssh','vncserver','tigervncserver','tigervncsession','xvnc','x11vnc','wayvnc'}

def run(args,check=True):
    return subprocess.run(args,capture_output=True,text=True,timeout=30,check=check,
                          env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})

def secure_directory(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            try: os.mkdir(part,0o700,dir_fd=fd)
            except FileExistsError: pass
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child;info=os.fstat(fd)
            if info.st_uid!=0 or info.st_mode&0o022: raise PermissionError('Unsafe containment directory: '+str(path))
    finally: os.close(fd)

def mask_local(name,user=False):
    directory=Path('/etc/systemd/user' if user else '/etc/systemd/system')
    secure_directory(directory)
    target=directory/name
    if target.is_symlink() and os.readlink(target)=='/dev/null': return False
    if os.path.lexists(target):
        info=target.lstat()
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            raise PermissionError('Unexpected unit override type: '+str(target))
        backup=ROOT/'backups'/str(time.time_ns()); secure_directory(backup)
        os.rename(target,backup/name)
    os.symlink('/dev/null',target)
    return True

def user_units():
    names=set()
    for folder in ('/usr/lib/systemd/user','/etc/systemd/user'):
        path=Path(folder)
        if path.is_dir(): names.update(x.name for x in path.iterdir() if server_unit(x.name))
    changed=any([mask_local(name,user=True) for name in names])
    return sorted(names),changed

def stop_processes():
    stopped=[]
    for process in Path('/proc').glob('[0-9]*'):
        pid=int(process.name)
        if pid<=1 or pid==os.getpid(): continue
        try:
            executable=Path(os.readlink(process/'exe')).name.removesuffix(' (deleted)')
            if executable not in BINARIES: continue
            fd=os.pidfd_open(pid)
            try:
                # Recheck executable after acquiring a stable process reference.
                if Path(os.readlink(process/'exe')).name.removesuffix(' (deleted)')!=executable: continue
                signal.pidfd_send_signal(fd,signal.SIGKILL)
                stopped.append({'pid':pid,'executable':executable})
            finally: os.close(fd)
        except (FileNotFoundError,ProcessLookupError): continue
    return stopped

def apply():
    if os.geteuid()!=0: raise PermissionError('Containment requires root')
    secure_directory(ROOT)
    errors=[]
    listed=run(['/usr/bin/systemctl','list-unit-files','--no-legend','--no-pager']).stdout
    loaded=run(['/usr/bin/systemctl','list-units','--all','--plain','--no-legend','--no-pager']).stdout
    units=sorted({line.split()[0] for text in (listed,loaded) for line in text.splitlines() if line.split() and server_unit(line.split()[0])})
    changed_units=[name for name in units if mask_local(name)]
    # systemctl disable normally reloads PID 1, even for an already masked
    # unit. Only remove enablement links after a mask actually changes, then
    # perform one explicit reload for the entire transaction.
    for name in changed_units:
        run(['/usr/bin/systemctl','--no-reload','disable','--',name],False)
    changed=bool(changed_units)
    if changed: run(['/usr/bin/systemctl','daemon-reload'])
    for name in units:
        if run(['/usr/bin/systemctl','is-active','--quiet',name],False).returncode==0:
            run(['/usr/bin/systemctl','stop','--',name])
        if run(['/usr/bin/systemctl','is-active','--quiet',name],False).returncode==0:
            errors.append('Remote server still active: '+name)
    masked_user,user_changed=user_units()
    if user_changed: _USER_RELOADS.clear()
    # Global user masks prevent new starts. Reload current user managers when present.
    if masked_user:
        import pwd
        present=set()
        for runtime in Path('/run/user').glob('[0-9]*'):
            if not (runtime/'bus').exists(): continue
            info=(runtime/'bus').stat()
            manager=(info.st_dev,info.st_ino,info.st_ctime_ns,tuple(masked_user))
            present.add(str(runtime))
            try: user=pwd.getpwuid(int(runtime.name)).pw_name
            except KeyError: continue
            prefix=['/usr/sbin/runuser','-u',user,'--','/usr/bin/env','-i','PATH=/usr/sbin:/usr/bin',
                    'XDG_RUNTIME_DIR='+str(runtime),'DBUS_SESSION_BUS_ADDRESS=unix:path='+str(runtime/'bus'),'/usr/bin/systemctl','--user']
            # A new user manager needs one reload, not one on every watch
            # iteration. Replacing its bus or changing masks invalidates it.
            if _USER_RELOADS.get(str(runtime))!=manager:
                reload=run(prefix+['daemon-reload'],False)
                if reload.returncode:
                    errors.append('User daemon reload failed for UID '+runtime.name)
                else: _USER_RELOADS[str(runtime)]=manager
            for name in masked_user:
                if run(prefix+['is-active','--quiet',name],False).returncode==0:
                    run(prefix+['stop','--',name],False)
                    if run(prefix+['is-active','--quiet',name],False).returncode==0:
                        errors.append('User remote server still active for UID '+runtime.name+': '+name)
        for runtime in set(_USER_RELOADS)-present: _USER_RELOADS.pop(runtime,None)
    stopped=stop_processes()
    report={'status':'guarded' if not errors else 'degraded','updated_at':time.time(),
            'server_units_masked':units,'global_user_units_masked':masked_user,'processes_stopped':stopped,
            'errors':errors,'client_services_preserved':['teamviewerd.service','anydesk.service'],
            'vendor_incoming_session_policy':'requires_native_policy_verification',
            'host_cleanliness_verified':False}
    fd,temp=tempfile.mkstemp(prefix='.status-',dir=ROOT)
    try:
        with os.fdopen(fd,'w') as stream: json.dump(report,stream);stream.flush();os.fsync(stream.fileno())
        os.replace(temp,STATUS)
    finally:
        if os.path.exists(temp): os.unlink(temp)
    return report

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--watch',action='store_true');parser.add_argument('--check',action='store_true');args=parser.parse_args()
    if args.check:
        for _ in range(30):
            try:
                report=json.loads(STATUS.read_text())
                if time.time()-report['updated_at']<20:
                    print(json.dumps(report));return 0 if report['status']=='guarded' else 1
            except (OSError,ValueError,KeyError): pass
            time.sleep(.5)
        raise RuntimeError('Containment startup was not verified')
    running=True
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    while running:
        report=apply()
        if not args.watch:
            print(json.dumps(report));return 0 if report['status']=='guarded' else 1
        for _ in range(20):
            if not running: break
            time.sleep(.5)
    return 0

if __name__=='__main__': raise SystemExit(main())
