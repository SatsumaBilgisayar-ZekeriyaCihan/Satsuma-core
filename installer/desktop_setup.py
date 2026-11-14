"""Idempotent desktop enrollment; passwords are initialized only over stdin."""
import argparse
import json
import os
import pwd
import subprocess
import sys

sys.path.insert(0,'/opt/satsuma-core')


def active_desktop_users(runner=subprocess.run):
    result=runner(['/usr/bin/loginctl','list-sessions','--no-legend','--no-pager'],
                  capture_output=True,text=True,timeout=10,check=True)
    users=set()
    for line in result.stdout.splitlines():
        fields=line.split()
        if not fields:continue
        session=runner(['/usr/bin/loginctl','show-session',fields[0],
                        '--property=Name,User,Active,Remote,Type,Class'],
                       capture_output=True,text=True,timeout=5,check=True)
        values=dict(row.split('=',1) for row in session.stdout.splitlines() if '=' in row)
        if (values.get('Active')=='yes' and values.get('Remote')=='no'
            and values.get('Type') in ('x11','wayland') and values.get('Class')=='user'
            and values.get('User','').isdigit() and int(values['User'])>=1000):
            users.add(values['Name'])
    return sorted(users)


def configure(user, password=None):
    import grp
    from installer.boot_setup import enroll_user,provision
    from satsuma.dashboard_auth import admin_hash_status,hash_password,write_admin_hash
    account=pwd.getpwnam(user)
    if account.pw_uid<1000 or account.pw_shell.endswith(('/nologin','/false')):
        raise ValueError('A normal desktop user is required')
    actor=os.environ.get('PKEXEC_UID')
    if actor and int(actor)!=account.pw_uid:
        raise PermissionError('Desktop enrollment must match the authenticated caller')
    provision()
    group=grp.getgrnam('satsuma-reader')
    if user not in group.gr_mem and account.pw_gid!=group.gr_gid:enroll_user(user)
    if password is not None:
        if not 12<=len(password)<=1024:raise ValueError('Password must contain 12 to 1024 characters')
        if admin_hash_status().get('configured'):raise ValueError('An administrator password is already configured')
        import fcntl
        import stat
        fd=os.open('/etc/satsuma-core/.admin-init.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077 or info.st_nlink!=1:
                raise PermissionError('Unsafe administrator setup lock')
            fcntl.flock(fd,fcntl.LOCK_EX)
            if admin_hash_status().get('configured'):raise ValueError('An administrator password is already configured')
            write_admin_hash(hash_password(password))
        finally:os.close(fd)
    return {'status':'DESKTOP_ENROLLED','user':user,'admin_credential':admin_hash_status()}


def main():
    if os.geteuid()!=0:raise PermissionError('Root required')
    parser=argparse.ArgumentParser()
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--auto',action='store_true');group.add_argument('--user')
    parser.add_argument('--password-stdin',action='store_true')
    args=parser.parse_args()
    if args.auto:
        users=active_desktop_users()
        if len(users)!=1:
            print(json.dumps({'status':'PENDING_DESKTOP','reason':'No unique active local desktop; enrollment runs on first launch'}))
            return 0
        user=users[0]
    else:user=args.user
    password=None
    if args.password_stdin:
        raw=sys.stdin.buffer.read(4097)
        if len(raw)>4096:raise ValueError('Password exceeds capacity')
        password=raw.decode('utf-8')
    print(json.dumps(configure(user,password)))
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception as exc:
        print('Desktop setup failed: '+str(exc),file=sys.stderr);raise SystemExit(1)
