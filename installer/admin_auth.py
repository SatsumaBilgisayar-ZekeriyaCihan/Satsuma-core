"""Root-only admin credential setup and PAM verification. Passwords only via tty/pipe."""
import os,sys,json,hashlib,hmac,secrets,getpass,fcntl,time,stat
from pathlib import Path
CREDENTIAL=Path('/etc/satsuma-core/sudo-admin.json')
STATE=Path('/var/lib/satsuma-admin/attempts.json')

def digest(password,salt):return hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(salt),600000).hex()
def valid(password,record):return hmac.compare_digest(digest(password,record['salt']),record['digest'])
def read_secure(path):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    try:
        st=os.fstat(fd)
        if st.st_uid!=0 or st.st_mode&0o077 or not stat.S_ISREG(st.st_mode):raise PermissionError('Private root-owned credential required')
        with os.fdopen(os.dup(fd)) as f:return json.load(f)
    finally:os.close(fd)
def setup():
    if CREDENTIAL.exists():
        old=read_secure(CREDENTIAL)
        if not valid(getpass.getpass('Mevcut Satsuma yonetici parolasi: '),old):raise ValueError('Parola reddedildi')
        return
    a=getpass.getpass('Yeni Satsuma yonetici parolasi (en az 12 karakter): ')
    b=getpass.getpass('Parolayi tekrar girin: ')
    if a!=b or len(a)<12 or len(a.encode())>1024:raise ValueError('Parolalar uyusmuyor veya uzunluk uygun degil')
    salt=secrets.token_hex(32);record={'scheme':'pbkdf2_sha256','iterations':600000,'salt':salt,'digest':digest(a,salt)}
    fd=os.open(CREDENTIAL,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as f:json.dump(record,f);f.flush();os.fsync(f.fileno())
def verify(password):
    STATE.parent.mkdir(mode=0o700,exist_ok=True)
    fd=os.open(STATE,os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'r+') as f:
        fcntl.flock(f,fcntl.LOCK_EX)
        raw=f.read();state=json.loads(raw) if raw else {};now=time.time()
        if state.get('until',0)>now:return False
        ok=valid(password,read_secure(CREDENTIAL))
        failures=0 if ok else int(state.get('failures',0))+1
        state={'failures':failures,'until':now+60 if failures>=5 else 0}
        if failures>=5:state['failures']=0
        f.seek(0);json.dump(state,f);f.truncate();f.flush();os.fsync(f.fileno())
        return ok
if __name__=='__main__':
    if os.geteuid()!=0:sys.exit(1)
    try:
        if sys.argv[1]=='setup':setup()
        elif sys.argv[1]=='verify':sys.exit(0 if verify(sys.stdin.buffer.read(1025).decode('utf-8')) else 1)
        else:sys.exit(2)
    except Exception:
        print('Satsuma yonetici dogrulamasi basarisiz.',file=sys.stderr);sys.exit(1)
