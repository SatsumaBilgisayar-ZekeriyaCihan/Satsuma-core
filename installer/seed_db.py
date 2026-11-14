import sys,time
sys.path.insert(0,'/opt/satsuma-core')
from satsuma.store import Store
from satsuma.host_store import HostStore
from satsuma.auto_action import AutoActionEngine
if sys.argv[1:] == ['--refresh-verified-runtime']:
    import os, stat
    from installer.integrity import verify
    verify()
    from satsuma.dashboard_auth import read_admin_hash, write_admin_hash, ADMIN_HASH_PATH
    credential = read_admin_hash()
    if credential and (ADMIN_HASH_PATH.stat().st_mode & 0o077):
        # Preserve the password while removing legacy group-readable access.
        write_admin_hash(credential)
    s = Store()
    baseline = s.get('critical_paths_baseline', {}) or {}
    # Refresh only the RPM-owned runtime paths. Host paths retain their identity.
    for path in ('/opt/satsuma-core/main.py', '/opt/satsuma-core/satsuma'):
        info = os.stat(path)
        baseline[path] = {'device': info.st_dev, 'inode': info.st_ino, 'type': stat.S_IFMT(info.st_mode)}
    s.set('critical_paths_baseline', baseline)
    s.add('events', {'action': 'verified_runtime_identity_updated', 'timestamp': time.time()})
    s.close()
    raise SystemExit(0)
s=Store();h=HostStore();AutoActionEngine(s,{})
s.db.execute("UPDATE commands SET status='migration_review' WHERE status IN ('pending','running')")
s.db.commit();s.add('events',{'action':'release_installed','version':__import__('satsuma').__version__,'timestamp':time.time(),'note':'Previous pending commands retained for review'})
s.close();h.close()
