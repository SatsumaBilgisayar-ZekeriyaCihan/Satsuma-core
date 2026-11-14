"""Dedicated Audit reader worker."""
import fcntl,os,signal,time
from satsuma.audit_host import AuditReader
from satsuma.config import load_with_policy
from satsuma.host_store import HostStore


def run():
    from satsuma.runtime_user import require_service_user; require_service_user()
    os.umask(0o077);config,meta,_=load_with_policy();store=HostStore(archive_budget=config['archive_budget_bytes'])
    lock=os.open(store.root/'audit-worker.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);running=True;reader=None
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        if not config['audit_enabled']:
            while running:
                store.set('audit_health',{'updated_at':time.time(),'status':'DISABLED','policy':meta});time.sleep(1)
        else:
            reader=AuditReader(store,config['audit_log_path'])
            while running:
                status=reader.poll();store.set('audit_health',{**status,'updated_at':time.time(),'status':'RUNNING' if status['status']=='READING' else status['status'],'policy':meta});time.sleep(.25)
    finally:
        if reader:reader.close()
        store.close();os.close(lock)
