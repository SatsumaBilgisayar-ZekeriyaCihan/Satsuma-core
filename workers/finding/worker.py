"""Dedicated finding review and evidence worker."""
import fcntl,json,os,signal,time
from satsuma.audit_host import correlate
from satsuma.config import load_with_policy
from satsuma.findings import review
from satsuma.host_store import HostStore


class FindingWorker:
    def __init__(self,store,config,meta):
        self.store=store;self.config=config;self.meta=meta;self.processed=0;self.last_persistence_scan=0.0;self.last_error=''
        store.db.execute("UPDATE jobs SET status='interrupted',result='Finding worker restarted during job' WHERE status='running' AND kind IN ('review','archive_finding','archive')");store.db.commit()


    def finish(self,ident,status,result):
        result.setdefault('timestamp',time.time())
        self.store.db.execute('UPDATE jobs SET status=?,result=? WHERE id=?',(status,json.dumps(result),ident));self.store.db.commit()

    def process_job(self):
        row=self.store.db.execute("SELECT id,kind,body FROM jobs WHERE status='pending' AND kind IN ('review','archive_finding','archive') ORDER BY id LIMIT 1").fetchone()
        if not row:return
        ident,kind,body=row;self.store.db.execute("UPDATE jobs SET status='running' WHERE id=?",(ident,));self.store.db.commit()
        try:
            obj=json.loads(body)
            if not self.config['evidence_enabled']:raise RuntimeError('Evidence worker is disabled by policy')
            if kind=='review':result={'archive':review(self.store,obj['finding_id'],obj['status'],obj['note'])}
            elif kind=='archive_finding':
                row=self.store.db.execute('SELECT body FROM findings WHERE finding_id=?',(obj['finding_id'],)).fetchone()
                if not row:raise ValueError('Finding not retained')
                finding=json.loads(row[0]);result=self.store.archive(finding);finding['archive']=result
                self.store.db.execute('UPDATE findings SET body=? WHERE finding_id=?',(json.dumps(finding),obj['finding_id']));self.store.db.commit()
            else:
                row=self.store.db.execute('SELECT kind,body FROM records WHERE id=?',(int(obj['record_id']),)).fetchone()
                if not row:raise ValueError('Selected host record no longer retained')
                result=self.store.archive({'kind':row[0],'body':json.loads(row[1])})
            self.finish(ident,'done',result)
        except Exception as exc:self.finish(ident,'failed',{'status':'FAILED','error':str(exc)[:1000]})

    def tick(self):
        # Slow, independent persistence survey. Never used for hot-path actions.
        if time.monotonic() - self.last_persistence_scan >= 3600 or self.last_persistence_scan == 0:
            self.last_persistence_scan = time.monotonic()
            try:
                from workers.finding.persistence import inventory
                self.store.set('finding_persistence_inventory', inventory())
            except Exception as exc:
                self.store.set('finding_persistence_inventory', {'status': 'ERROR',
                               'error_type': type(exc).__name__, 'enforcement': False})
        self.last_error=''
        try:self.process_job()
        except Exception as exc:
            self.last_error=str(exc)[:500]
            self.store.add('host_errors',{'timestamp':time.time(),'status':'FINDING_WORKER_ERROR','error':self.last_error})
        self.store.set('finding_health',{'updated_at':time.time(),'status':'RUNNING' if not self.last_error else 'DEGRADED',
          'last_error':self.last_error,'evidence_enabled':self.config['evidence_enabled'],
          'archive_budget_bytes':self.config['archive_budget_bytes'],'policy':self.meta})


def run():
    from satsuma.runtime_user import require_service_user; require_service_user()
    os.umask(0o077);config,meta,_=load_with_policy();store=HostStore(archive_budget=config['archive_budget_bytes'])
    lock=os.open(store.root/'finding-worker.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600);fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    running=True;worker=FindingWorker(store,config,meta)
    def stop(*_):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
    try:
        while running:
            if config['finding_enabled']:worker.tick()
            else:store.set('finding_health',{'updated_at':time.time(),'status':'DISABLED','policy':meta})
            time.sleep(.25)
    finally:store.close();os.close(lock)
