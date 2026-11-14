"""Journal ingestion with durable per-record cursors and explicit failures."""
import json,subprocess,time,selectors,os,tempfile
from contextlib import nullcontext
class WorkerJournal:
    name='journal'
    def __init__(self,store,config=None):
        self.store=store;self.config=config or {};self.cursor_key='worker.journal.cursor.v3';self.health_key='worker.journal.health'
    def tick(self,pipeline=None):
        count=0;error=None;p=None;errors=None;budget_reached=False
        started=time.monotonic()
        try:
            errors=tempfile.TemporaryFile()
            if pipeline is None:raise RuntimeError('Pipeline required; journal cursor retained')
            args=['/usr/bin/journalctl','--output=json','--no-pager','--no-tail']
            cursor=self.store.get(self.cursor_key)
            if cursor:args+=['--after-cursor='+cursor]
            p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=errors,env={'PATH':'/usr/sbin:/usr/bin','LC_ALL':'C'})
            sel=selectors.DefaultSelector();sel.register(p.stdout,selectors.EVENT_READ)
            buf=b'';deadline=time.monotonic()+0.25
            try:
                while count<128:
                    remaining=deadline-time.monotonic()
                    if remaining<=0:
                        budget_reached=True;break
                    if not sel.select(min(0.05,remaining)):continue
                    chunk=os.read(p.stdout.fileno(),65536)
                    if not chunk:
                        rc=p.wait(timeout=5)
                        if rc:
                            errors.seek(0)
                            raise RuntimeError(errors.read(4096).decode(errors='replace'))
                        if buf.strip():raise ValueError('Incomplete journal record; cursor retained')
                        break
                    buf+=chunk
                    if any(len(line)>1048576 for line in buf.split(b'\n')):
                        raise ValueError('Oversized journal record; cursor retained')
                    while b'\n' in buf and count<128:
                        if time.monotonic()>=deadline:
                            budget_reached=True;break
                        line,buf=buf.split(b'\n',1)
                        if not line.strip():continue
                        obj=json.loads(line);pri=int(obj.get('PRIORITY',6))
                        event={'source':'journal','kind':'journal_event','action':'journal_event','category':'identity',
                               'timestamp':int(obj.get('__REALTIME_TIMESTAMP',0))/1000000,
                               'severity':'critical' if pri<=2 else 'high' if pri==3 else 'medium' if pri==4 else 'info',
                               'unit':obj.get('_SYSTEMD_UNIT',obj.get('UNIT','unknown')),'message':obj.get('MESSAGE',''),
                               'pid':obj.get('_PID'),'uid':obj.get('_UID'),'comm':obj.get('_COMM'),'journal_cursor':obj['__CURSOR']}
                        # Keep FULL SQLite durability but combine raw/normalized
                        # rows and progress into one transaction. Failed delivery
                        # leaves the cursor behind for replay, never silent loss.
                        atomic=getattr(self.store,'atomic',nullcontext)
                        with atomic():
                            pipeline.ingest_host(event)
                            self.store.set(self.cursor_key,obj['__CURSOR'])
                        count+=1
                budget_reached=budget_reached or count>=128
            finally:sel.close()
        except Exception as exc:error=str(exc)
        finally:
            if p:
                if p.poll() is None:p.terminate()
                try:p.wait(timeout=3)
                except subprocess.TimeoutExpired:p.kill();p.wait()
                p.stdout.close()
            if errors is not None:errors.close()
        health={'ok':error is None,'status':'DEGRADED' if error else 'RUNNING','events':count,'error':error,'updated_at':time.time(),
                'budget_reached':budget_reached,'elapsed_seconds':time.monotonic()-started,
                'max_events_per_tick':128,'read_budget_seconds':0.25}
        self.store.set(self.health_key,health);return health
