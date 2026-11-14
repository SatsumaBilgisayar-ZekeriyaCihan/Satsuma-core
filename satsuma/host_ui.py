import json,sqlite3,time
from pathlib import Path
from .protected_storage import check
from .sqlite_closing import ClosingConnection

PATH=Path('/var/lib/satsuma-core/host/host.db')


def connect():
    check(PATH.parent.lstat(),True);check(PATH.lstat())
    return sqlite3.connect('file:'+str(PATH)+'?mode=rw',uri=True,timeout=2,factory=ClosingConnection)


def health():
    try:
        with connect() as db:
            output={}
            for key,name in (('audit_health','audit'),('finding_health','finding')):
                row=db.execute('SELECT body FROM state WHERE key=?',(key,)).fetchone()
                value=json.loads(row[0]) if row else {'status':'UNAVAILABLE'}
                if time.time()-value.get('updated_at',0)>5:value['status']='STALE'
                output[name]=value
            statuses=[output[name].get('status') for name in ('audit','finding')]
            output['status']='RUNNING' if all(status in ('RUNNING','IDLE','DISABLED') for status in statuses) else 'DEGRADED'
            return output
    except (OSError,sqlite3.Error):return {'status':'UNAVAILABLE','audit':{},'finding':{}}


def recent(kind):
    try:
        with connect() as db:
            if kind=='findings':return [dict(json.loads(body),_id=ident,_host=True) for ident,body in db.execute('SELECT finding_id,body FROM findings ORDER BY last_seen DESC LIMIT 500')]
            return [dict(json.loads(body),_id=ident,_host=True) for ident,body in db.execute('SELECT id,body FROM records WHERE kind=? ORDER BY id DESC LIMIT 500',(kind,))]
    except (OSError,sqlite3.Error):raise


def submit(kind,body):
    if kind not in ('review','archive_finding','archive'):
        raise ValueError('Unsupported host operation')
    worker='finding'
    if health().get(worker,{}).get('status') not in ('RUNNING','IDLE'):
        raise ValueError(worker+' worker aktif degil; talep gonderilmedi')
    with connect() as db:
        if db.execute("SELECT count(*) FROM jobs WHERE status IN ('pending','running')").fetchone()[0]>=10:raise ValueError('Is kuyrugu dolu (10)')
        ident=db.execute('INSERT INTO jobs(kind,body) VALUES(?,?)',(kind,json.dumps(body))).lastrowid
    return ident


def group_alerts(rows):
    output=[];groups={}
    for row in rows:
        if row.get('risk_level')!='UNASSESSED':output.append(row);continue
        key=(row.get('signature_id'),row.get('signature'),row.get('in_iface'))
        if key not in groups:
            row=dict(row,display_count=1,first_seen=row.get('timestamp'),last_seen=row.get('timestamp'),grouped_raw_ids=[row.get('raw_id')]);groups[key]=row;output.append(row)
        else:
            item=groups[key];item['display_count']+=1;item['first_seen']=row.get('timestamp');item['grouped_raw_ids'].append(row.get('raw_id'))
    return output
