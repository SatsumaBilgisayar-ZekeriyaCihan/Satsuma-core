"""Read-only, paginated database views with explicit secret exclusions.

Gizli verileri açıkça dışarıda bırakan salt okunur, sayfalı veritabanı görünümü.
No SQL supplied by the GUI is executed. View access never grants control access.
Arayüzden SQL alınmaz; görüntüleme yetkisi kontrol yetkisi vermez.
"""
import json
import re

PRIVATE_TABLE=re.compile(r'(auth|credential|password|session|secret|token|private_key)',re.I)
PRIVATE_KEY=re.compile(r'(password|passwd|api[_-]?key|secret|token|authorization|cookie|private[_-]?key|session)',re.I)


def redact(value):
    if isinstance(value,dict):
        return {k:'[GİZLENDİ]' if PRIVATE_KEY.search(str(k)) else redact(v) for k,v in value.items()}
    if isinstance(value,list):return [redact(v) for v in value]
    if isinstance(value,bytes):return {'binary_bytes':len(value),'content':'[İKİLİ İÇERİK]'}
    if isinstance(value,str):
        try:return redact(json.loads(value))
        except (ValueError,TypeError):
            return re.sub(r'(?i)(bearer\s+|(?:password|api[_-]?key|secret|token)\s*[:=]\s*)[^\s,;]+',r'\1[GİZLENDİ]',value)
    return value


def quote(name):return '"'+name.replace('"','""')+'"'


def tables(db):
    return [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]


def catalog(db):
    result=[]
    for table in tables(db):
        count=db.execute('SELECT count(*) FROM '+quote(table)).fetchone()[0]
        private=bool(PRIVATE_TABLE.search(table))
        groups=[]
        if table=='records':
            groups=[{'kind':r[0],'count':r[1]} for r in db.execute('SELECT kind,count(*) FROM records GROUP BY kind ORDER BY kind')]
        result.append({'table':table,'count':count,'groups':groups,
                       'access':'metadata_only' if private else 'redacted_rows',
                       'reason':'Kimlik/oturum sırlarının içeriği bu sayfada açılmaz' if private else 'Gizli alanlar maskelenir'})
    return result


def page(db,table,*,kind=None,offset=0,limit=50):
    if table not in tables(db):raise ValueError('Unknown database table')
    if PRIVATE_TABLE.search(table):raise PermissionError('Secret table is metadata-only')
    offset=max(0,int(offset));limit=max(1,min(100,int(limit)))
    columns=[r[1] for r in db.execute('PRAGMA table_info('+quote(table)+')')]
    params=[];where=''
    if table=='records' and kind is not None:
        where=' WHERE kind=?';params=[str(kind)]
    total=db.execute('SELECT count(*) FROM '+quote(table)+where,params).fetchone()[0]
    # PK order works for normal and WITHOUT ROWID tables. Always deterministic.
    info=list(db.execute('PRAGMA table_info('+quote(table)+')'))
    order=[r[1] for r in sorted(info,key=lambda r:r[5]) if r[5]] or columns
    sql='SELECT '+','.join(quote(c) for c in columns)+' FROM '+quote(table)+where
    sql+=' ORDER BY '+','.join(quote(c) for c in order)+' LIMIT ? OFFSET ?'
    rows=[]
    for values in db.execute(sql,[*params,limit,offset]):
        row=dict(zip(columns,values))
        if table=='state' and PRIVATE_KEY.search(str(row.get('key',''))):
            row={k:'[GİZLENDİ]' if k!='key' else v for k,v in row.items()}
        rows.append(redact(row))
    return {'items':rows,'count':total,'offset':offset,'limit':limit,'data_state':'OK',
            'has_more':offset+len(rows)<total,'columns':columns,
            'redacted':True,'pagination_scope':'live data; refresh restarts browsing'}


def stopped(db,*,offset=0,limit=50):
    """Only explicit process.terminate + signal + verified exit is a stopped process."""
    offset=max(0,int(offset));limit=max(1,min(100,int(limit)))
    # Record rows from the final executor and parent can repeat the same finding.
    # Keep one result per known finding/PID; unknown identities stay separate.
    query='''WITH eligible AS (
      SELECT id,created,body,
      ROW_NUMBER() OVER (PARTITION BY
        CASE WHEN json_extract(body,'$.finding_id') IS NOT NULL
          THEN CAST(json_extract(body,'$.finding_id') AS TEXT)||':'||CAST(json_extract(body,'$.pid') AS TEXT)
          ELSE 'row:'||CAST(id AS TEXT) END ORDER BY id DESC) AS number
      FROM records WHERE kind='actions' AND json_valid(body)
        AND json_extract(body,'$.action')='process.terminate'
        AND json_extract(body,'$.signal_sent')=1
        AND json_extract(body,'$.exit_verified')=1
        AND json_extract(body,'$.status')='terminated')'''
    total=db.execute(query+' SELECT count(*) FROM eligible WHERE number=1').fetchone()[0]
    rows=[]
    for ident,created,body in db.execute(query+' SELECT id,created,body FROM eligible WHERE number=1 ORDER BY id DESC LIMIT ? OFFSET ?',(limit,offset)):
        row=redact(json.loads(body));row.update(record_id=ident)
        row.setdefault('timestamp',created);rows.append(row)
    return {'items':rows,'count':total,'offset':offset,'limit':limit,'data_state':'OK','has_more':offset+len(rows)<total,
            'scope':'Only verified process exits; authorization or signal alone is not completion'}
