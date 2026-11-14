"""Shared Module 2 storage and explicitly retained evidence.

Özel SQLite kaydı; mevcut kanıtları koruyan ek indeksler yazıcı tarafından kurulur.
"""
import hashlib,json,os,sqlite3,time,uuid
from pathlib import Path
from .protected_storage import open_directory,check

SCHEMA_VERSION = 2
_STATE_DEFAULTS = {
    'persistent_blocks': {},
    'action_state': {},
    'correlation_state': {},
}

class HostStore:
    def __init__(self,root='/var/lib/satsuma-core/host',test=False,archive_budget=1024**3):
        self.root=Path(root);self.archive_budget=archive_budget
        if test:self.root.mkdir(parents=True,exist_ok=True)
        else:
            if str(self.root)!='/var/lib/satsuma-core/host':raise ValueError('Fixed production host path')
            os.close(open_directory(self.root))
            for name in ('host.db','host.db-wal','host.db-shm'):
                path=self.root/name
                if path.exists() or path.is_symlink():check(path.lstat())
        self.db=sqlite3.connect(self.root/'host.db',timeout=60)
        self.db.execute('PRAGMA busy_timeout=60000')
        self.db.execute('PRAGMA wal_autocheckpoint=200')
        self.db.execute('PRAGMA journal_mode=WAL');self.db.execute('PRAGMA secure_delete=OFF');self.db.execute('PRAGMA synchronous=FULL');self.db.execute('PRAGMA max_page_count=2000000')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY,kind TEXT,created REAL,body TEXT,digest TEXT UNIQUE);
        CREATE INDEX IF NOT EXISTS host_kind ON records(kind,id);
        CREATE TABLE IF NOT EXISTS audit_paths(path TEXT,event_time REAL,record_id INTEGER,PRIMARY KEY(path,record_id));
        CREATE INDEX IF NOT EXISTS audit_path_time ON audit_paths(path,event_time);
        CREATE TABLE IF NOT EXISTS findings(finding_id TEXT PRIMARY KEY,last_seen REAL,body TEXT);
        CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,body TEXT);
        CREATE TABLE IF NOT EXISTS processed(worker TEXT,record_id INTEGER,PRIMARY KEY(worker,record_id));
        CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY,kind TEXT,body TEXT,status TEXT DEFAULT 'pending',result TEXT);''')
        self.db.commit()
        self._migrate_schema()
        from .finding_index import install
        install(self.db,'host')
        self.evidence=self.root/'evidence';self.evidence.mkdir(mode=0o700,exist_ok=True)
        if not test:check(self.evidence.lstat(),True)
        self.count=0

    def _migrate_schema(self):
        """Idempotent, transactional host DB upgrade preserving evidence."""
        current=int(self.db.execute('PRAGMA user_version').fetchone()[0])
        if current>SCHEMA_VERSION:
            raise RuntimeError(f'host database schema {current} is newer than supported {SCHEMA_VERSION}')
        if current==SCHEMA_VERSION:
            return
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute('CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)')
            now=time.time()
            if current<1:
                self.db.execute('INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,?)',(now,))
            if current<2:
                for key,default in _STATE_DEFAULTS.items():
                    row=self.db.execute('SELECT 1 FROM state WHERE key=?',(key,)).fetchone()
                    if row is None:
                        self.db.execute('INSERT INTO state(key,body) VALUES(?,?)',(key,json.dumps(default,ensure_ascii=True)))
                self.db.execute('INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(2,?)',(now,))
            self.db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def add(self,kind,body,commit=True):
        payload=json.dumps(body,ensure_ascii=True,allow_nan=False)
        if len(payload)>8*1024*1024:raise ValueError('Host record too large')
        digest=hashlib.sha256((kind+payload).encode()).hexdigest()
        self.db.execute('INSERT OR IGNORE INTO records(kind,created,body,digest) VALUES(?,?,?,?)',(kind,time.time(),payload,digest))
        row=self.db.execute('SELECT id FROM records WHERE digest=?',(digest,)).fetchone();ident=row[0]
        if kind=='audit':
            for item in body.get('paths',[]):
                if item.get('path'):self.db.execute('INSERT OR IGNORE INTO audit_paths VALUES(?,?,?)',(item['path'],body['timestamp'],ident))
        if commit:self.db.commit()
        self.count+=1
        if commit and self.count%100==0:self.maintain()
        return ident

    def maintain(self):
        # RETENTION DISABLED — 2026-09-20 veri kaybı sonrası
        # Sadece yetim audit_path kayıtlarını temizle
        self.db.execute('DELETE FROM audit_paths WHERE record_id NOT IN (SELECT id FROM records)');self.db.commit()

    def set(self,key,value):
        self.db.execute('INSERT OR REPLACE INTO state VALUES(?,?)',(key,json.dumps(value)));self.db.commit()

    def get(self,key,default=None):
        row=self.db.execute('SELECT body FROM state WHERE key=?',(key,)).fetchone();return json.loads(row[0]) if row else default

    def archive(self,body):
        payload=json.dumps({'schema':'satsuma.evidence.v1','saved_at':time.time(),'record':body},sort_keys=True,ensure_ascii=True,allow_nan=False).encode()
        used=sum(path.stat().st_size for path in self.evidence.iterdir() if path.is_file())
        if used+len(payload)>self.archive_budget:raise RuntimeError('Evidence archive budget full; existing evidence retained')
        digest=hashlib.sha256(payload).hexdigest();name=str(uuid.uuid4())+'-'+digest+'.json'
        fd=os.open(self.evidence/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(payload);stream.flush();os.fsync(stream.fileno())
        directory=os.open(self.evidence,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(directory)
        finally:os.close(directory)
        result={'timestamp':time.time(),'status':'ARCHIVED','path':str(self.evidence/name),'sha256':digest,'bytes':len(payload)}
        self.add('evidence',result);return result

    def close(self):self.db.close()
