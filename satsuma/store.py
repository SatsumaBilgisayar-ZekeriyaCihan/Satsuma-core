"""Private SQLite persistence; all security writes precede external actions.

Özel SQLite kaydı; mevcut kanıtları koruyan ek indeksler yazıcı tarafından kurulur.
"""
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from .protected_storage import open_directory, check

SCHEMA_VERSION = 2
_STATE_DEFAULTS = {
    'persistent_blocks': {},
    'action_state': {},
    'correlation_state': {},
}

class Store:
    def __init__(self, directory='/var/lib/satsuma-core', *, test=False):
        self.directory=Path(directory)
        if test:
            self.directory.mkdir(parents=True, exist_ok=True)
        else:
            if self.directory != Path('/var/lib/satsuma-core'):
                raise PermissionError('Production storage path is fixed')
            fd=open_directory(self.directory); os.close(fd)
            for name in ('core.db','core.db-wal','core.db-shm'):
                path=self.directory/name
                if path.exists() or path.is_symlink(): check(path.lstat())
        self.path=self.directory/'core.db'
        old=os.umask(0o077)
        try:
            self.db=sqlite3.connect(self.path, timeout=60.0)
            self.db.execute('PRAGMA busy_timeout=60000')
            self.db.execute('PRAGMA auto_vacuum=INCREMENTAL')
            self.db.execute('PRAGMA journal_mode=WAL')
            self.db.execute('PRAGMA synchronous=FULL')
            self.db.execute('PRAGMA secure_delete=OFF')
            # max_page_count KALDIRILDI - sinirsiz buyume
            self.db.executescript('''
              CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY, kind TEXT NOT NULL, created REAL NOT NULL, body TEXT NOT NULL);
              CREATE INDEX IF NOT EXISTS records_kind_id ON records(kind,id);
              CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,body TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS commands(id INTEGER PRIMARY KEY,created REAL,kind TEXT,body TEXT,status TEXT DEFAULT 'pending');
              CREATE TABLE IF NOT EXISTS process_approvals(id TEXT PRIMARY KEY, created REAL NOT NULL, expires REAL NOT NULL, state TEXT NOT NULL, payload TEXT NOT NULL);
            ''')
            self.db.commit()
            self._migrate_schema()
            from .finding_index import install
            install(self.db,'core')
            from .process_followup import install as install_followup
            install_followup(self.db)
            self.db.commit()
        except Exception:
            try: self.db.close()
            except Exception: pass
            raise
        finally: os.umask(old)
        self.writes=0
        self._atomic_depth=0

    def _commit(self):
        if not self._atomic_depth:
            self.db.commit()

    @contextmanager
    def atomic(self):
        """One durable commit for an ingested record and its cursor, or neither."""
        depth=self._atomic_depth
        name='satsuma_atomic_'+str(depth)
        writes=self.writes
        self.db.execute('SAVEPOINT '+name)
        self._atomic_depth+=1
        try:
            yield
            self.db.execute('RELEASE SAVEPOINT '+name)
        except BaseException:
            self.db.execute('ROLLBACK TO SAVEPOINT '+name)
            self.db.execute('RELEASE SAVEPOINT '+name)
            self.writes=writes
            raise
        finally:
            self._atomic_depth=depth

    def _migrate_schema(self):
        """Idempotent, transactional schema upgrade preserving existing data."""
        current = int(self.db.execute('PRAGMA user_version').fetchone()[0])
        if current > SCHEMA_VERSION:
            raise RuntimeError(
                f'database schema {current} is newer than supported {SCHEMA_VERSION}'
            )
        if current == SCHEMA_VERSION:
            return
        try:
            self.db.execute('BEGIN IMMEDIATE')
            self.db.execute(
                'CREATE TABLE IF NOT EXISTS schema_migrations('
                'version INTEGER PRIMARY KEY, applied_at REAL NOT NULL)'
            )
            now = time.time()
            if current < 1:
                # Baseline tables already exist; this marker makes future
                # upgrades deterministic for databases created before versioning.
                self.db.execute(
                    'INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(1,?)',
                    (now,),
                )
            if current < 2:
                for key, default in _STATE_DEFAULTS.items():
                    row = self.db.execute(
                        'SELECT 1 FROM state WHERE key=?', (key,)
                    ).fetchone()
                    if row is None:
                        self.db.execute(
                            'INSERT INTO state(key,body) VALUES(?,?)',
                            (key, json.dumps(default, ensure_ascii=True)),
                        )
                self.db.execute(
                    'INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(2,?)',
                    (now,),
                )
            self.db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

    def add(self, kind, body):
        encoded=json.dumps(body,ensure_ascii=True,allow_nan=False)
        if len(encoded)>4*1024*1024: raise ValueError('record exceeds 4 MiB')
        c=self.db.execute('INSERT INTO records(kind,created,body) VALUES(?,?,?)',(kind,time.time(),encoded))
        metadata=body.get('metadata') if kind=='events' and isinstance(body,dict) else None
        finding=body if kind=='findings' else metadata.get('finding') if isinstance(metadata,dict) else None
        if isinstance(finding,dict):
            from .process_followup import register
            register(self,finding,commit=False)
        self._commit(); self.writes+=1
        # Her 1000 kayitta WAL checkpoint (dosya butunlugu icin)
        if self.writes%1000==0 and not self._atomic_depth:
            self.db.execute('PRAGMA wal_checkpoint(PASSIVE)')
        return c.lastrowid

    def maintain(self):
        # SADECE WAL checkpoint. Silme, vacuum, retention YOK.
        self.db.commit()
        self.db.execute('PRAGMA wal_checkpoint(PASSIVE)')

    def set(self,key,body):
        self.db.execute('INSERT OR REPLACE INTO state VALUES(?,?)',(key,json.dumps(body,ensure_ascii=True)))
        self._commit()

    def get(self,key,default=None):
        row=self.db.execute('SELECT body FROM state WHERE key=?',(key,)).fetchone()
        return json.loads(row[0]) if row else default

    def recent(self,kind,limit=100):
        return [dict(json.loads(b),_id=i) for i,b in self.db.execute('SELECT id,body FROM records WHERE kind=? ORDER BY id DESC LIMIT ?',(kind,limit))]

    def close(self):
        self.db.close()
