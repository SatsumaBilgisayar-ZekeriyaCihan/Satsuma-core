"""Indexed RAM history must preserve old evidence and read-only boundaries.

İndeksli RAM geçmişi eski kanıtı ve salt okunur sınırı korumalıdır.
"""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from satsuma import dashboard_api as api
from satsuma.store import Store
from satsuma.host_store import HostStore
from satsuma.finding_index import definition,restrict


class MemoryIndexTests(unittest.TestCase):
    def test_old_memory_finding_survives_large_unrelated_history(self):
        with tempfile.TemporaryDirectory() as directory:
            core=Store(Path(directory)/'core',test=True)
            host=HostStore(Path(directory)/'host',test=True)
            try:
                core.add('findings',{'rule_id':'SATSUMA-RAM-106','title':'Old RAM finding','timestamp':1})
                core.add('events',{'event':{'category':'finding'},'metadata':{'finding':{
                    'matched_rules':['SATSUMA-FILELESS-001'],'title':'Wrapped finding','timestamp':1}}})
                core.add('normalized',{'rule_id':'SATSUMA-RAM-106','title':'Not a finding'})
                payload=json.dumps({'rule_id':'SATSUMA-EXEC-001','title':'other','timestamp':2})
                core.db.executemany('INSERT INTO records(kind,created,body) VALUES(?,?,?)',
                                    (('findings',2,payload) for _ in range(10000)))
                core.db.execute("INSERT INTO records(kind,created,body) VALUES('findings',3,'bad json')")
                host.db.execute('INSERT INTO findings VALUES(?,?,?)',('host-memory',3,
                    json.dumps({'rule_id':'SATSUMA-MEM-001','title':'Host RAM finding','timestamp':3})))
                core.db.commit();host.db.commit()
                with patch.object(api,'DB_PATH',str(core.path)),patch.object(api,'HOST_DB_PATH',str(host.root/'host.db')):
                    result=api.m_memory_defense()
                    self.assertEqual(result['data_state'],'OK')
                    self.assertEqual({r['rule_id'] for r in result['items']},
                                     {'SATSUMA-RAM-106','SATSUMA-MEM-001','SATSUMA-FILELESS-001'})
                    self.assertEqual(result['total_count'],3)
                    with api._connect() as reader:
                        self.assertEqual(reader.execute('PRAGMA query_only').fetchone()[0],1)
                        with self.assertRaises(sqlite3.OperationalError):
                            reader.execute("INSERT INTO state VALUES('forbidden','{}')")
                for db,origin in ((core.db,'core'),(host.db,'host')):
                    name,table,*_=definition(origin)
                    sql=' UNION ALL '.join('SELECT body FROM '+table+' INDEXED BY '+name+' WHERE '+p
                                           for p in restrict(db,origin))
                    plan=db.execute('EXPLAIN QUERY PLAN '+sql).fetchall()
                    self.assertEqual(sum('SEARCH' in row[-1] for row in plan),3)
            finally:
                core.close();host.close()

    def test_missing_index_reports_pending_instead_of_scanning_or_writing(self):
        db=sqlite3.connect(':memory:')
        try:
            with self.assertRaisesRegex(ValueError,'INDEX_PENDING'):
                restrict(db,'core')
            self.assertEqual(db.execute('SELECT count(*) FROM sqlite_master').fetchone()[0],0)
        finally:
            db.close()
