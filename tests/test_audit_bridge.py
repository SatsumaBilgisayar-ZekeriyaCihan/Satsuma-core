import json
import sqlite3
from support import EvidenceDirectory
import unittest
from pathlib import Path

from satsuma.store import Store
from satsuma.worker_audit_bridge import WorkerAuditBridge
from satsuma.teams.identity_team.team_lead import IdentityTeamLead


class DummyPipeline:
    def __init__(self):
        self.events = []

    def ingest_audit(self, event):
        self.events.append(event)


class AuditBridgeTests(unittest.TestCase):
    def _host_db(self, path):
        conn = sqlite3.connect(path)
        conn.execute('CREATE TABLE records(id INTEGER PRIMARY KEY,kind TEXT,created REAL,body TEXT,digest TEXT UNIQUE)')
        conn.commit()
        return conn

    def test_identity_team_uses_bridge_not_legacy_log_reader(self):
        names = [w.__name__ for w in IdentityTeamLead.workers]
        self.assertIn('WorkerAuditBridge', names)
        self.assertNotIn('WorkerAudit', names)

    def test_bridge_baselines_then_emits_new_audit_record(self):
        with EvidenceDirectory() as td:
            root = Path(td)
            host_db = root / 'host.db'
            conn = self._host_db(host_db)
            conn.execute(
                'INSERT INTO records(kind,created,body,digest) VALUES(?,?,?,?)',
                ('audit', 1.0, json.dumps({'timestamp': 1, 'serial': '1', 'paths': []}), 'd1'),
            )
            conn.commit()

            store = Store(root / 'core', test=True)
            bridge = WorkerAuditBridge(store, {'audit_host_db_path': str(host_db)})
            pipe = DummyPipeline()

            first = bridge.tick(pipe)
            self.assertEqual(first['status'], 'RUNNING')
            self.assertEqual(pipe.events, [])

            record = {
                'timestamp': 2.0,
                'serial': '2',
                'pid': '123', 'ppid': '1', 'uid': '0', 'auid': '1000',
                'exe': '/usr/bin/python3', 'comm': 'python3',
                'syscall': '257', 'a2': '241', 'success': 'yes',
                'execve': {'argc': '2', 'a0': 'python3', 'a1': 'script.py'},
                'paths': [{'path': '/etc/passwd', 'inode': '42', 'nametype': 'NORMAL'}],
                'types': ['SYSCALL', 'EXECVE', 'PATH'],
            }
            conn.execute(
                'INSERT INTO records(kind,created,body,digest) VALUES(?,?,?,?)',
                ('audit', 2.0, json.dumps(record), 'd2'),
            )
            conn.commit()

            result = bridge.tick(pipe)
            self.assertTrue(result['ok'])
            self.assertEqual(result['records'], 1)
            file_events = [e for e in pipe.events if e.get('action') == 'file_access']
            self.assertEqual(len(file_events), 1)
            self.assertEqual(file_events[0]['file_path'], '/etc/passwd')
            self.assertEqual(file_events[0]['operation'], 'write')
            self.assertTrue(any(e.get('action') == 'execve' for e in pipe.events))
            store.close()
            conn.close()


if __name__ == '__main__':
    unittest.main()
