import unittest

from satsuma.worker_audit import WorkerAudit


class DummyStore:
    def get(self, key, default=None): return default
    def set(self, key, value): pass
    def add(self, kind, body): return 1


class AuditWorkerTests(unittest.TestCase):
    def test_openat_write_produces_rule_contract(self):
        worker = WorkerAudit(DummyStore())
        lines = [
            'type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=0 a2=241 pid=123 ppid=10 uid=1000 auid=1000 exe="/usr/bin/bash" comm="bash"',
            'type=PATH msg=audit(1700000000.123:42): item=0 name="/etc/passwd" inode=100 dev=08:01 mode=0100644 nametype=NORMAL',
        ]
        records = [worker._parse_line(line) for line in lines]
        events = worker._raw_to_events({'records': records})
        file_events = [e for e in events if e.get('action') == 'file_access']
        self.assertEqual(len(file_events), 1)
        event = file_events[0]
        self.assertEqual(event['file_path'], '/etc/passwd')
        self.assertEqual(event['operation'], 'write')
        self.assertEqual(event['metadata']['extensions']['host.operation'], 'write')


if __name__ == '__main__':
    unittest.main()
