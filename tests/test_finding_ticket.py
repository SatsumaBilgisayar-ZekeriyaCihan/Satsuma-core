from support import EvidenceDirectory
import unittest

from satsuma.finding_store import record_finding
from satsuma.store import Store
from satsuma.ticket_builder import TicketBuilder


class FindingTicketTests(unittest.TestCase):
    def test_finding_event_dedup(self):
        with EvidenceDirectory() as td:
            store = Store(td, test=True)
            try:
                finding = {
                    'finding_id': 'stable-1',
                    'type': 'example',
                    'severity': 'high',
                    'classification': 'suspicious',
                    'summary': 'same evidence',
                    'events': [{'id': 5}],
                }
                first = record_finding(store, finding, 'test')
                second = record_finding(store, finding, 'test')
                self.assertTrue(first['written'])
                self.assertFalse(second['written'])
                count = store.db.execute("SELECT COUNT(*) FROM records WHERE kind='events'").fetchone()[0]
                self.assertEqual(count, 1)
            finally:
                store.close()

    def test_indicator_cannot_be_s1(self):
        with EvidenceDirectory() as td:
            store = Store(td, test=True)
            try:
                builder = TicketBuilder(store)
                level = builder.compute_level({
                    'type': 'privilege_escalation_attempt',
                    'severity': 'critical',
                    'classification': 'indicator',
                })
                self.assertEqual(level, 4)
                suspicious = builder.compute_level({
                    'type': 'privilege_escalation_attempt',
                    'severity': 'critical',
                    'classification': 'suspicious',
                })
                self.assertEqual(suspicious, 2)
            finally:
                store.close()


if __name__ == '__main__':
    unittest.main()
