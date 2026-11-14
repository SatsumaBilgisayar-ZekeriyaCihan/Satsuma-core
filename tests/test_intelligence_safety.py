from support import EvidenceDirectory
import unittest
from unittest.mock import patch

from satsuma.config import validate
from satsuma.otx import run_once
from satsuma.sentinel import Monitor
from satsuma.store import Store


class FakeResponse:
    def __init__(self):
        self.blocks = []
        self.config = {
            'nft_family': 'inet',
            'nft_table': 'filter',
            'nft_set': 'blocked_ips',
            'nft_set_v6': 'blocked_ips_v6',
        }

    def block(self, ip, reason, manual=False):
        self.blocks.append((ip, reason, manual))
        return {'status': 'blocked'}

    def run(self, cmd):
        return 0, ''


class IntelligenceSafetyTests(unittest.TestCase):
    def test_clean_default_has_response_enabled(self):
        # 2.2.9 full protection: responses are on out of the box.
        self.assertTrue(validate({})['response_enabled'])

    def test_ptr_absence_never_auto_blocks(self):
        with EvidenceDirectory() as td:
            store = Store(td, test=True)
            try:
                response = FakeResponse()
                monitor = Monitor(store, response)
                for i in range(4):
                    monitor.step({'8.8.8.8': 'absent'}, now=1000 + i * 15)
                self.assertEqual(response.blocks, [])
                rows = store.db.execute("SELECT body FROM records WHERE kind='sentinel'").fetchall()
                self.assertTrue(rows)
                self.assertIn('review', rows[-1][0])
            finally:
                store.close()

    def test_sentinel_says_blocking_belongs_to_the_guard_rule(self):
        # The sentinel stays review-only; it must not claim that PTR absence
        # never blocks, because the guard's fixed rule does (peer_watch).
        with EvidenceDirectory() as td:
            store = Store(td, test=True)
            try:
                Monitor(store, FakeResponse()).step({'8.8.8.8': 'absent'}, now=1000)
                health = store.get('sentinel_health', {})
                self.assertIn('guard_blocks_no_ptr_peer', health['ptr_policy'])
                self.assertNotIn('never_auto_blocks', health['ptr_policy'])
            finally:
                store.close()

    def test_otx_threshold_is_review_not_block(self):
        with EvidenceDirectory() as td:
            store = Store(td, test=True)
            try:
                response = FakeResponse()
                cfg = {
                    'enabled': True,
                    'api_key': 'x' * 32,
                    'pulse_threshold': 11,
                    'cache_ttl_seconds': 3600,
                    'max_queries_per_cycle': 12,
                }
                data = {'pulse_info': {'count': 20, 'pulses': []}, 'reputation': 5}
                tls = {'verified': True, 'host': 'otx.alienvault.com', 'version': 'TLSv1.3', 'cipher': 'x'}
                with patch('satsuma.otx.load_config', return_value=cfg), \
                     patch('satsuma.otx.load_with_policy', return_value=({"otx_enabled":True}, {}, {})), \
                     patch('satsuma.dnsmasq_control.refresh'), \
                     patch('satsuma.otx.request_ipv4', return_value=(data, tls)):
                    results = run_once(store=store, response=response, candidates=['8.8.8.8'])
                self.assertEqual(response.blocks, [])
                self.assertEqual(results[0]['decision'], 'review')
                self.assertEqual(results[0]['classification'], 'suspicious')
            finally:
                store.close()


if __name__ == '__main__':
    unittest.main()
