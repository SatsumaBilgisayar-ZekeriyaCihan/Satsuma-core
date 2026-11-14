import unittest

from satsuma.response import ResponseWorker


class DummyStore:
    def __init__(self):
        self.records = []
        self.state = {}
    def get(self,key,default=None):return self.state.get(key,default)
    def set(self,key,value):self.state[key]=value
    def add(self, kind, body):
        self.records.append((kind, body))
        return len(self.records)


class ResponseTests(unittest.TestCase):
    def config(self, enabled=True):
        return {
            'response_enabled': enabled,
            'nft_family': 'inet',
            'nft_table': 'satsuma_core',
            'nft_set': 'blocked_ips',
            'nft_set_v6': 'blocked_ips_v6',
        }

    def test_disabled_is_hard_brake(self):
        calls = []
        worker = ResponseWorker(DummyStore(), self.config(False), runner=lambda cmd: calls.append(cmd) or {'returncode': 0})
        result = worker.block_ip('8.8.8.8', 'test')
        self.assertEqual(result['status'], 'response_disabled')
        self.assertEqual(calls, [])

    def test_loopback_never_blocks(self):
        calls = []
        worker = ResponseWorker(DummyStore(), self.config(True), runner=lambda cmd: calls.append(cmd) or {'returncode': 0})
        result = worker.block_ip('127.0.0.1', 'test', manual=True)
        self.assertEqual(result['status'], 'protected_target')
        self.assertEqual(calls, [])

    def test_private_auto_is_not_held_but_gateway_is_protected(self):
        from unittest.mock import patch
        calls = []
        worker = ResponseWorker(DummyStore(), self.config(True), runner=lambda cmd: calls.append(cmd) or {'returncode': 0})
        with patch('satsuma.full_protection.protected_local_targets', lambda: {'192.168.1.1'}):
            self.assertNotEqual(worker.block_ip('192.168.1.2', 'test', manual=False)['status'], 'target_review_required')
            calls.clear()
            self.assertEqual(worker.block_ip('192.168.1.1', 'test', manual=False)['status'], 'protected_gateway_or_dns')
        self.assertEqual(calls, [])

    def test_manual_global_ipv4_uses_declared_nft_set(self):
        from network_fixture import table_json
        calls=[]
        def runner(cmd):
            calls.append(cmd)
            return {'returncode':0,'stdout':table_json() if '-j' in cmd else ''}
        worker=ResponseWorker(DummyStore(),self.config(True),runner=runner)
        result=worker.block_ip('8.8.8.8','test',manual=True)
        self.assertEqual(result['status'],'set_membership_confirmed')
        self.assertTrue(result['drop_rule_linked'])
        self.assertFalse(result['traffic_drop_verified'])
        self.assertIn(['nft','add','element','inet','satsuma_core','blocked_ips','{','8.8.8.8','}'],calls)


    def test_subnet_target_is_rejected_without_nft_commands(self):
        calls = []
        worker = ResponseWorker(
            DummyStore(), self.config(True),
            runner=lambda cmd: calls.append(cmd) or {'returncode': 0}
        )
        result = worker.block_ip('8.8.8.0/24', 'not a single host')
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(calls, [])

    def test_kernel_membership_is_not_called_durable_if_persistence_fails(self):
        from network_fixture import table_json
        class StoreWithoutPersistence(DummyStore):
            def set(self, key, value):
                raise OSError('simulated storage outage')
        calls = []
        def runner(cmd):
            calls.append(cmd)
            return {'returncode': 0,
                    'stdout': table_json() if '-j' in cmd else ''}
        worker = ResponseWorker(StoreWithoutPersistence(), self.config(True), runner=runner)
        result = worker.block_ip('8.8.8.8', 'persist failed',manual=True)
        self.assertEqual(result['status'], 'set_membership_confirmed_state_unpersisted')
        self.assertFalse(result['persisted'])
        self.assertTrue(result['drop_rule_linked'])
        self.assertFalse(result['traffic_drop_verified'])
        self.assertTrue(any(cmd[1:3] == ['add', 'element'] for cmd in calls))


if __name__ == '__main__':
    unittest.main()
