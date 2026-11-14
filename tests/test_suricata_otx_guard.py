import importlib.util
import json
import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch, Mock

spec = importlib.util.spec_from_file_location('guard', pathlib.Path(__file__).resolve().parents[1] / 'integrations' / 'satsuma_guard.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

class Tests(unittest.TestCase):
    def test_nft_requires_readback_for_both_families(self):
        for ip, name in [('45.33.32.10', 'blocked_v4'), ('2606:4700:4700::1111', 'blocked_v6')]:
            with self.subTest(ip=ip):
                nft = guard.Nft()
                def snapshot(elements):
                    return json.dumps({'nftables': [{'set': {
                        'family': 'inet', 'table': nft.TABLE, 'name': name, 'elem': elements}}]})
                with patch.object(nft, 'run', side_effect=[snapshot([]), '', snapshot([])]):
                    with self.assertRaisesRegex(RuntimeError, 'failed kernel readback'):
                        nft.block(ip)
                with patch.object(nft, 'run', side_effect=[snapshot([]), '', snapshot([ip])]):
                    nft.block(ip)

    def test_nft_rejects_unverifiable_or_widened_readback(self):
        nft = guard.Nft()
        for raw in ['{}', 'not JSON', json.dumps({'nftables': [{'set': {
                'family': 'inet', 'table': nft.TABLE, 'name': 'blocked_v4',
                'elem': [{'prefix': {'addr': '45.33.32.0', 'len': 24}}]}}]})]:
            with self.subTest(raw=raw), patch.object(nft, 'run', return_value=raw):
                with self.assertRaises(RuntimeError):
                    nft.block('45.33.32.10')

    def test_unblock_requires_absence_in_kernel(self):
        nft = guard.Nft()
        with patch.object(nft, 'run', return_value=''), patch.object(nft, 'contains', return_value=True):
            with self.assertRaisesRegex(RuntimeError, 'unblock failed'):
                nft.unblock('45.33.32.10')

    def test_duplicate_block_rechecks_kernel_and_failure_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(guard, 'local_ips', return_value=set()):
            cfg = dict(guard.DEFAULT, mode='observe', state_dir=tmp, otx_enabled=False)
            svc = guard.Guard(cfg, boot_provider=lambda: {'response_unlocked': True})
            try:
                svc.cfg['mode'] = 'block'
                svc.nft = Mock()
                svc.block('45.33.32.10', 'test_rule')
                svc.block('45.33.32.10', 'test_rule')
                self.assertEqual(svc.nft.block.call_count, 2)
                self.assertEqual(svc.db.execute('SELECT count(*) FROM blocks').fetchone()[0], 1)
                svc.nft.block.side_effect = RuntimeError('kernel refused')
                svc.block('8.8.8.8', 'test_rule')
                self.assertIsNone(svc.db.execute('SELECT 1 FROM blocks WHERE ip=?', ('8.8.8.8',)).fetchone())
                events = [json.loads(line) for line in pathlib.Path(tmp, 'events.jsonl').read_text().splitlines()]
                self.assertEqual(events[-1]['event'], 'ACTION_FAILED')
                failure = svc.db.execute("SELECT body FROM events WHERE event='ACTION_FAILED'").fetchone()
                self.assertEqual(json.loads(failure[0])['ip'], '8.8.8.8')
                self.assertEqual(svc.db.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
                self.assertFalse(any(e['event'] == 'block' and e.get('ip') == '8.8.8.8' for e in events))
            finally:
                svc.db.close()
                svc.events.close()

    def test_fast_parser_inbound(self):
        line = '10/05/10-10:08:59.667372 [**] [1:12:3] test [**] [Classification: misc] [Priority: 3] {TCP} 45.33.32.10:443 -> 192.168.1.10:1234'
        e = guard.parse_alert(line, 'fast')
        self.assertEqual(e['source_ip'], '45.33.32.10')
        self.assertEqual(e['priority'], 3)
        self.assertEqual(e['dest_ip'], '192.168.1.10')

    def test_eve_parser(self):
        line = json.dumps({'event_type': 'alert', 'src_ip': '45.33.32.10', 'dest_ip': '192.168.1.10', 'alert': {'severity': 3, 'signature':'x'}})
        self.assertEqual(guard.parse_alert(line,'eve')['signature'],'x')

    def test_conntrack_parser(self):
        line = 'tcp 6 431999 ESTABLISHED src=45.33.32.10 dst=192.168.1.10 sport=123 dport=80 src=192.168.1.10 dst=45.33.32.10 sport=80 dport=123 [ASSURED]'
        self.assertEqual(len(guard.parse_conntrack(line)),1)
        self.assertEqual(guard.parse_conntrack(line.replace('ESTABLISHED','SYN_SENT')),set())

    def test_subnet_tenth_newcomer_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = dict(guard.DEFAULT)
            cfg.update({'mode':'observe','state_dir':tmp,'otx_enabled':False,'fast_block':False})
            svc = guard.Guard(cfg)
            def fake_scan(peers):
                text = '\n'.join(f'tcp 6 431999 ESTABLISHED src=45.33.32.{i} dst=192.168.1.10 sport=123 dport=80' for i in peers)
                return types.SimpleNamespace(returncode=0,stdout=text,stderr='')
            with patch.object(guard.shutil,'which',return_value='/usr/sbin/conntrack'):
                with patch.object(guard,'command',return_value=fake_scan(range(1,10))):
                    svc.check_connections()
                with patch.object(guard,'command',return_value=fake_scan(range(1,11))):
                    svc.check_connections()
            items = [json.loads(x) for x in pathlib.Path(tmp,'events.jsonl').read_text().splitlines()]
            would = [x for x in items if x['event']=='would_block']
            self.assertEqual(len(would),1)
            self.assertEqual(would[0]['ip'],'45.33.32.10')
            self.assertEqual(would[0]['active_distinct'],10)
            svc.db.close()
            svc.events.close()

    def test_trusted_and_outbound_not_targeted(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = dict(guard.DEFAULT)
            cfg.update({'mode':'observe','state_dir':tmp,'otx_enabled':False,'trusted_cidrs':['45.33.32.0/24']})
            svc = guard.Guard(cfg)
            svc.resolvers = lambda: set()  # independent of this machine's resolv.conf
            self.assertFalse(svc.eligible('45.33.32.10','192.168.1.1'))
            self.assertFalse(svc.eligible('192.168.1.1','45.33.32.10'))
            self.assertTrue(svc.eligible('8.8.8.8','192.168.1.1'))
            svc.db.close()
            svc.events.close()

if __name__=='__main__':
    unittest.main()
