"""Memory integration regression tests / Bellek bütünleşme testleri."""
import importlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from satsuma.ram.coordinator import MemoryMonitor, finding_event
from satsuma.ram.clamd import parse_reply
from satsuma.ram.proc import Process, Region, parse_maps
from satsuma.worker_memory import WorkerMemory

ROOT = Path(__file__).resolve().parents[1]

class Store:
    def __init__(self):self.values={};self.records=[]
    def set(self,k,v):self.values[k]=v
    def get(self,k,default=None):return self.values.get(k,default)
    def add(self,k,v):self.records.append((k,v))

class Monitor:
    def __init__(self,*args):self.acked=0
    def drain(self):
        return [{'pid':42,'observed_at':100.,'findings':[{'identity':(42,99,'/fixture',1,1),'status':'REPRODUCED_SIGNATURE','signature':'Fixture'}]}]
    def health(self):return {'status':'OBSERVING','full_ram_coverage':False}
    def ack(self):self.acked+=1

class IntegrationTests(unittest.TestCase):
    def test_delivery_failure_retains_memory_evidence(self):
        s=Store();w=WorkerMemory(s)
        class Pipeline:
            def ingest_host(self,e):raise RuntimeError('fixture_delivery_failure')
        with patch('satsuma.ram.coordinator.MemoryMonitor', Monitor):
            result=w.tick(Pipeline())
        self.assertFalse(result['progress_committed'])
        self.assertEqual(w.ram_v2.acked,0)
        self.assertEqual(w.last,0)
    def test_delivery_success_acknowledges_after_original_worker(self):
        s=Store()
        with tempfile.TemporaryDirectory() as d:
            w=WorkerMemory(s,proc_root=d);events=[]
            class Pipeline:
                def ingest_host(self,e):events.append(e)
            with patch('satsuma.ram.coordinator.MemoryMonitor', Monitor):
                w.tick(Pipeline())
            self.assertEqual(w.ram_v2.acked,1)
            self.assertEqual(events[0]['action'],'ram_signature_match_v2')
            self.assertIn('worker.memory.health',s.values)
            self.assertIn('worker.ram_v2.health',s.values)
    def test_pipeline_missing_does_not_start_thread(self):
        w=WorkerMemory(Store());w.tick(None)
        self.assertIsNone(w.ram_v2)
    def test_monitor_round_robin_pruning_and_capacity_visible(self):
        m=MemoryMonitor(autostart=False)
        with patch('satsuma.ram.coordinator.MAX_TRACKED',2):
            m.refresh([3,1,2]);self.assertEqual(list(m.order),[1,2]);self.assertEqual(m.capacity_excluded,1)
            m.refresh([2,3]);self.assertEqual(list(m.order),[2,3]);self.assertNotIn(1,m.progress)
    def test_delivery_backlog_stays_bounded(self):
        m=MemoryMonitor(autostart=False)
        for i in range(16):m.results.put_nowait({'pid':i,'status':'PARTIAL','observed_at':i})
        self.assertEqual(len(m.drain()),16)
        for i in range(16):m.results.put_nowait({'pid':i,'status':'PARTIAL','observed_at':i})
        self.assertEqual(len(m.drain()),16)
        self.assertEqual(m.results.qsize(),16)
        m.ack();self.assertEqual(len(m.drain()),16)
    def test_scope3_reported_blocked_without_writes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);p=root/'sys/kernel/yama/ptrace_scope';p.parent.mkdir(parents=True);p.write_text('3\n')
            m=MemoryMonitor(root,autostart=False);self.assertEqual(m.health()['status'],'BLOCKED');self.assertEqual(p.read_text(),'3\n')
    def test_unavailable_report_degrades_health(self):
        m=MemoryMonitor(autostart=False);m.ready=[{'pid':1,'status':'SCANNER_UNAVAILABLE','observed_at':1}]
        self.assertEqual(m.health()['status'],'DEGRADED')
    def test_event_uses_original_observation_time_and_identity(self):
        e=finding_event({'observed_at':1},{'identity':(7,8,'/fixture',9,10),'signature':'Fixture'})
        self.assertEqual(e['timestamp'],1);self.assertEqual(e['metadata']['extensions']['host.starttime'],8)
    def test_clamd_reply_errors_and_heuristics(self):
        self.assertEqual(parse_reply(b'stream: OK')['status'],'NO_MATCH')
        self.assertEqual(parse_reply(b'stream: Heuristics.Fixture FOUND')['status'],'REVIEW_REQUIRED')
        self.assertEqual(parse_reply(b'stream: PUA.Fixture FOUND')['status'],'REVIEW_REQUIRED')
        self.assertEqual(parse_reply(b'stream: Fixture FOUND')['status'],'SIGNATURE_MATCH')
        self.assertEqual(parse_reply(b'stream: Heuristics.Limits.Exceeded.MaxScanTime FOUND')['status'],'LIMIT_EXCEEDED')
        with self.assertRaises(RuntimeError):parse_reply(b'stream: scan failed ERROR')
        with self.assertRaises(RuntimeError):parse_reply(b'stream: bad\nname FOUND')
    def test_shared_anon_included_device_excluded(self):
        p=object.__new__(Process)
        self.assertTrue(p.eligible(Region(0,4096,'rw-s',0,(0,0),0,''))[0])
        self.assertFalse(p.eligible(Region(0,4096,'rw-s',0,(0,0),0,'/dev/fake'))[0])
    def test_regular_backing_must_match_inode(self):
        p=object.__new__(Process);p.fd=999
        with patch('satsuma.ram.proc.os.stat',side_effect=PermissionError):
            self.assertEqual(p.eligible(Region(0,4096,'rw-s',0,(0,1),2,'/file'))[1],'backing_type_unverified')
    def test_maps_parser_rejects_overlap(self):
        with self.assertRaises(ValueError):parse_maps('00000000-00002000 rw-p 0 00:00 0\n00001000-00003000 rw-p 0 00:00 0\n')
    def test_config_is_in_integrity_external_inventory(self):
        source=(ROOT/'installer/image_runtime.py').read_text()
        self.assertIn("'/etc/clamd.d/satsuma-ram.conf'",source)
    def test_packaging_contains_local_scanner_and_ordering(self):
        spec=(ROOT/'packaging/satsuma-core.spec').read_text()
        self.assertIn('Requires: clamd',spec)
        self.assertIn('%config(noreplace) /etc/clamd.d/satsuma-ram.conf',spec)
        self.assertIn('Wants=satsuma-ram-clamd.service',(ROOT/'systemd/satsuma-core.service').read_text())
    def test_new_detection_rule_has_no_direct_destructive_action(self):
        import yaml
        rules=yaml.safe_load((ROOT/'rules/memory_integrity.yaml').read_text())
        rule=next(r for r in rules if r['id']=='SATSUMA-RAM-106')
        self.assertEqual(rule['actions'],['record','evidence','correlation_request'])
        self.assertEqual(len([r for r in rules if r['id']=='SATSUMA-RAM-005']),1)

class ResponseRevalidationTests(unittest.TestCase):
    def test_review_event_does_not_become_signature_event(self):
        e=finding_event({'observed_at':1},{'identity':(1,2,'/fixture',3,4),'status':'REVIEW_REQUIRED'})
        self.assertEqual(e['action'],'ram_review_v2')
    def test_revalidation_rejects_wrong_pid_and_scan_limit_before_read(self):
        from satsuma.ram.revalidate import revalidate
        with patch('satsuma.ram.revalidate.Process') as p:
            self.assertFalse(revalidate(1, {'identity':[2,3,'/fixture',4,5],'status':'REPRODUCED_SIGNATURE'}))
            self.assertFalse(revalidate(1, {'identity':[1,3,'/fixture',4,5],'status':'REVIEW_REQUIRED',
                                            'signature':'Heuristics.Limits.Exceeded.MaxScanTime'}))
            self.assertFalse(revalidate(1, {'identity':[1,3,'/fixture',4,5],'status':'NO_MATCH','signature':'Fixture'}))
            p.assert_not_called()
    def test_a_heuristic_or_unconfirmed_signature_is_reproduced_then_stops(self):
        # 2.2.38 (owner, 2026-11-13): RAM-107 is read and scanned again, not only recorded.
        from satsuma.ram import revalidate as module
        for name in ('Heuristics.Fixture','PUA.Fixture','Unix.Trojan.Fixture'):
            with patch.object(module,'Process') as p,patch.object(module,'confirm',return_value=True) as c:
                self.assertTrue(module.revalidate(1,{'identity':[1,3,'/fixture',4,5],'status':'REVIEW_REQUIRED','signature':name}))
                p.assert_called_once_with(1);c.assert_called_once()
    def test_auto_process_denies_even_with_user_enforcement(self):
        from satsuma.auto_process import respond
        from unittest.mock import Mock
        event={'source':'memory','action':'ram_signature_match_v2','pid':42,'timestamp':100,
               'metadata':{'extensions':{'host.pid':42,'host.starttime':99,'host.exe':'/fixture','host.ram_v2':{'status':'REVIEW_REQUIRED'}}}}
        response=Mock();store=Store()
        with patch('satsuma.auto_process.verify_process_identity',return_value={'ok':True}),patch('satsuma.ram.revalidate.revalidate',return_value=False):
            r=respond(store,{'user_enforcement':True,'auto_action_process_enabled':True},{'rule_id':'SATSUMA-RAM-106','event':event},response)
        self.assertEqual(r['reasons'],['ram_signature_revalidation_failed']);response.terminate_process.assert_not_called()
    def test_successful_revalidation_still_respects_disabled_policy(self):
        from satsuma.auto_process import respond
        from unittest.mock import Mock
        import time
        event={'source':'memory','action':'ram_signature_match_v2','pid':42,'timestamp':time.time(),
               'metadata':{'extensions':{'host.pid':42,'host.starttime':99,'host.exe':'/fixture','host.ram_v2':{'status':'REPRODUCED_SIGNATURE'}}}}
        response=Mock();store=Store()
        with patch('satsuma.auto_process.verify_process_identity',return_value={'ok':True}),patch('satsuma.ram.revalidate.revalidate',return_value=True):
            r=respond(store,{'auto_action_process_enabled':False},{'rule_id':'SATSUMA-RAM-106','classification':'suspicious','severity':'high','event':event},response)
        self.assertIn('automatic_process_response_disabled',r['reasons']);response.terminate_process.assert_not_called()

class FinalSignalGuardTests(unittest.TestCase):
    def worker(self):
        from satsuma.response import ResponseWorker
        from unittest.mock import Mock
        w=object.__new__(ResponseWorker)
        w.store=Store();w.config={};w._rule_evidence_guard=Mock(return_value=None)
        w._privd=Mock(return_value=None);w._safe_pid=Mock(return_value=42);w._guard=Mock(return_value=None)
        return w
    def test_recheck_failure_prevents_sigterm(self):
        from unittest.mock import Mock
        from contextlib import ExitStack
        import satsuma.response as mod
        w=self.worker();poller=Mock();poller.poll.return_value=[]
        with ExitStack() as stack:
            stack.enter_context(patch.object(mod,'verify_process_identity',return_value={'ok':True}))
            stack.enter_context(patch.object(mod.os,'pidfd_open',return_value=999,create=True))
            stack.enter_context(patch.object(mod.os,'close'))
            stack.enter_context(patch.object(mod.select,'poll',return_value=poller))
            signal=stack.enter_context(patch.object(mod.signal,'pidfd_send_signal',create=True))
            stack.enter_context(patch('satsuma.ram.revalidate.revalidate',return_value=False))
            r=w.terminate_process(42,'fixture',evidence={'action':'ram_signature_match_v2'},context={'ram_v2_required':True,'ram_v2_evidence':{}})
            self.assertEqual(r['status'],'ram_signature_revalidation_failed');self.assertFalse(r['signal_sent']);signal.assert_not_called()
    def test_changed_evidence_prevents_escalation(self):
        from unittest.mock import Mock
        from contextlib import ExitStack
        import satsuma.response as mod
        w=self.worker();poller=Mock();poller.poll.return_value=[]
        with ExitStack() as stack:
            stack.enter_context(patch.object(mod,'verify_process_identity',return_value={'ok':True}))
            stack.enter_context(patch.object(mod.os,'pidfd_open',return_value=999,create=True))
            stack.enter_context(patch.object(mod.os,'close'))
            stack.enter_context(patch.object(mod.select,'poll',return_value=poller))
            signal=stack.enter_context(patch.object(mod.signal,'pidfd_send_signal',create=True))
            stack.enter_context(patch('satsuma.ram.revalidate.revalidate',side_effect=[True,False]))
            r=w.terminate_process(42,'fixture',evidence={'action':'ram_signature_match_v2'},context={'ram_v2_required':True,'ram_v2_evidence':{}})
            self.assertEqual(r['status'],'ram_signature_revalidation_failed')
            self.assertEqual(signal.call_count,1)
            self.assertEqual(signal.call_args.args[1],mod.signal.SIGTERM)
