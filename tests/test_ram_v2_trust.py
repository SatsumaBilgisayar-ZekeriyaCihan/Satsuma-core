"""Active response lock agrees with trust reports / Müdahale kilidi güven raporuyla tutarlıdır."""
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from satsuma.intervention_guard import evaluate
from satsuma.response import ResponseWorker
from satsuma.early_guard import read_verdict

class Store:
    def __init__(self,status='HEALTHY'):self.values={'integrity_runtime':{'status':status}}
    def get(self,k,d=None):return self.values.get(k,d)
    def set(self,k,v):self.values[k]=v
    def add(self,*args):pass

class TrustTests(unittest.TestCase):
    def verdict(self):return {'state':'FULL_CHECKED','response_unlocked':True}
    def test_valid_runtime_and_fresh_verdict_required(self):
        self.assertTrue(evaluate(Store(),self.verdict)['allowed'])
        self.assertFalse(evaluate(Store('UNTRUSTED'),self.verdict)['allowed'])
        self.assertFalse(evaluate(Store(),lambda:{'state':'STALE','response_unlocked':False})['allowed'])
    def test_unknown_malformed_or_exception_denies(self):
        for verdict in [None,[],{'state':'FULL_CHECKED','response_unlocked':'true'}]:
            self.assertFalse(evaluate(Store(),lambda:verdict)['allowed'])
        def broken():raise OSError('fixture')
        self.assertFalse(evaluate(Store(),broken)['allowed'])
    def test_config_flag_cannot_disable_gate(self):
        w=ResponseWorker(Store('UNTRUSTED'),{'response_enabled':True,'early_guard_required':False},runner=Mock())
        with patch('satsuma.early_guard.read_verdict',return_value=self.verdict()):
            self.assertEqual(w._guard('kill_process',42)['status'],'integrity_locked')
    def test_no_firewall_operation_when_locked(self):
        runner=Mock();w=ResponseWorker(Store('UNTRUSTED'),{'response_enabled':True},runner=runner)
        with patch('satsuma.early_guard.read_verdict',return_value=self.verdict()):
            self.assertEqual(w.block_ip('198.51.100.1','fixture')['status'],'integrity_locked')
        runner.assert_not_called()
    def test_no_privd_delegation_when_locked(self):
        w=ResponseWorker(Store('UNTRUSTED'),{'response_enabled':True})
        with patch('satsuma.early_guard.read_verdict',return_value=self.verdict()),patch('satsuma.privd.delegate') as delegate:
            self.assertEqual(w._privd('terminate',pid=42)['status'],'integrity_locked')
        delegate.assert_not_called()
    def test_broker_side_independently_denies(self):
        from satsuma.privd import handle
        w=ResponseWorker(Store('UNTRUSTED'),{'response_enabled':True},runner=Mock())
        with patch('satsuma.privd.allowed',return_value=True),patch('satsuma.early_guard.read_verdict',return_value=self.verdict()):
            r=handle({'op':'block_ip','ip':'198.51.100.1','reason':'fixture'}, {'uid':0},w,lambda x:None)
        self.assertEqual(r['status'],'integrity_locked');w.runner.assert_not_called()
    def test_replay_still_denies(self):
        w=ResponseWorker(Store(),{'response_enabled':True},replay=True)
        self.assertEqual(w._guard('kill_process')['status'],'replay_skip')
    def test_missing_required_verdict_checks_do_not_unlock(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'verdict.json';p.write_text(json.dumps({'schema':2,'boot_id':'fixture','generated_monotonic':time.monotonic(),'state':'FULL_CHECKED','response_unlocked':True,'checks':{'application':{'ok':True},'critical_paths':{'ok':True}}}));p.chmod(0o600)
            with patch('satsuma.early_guard.current_boot_id',return_value='fixture'):
                self.assertFalse(read_verdict(p)['response_unlocked'])

    def test_startup_does_not_import_app_after_integrity_failure(self):
        import runpy,sys,types
        fake=types.ModuleType('satsuma.self_guard');fake.verify=Mock(side_effect=RuntimeError('fixture integrity mismatch'))
        with patch.dict(sys.modules,{'satsuma.self_guard':fake}),patch.object(sys,'argv',['main.py','--run']):
            with self.assertRaises(SystemExit) as error:
                runpy.run_path(str(Path(__file__).resolve().parents[1]/'main.py'),run_name='__main__')
        self.assertEqual(error.exception.code,78)
