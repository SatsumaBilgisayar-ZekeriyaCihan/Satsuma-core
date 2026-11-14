"""Health isolation and honest partial scope regression tests."""
import json
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch
from satsuma.ram.coordinator import MemoryMonitor
from satsuma.ram import engine
from test_ram_v2_engine import FakeProcess, Scanner

class HealthIsolationTests(unittest.TestCase):
    def test_health_uses_only_indexed_core_state_without_history(self):
        from satsuma import dashboard_api as api
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'core.db';db=sqlite3.connect(path)
            db.execute('CREATE TABLE state(key TEXT PRIMARY KEY,body TEXT)')
            db.execute('INSERT INTO state VALUES (?,?)',('worker.memory.health',json.dumps({'status':'RUNNING'})))
            db.execute('INSERT INTO state VALUES (?,?)',('worker.ram_v2.health',json.dumps({'status':'DEGRADED'})))
            db.commit();db.close()
            with patch.object(api,'DB_PATH',str(path)),patch.object(api,'m_findings',side_effect=AssertionError('history must not run')),patch.object(api,'m_workers',side_effect=AssertionError('all workers must not run')):
                result=api.m_memory_health()
            self.assertEqual(result['collector']['status'],'RUNNING')
            self.assertEqual(result['ram_v2']['status'],'DEGRADED')
    def test_process_churn_is_distinct_from_scanner_failure(self):
        with tempfile.TemporaryDirectory() as d:
            m=MemoryMonitor(d,autostart=False)
            m.ready=[{'pid':1,'observed_at':time.time(),'status':'PROCESS_UNAVAILABLE','error':'FileNotFoundError'},
                     {'pid':2,'observed_at':time.time(),'status':'PROCESS_CHANGED','scanner_bytes_this_turn':4096}]
            health=m.health()
            self.assertEqual(health['scanner_state'],'BYTES_SUBMITTED')
            self.assertEqual(health['coverage_state'],'INCOMPLETE')
            self.assertEqual(health['process_observation_counts'],{'process_or_required_metadata_missing':1,'changed_during_scan':1})
            self.assertFalse(health['clean_verdict'])
            m.ready=[{'pid':3,'observed_at':time.time(),'status':'SCANNER_UNAVAILABLE'}]
            self.assertEqual(m.health()['scanner_state'],'UNAVAILABLE')
    def test_finished_cycle_preserves_error_from_previous_turn(self):
        p=FakeProcess(maps='00000000-00000400 rw-p 00000000 00:00 0 [heap]\n00000400-00002000 rw-p 00000000 00:00 0 [heap]\n');progress=engine.Progress()
        original=p.read
        def fail_first(address,size):
            if address==0:raise PermissionError('fixture')
            return original(address,size)
        p.read=fail_first
        with patch.object(engine,'CHUNK',1024),patch.object(engine,'OVERLAP',64),patch.object(engine,'TURN_BYTES',2048):
            first=engine.scan_turn(p,Scanner(),progress)
            self.assertTrue(first['errors'])
            p.read=original
            for _ in range(20):
                report=engine.scan_turn(p,Scanner(),progress)
                if report['cycle_complete']:break
        self.assertTrue(report['cycle_complete'])
        self.assertEqual(report['errors'],{})
        self.assertGreater(report['cycle_unreadable_bytes'],0)
        self.assertEqual(report['status'],'CYCLE_FINISHED_INCOMPLETE')
        self.assertFalse(report['clean_verdict'])
    def test_qt_health_survives_history_timeout_and_repeated_refresh(self):
        try:from PyQt6.QtWidgets import QApplication
        except ImportError:self.skipTest('Qt6 unavailable locally; CI installs Qt6')
        from satsuma.dashboard_qt.panels.defense_sections import MemoryDefensePanel
        class Backend:
            fail=True
            def call(self,method,**params):
                if method=='memory_health':return {'collector':{'updated_at':time.time(),'inspected':3,'unreadable':0,'validation_counts':{}},'ram_v2':{'status':'DEGRADED','scanner_state':'BYTES_SUBMITTED','coverage_state':'INCOMPLETE','updated_at':time.time()}}
                if self.fail:raise TimeoutError('fixture historical query timeout')
                return {'items':[],'count':0,'data_state':'OK'}
        app=QApplication.instance() or QApplication([]);backend=Backend();panel=MemoryDefensePanel(backend)
        try:
            panel.refresh()
            self.assertIn('bellek verisi tarayıcıya iletildi',panel.status.text())
            self.assertNotIn('BYTES_SUBMITTED',panel.status.text())
            self.assertIn('BYTES_SUBMITTED',panel.scope_details.toPlainText())
            self.assertIn('fixture historical query timeout',panel.status.text())
            backend.fail=False;panel.refresh();panel.refresh()
            self.assertEqual(panel.status.text().count('Bulgu listesi:'),1)
        finally:panel.close()
    def test_qt_backend_routes_health_to_independent_queue(self):
        try:from PyQt6.QtCore import QCoreApplication
        except ImportError:self.skipTest('Qt6 unavailable locally; CI installs Qt6')
        from satsuma.dashboard_qt import backend as module
        with patch.object(module,'SOCKET_AVAILABLE',True),patch.object(module,'AsyncReader') as factory:
            from unittest.mock import Mock
            history=Mock();health=Mock();factory.side_effect=[history,health]
            backend=module.Backend();backend.call('memory_health');backend.call('memory_defense')
            health.call.assert_called_once_with('memory_health');history.call.assert_called_once_with('memory_defense')
            backend.close();health.close.assert_called_once();history.close.assert_called_once()
