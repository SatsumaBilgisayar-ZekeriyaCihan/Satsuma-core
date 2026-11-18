"""Manual verification uses the complete pipeline and preserves visible outcomes."""
import unittest
from unittest.mock import Mock
from satsuma.maintenance_jobs import MaintenanceJobs
from satsuma.verification_view import job_text, decision_text

class AdminVerificationTests(unittest.TestCase):
    def test_manual_check_runs_serialized_full_service_and_preserves_failure(self):
        process=Mock();process.poll.return_value=None
        def launch(command,**kwargs):
            self.assertEqual(command,['/usr/bin/systemctl','start','--wait','satsuma-integrity-check.service'])
            self.assertNotIn('shell',kwargs)
            kwargs['stdout'].write(b'fixture verification failed')
            return process
        jobs=MaintenanceJobs(Mock(),popen=launch)
        self.assertTrue(jobs.start('boot_check')['accepted'])
        self.assertEqual(jobs.status()['status'],'RUNNING')
        with self.assertRaises(RuntimeError):jobs.start('boot_check')
        process.poll.return_value=1
        result=jobs.status()
        self.assertEqual(result['status'],'FAILED')
        self.assertIn('fixture verification failed',job_text(result))
        self.assertEqual(jobs.status(),result)
    def test_completed_job_does_not_claim_trust(self):
        self.assertIn('güven kararı',job_text({'status':'COMPLETED'}))
        self.assertIn('kilitli',decision_text(None))
        self.assertIn('kilitli',decision_text({'allowed':True,'status':'LOCKED'}))
    def test_diagnostic_output_is_bounded(self):
        self.assertLess(len(job_text({'output':'x'*50000})),10200)
    def test_unauthenticated_button_request_never_launches(self):
        from satsuma.operator_service import OperatorController
        jobs=Mock();auth=Mock();auth.validate_session.return_value=False
        controller=OperatorController(Mock(),auth=auth,jobs=jobs)
        with self.assertRaises(PermissionError):controller.dispatch(1000,'boot_check',{'token':'invalid'})
        jobs.start.assert_not_called()
    def test_qt_health_refresh_keeps_job_failure_visible(self):
        try:
            from PyQt6.QtWidgets import QApplication,QPushButton
        except ImportError:self.skipTest('Qt6 unavailable locally; Fedora CI installs Qt6')
        import sys
        from pathlib import Path
        sys.path.insert(0,str(Path(__file__).parents[1]/'tools'))
        from dashboard_fixture import FakeBackend
        from satsuma.dashboard_qt.panels.health import HealthPanel
        app=QApplication.instance() or QApplication([])
        panel=HealthPanel(FakeBackend());acted=[];panel.act=lambda action,refresh=True:acted.append(action)
        try:
            panel._operator_status('status',{},{'ok':True,'maintenance':{'status':'FAILED','operation':'boot_check','output':'fixture diagnostic'},'verification':{'allowed':False,'status':'LOCKED','reasons':['application_integrity_unverified']}})
            self.assertIn('fixture diagnostic',panel.jobs.text())
            self.assertIn('kilitli',panel.jobs.text())
            button=next(b for b in panel.findChildren(QPushButton) if b.text()=='Dosyaları şimdi doğrula')
            button.click();self.assertEqual(acted[-1],{'method':'boot_check','params':{}})
        finally:panel.close()
