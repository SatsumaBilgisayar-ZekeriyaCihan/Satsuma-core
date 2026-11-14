"""Update recovery and reader-to-screen evidence tests; never touch host services."""
import json
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch
from satsuma.network_health_view import network_model
from satsuma.self_health import disabled_dns_check
from satsuma.status_view import health_summary
ROOT=Path(__file__).resolve().parents[1]

class StabilityTests(unittest.TestCase):
    def identity(self):
        reference={'gateway':'10.20.30.1','interface':'eth0','gateway_mac':'00:11:22:33:44:55'}
        return {'status':'MODEM_REFERENCE_CHANGED','reference':reference,'gateways':[reference.copy()],
                'additional_gateway_candidates':[],'routing_snapshot_matches':False,'updated_at':time.time()}
    def test_same_modem_changed_routes_are_visible_without_reenrollment(self):
        data=self.identity();before=json.dumps(data,sort_keys=True)
        model=network_model(data)
        self.assertIn('Modem kimliği eşleşiyor',model['summary'])
        self.assertEqual(model['state'],'Rota değişikliği')
        self.assertIn('belirlenemiyor',' '.join(model['items']))
        self.assertEqual(json.dumps(data,sort_keys=True),before)
    def test_changed_modem_is_never_presented_as_same_or_healthy(self):
        data=self.identity();data['gateways']=[{**data['reference'],'gateway_mac':'00:11:22:33:44:66'}]
        model=network_model(data)
        self.assertEqual(model['tone'],'problem')
        self.assertNotIn('kimliği eşleşiyor',model['summary'])
    def test_stale_network_record_is_unknown_even_if_previously_matched(self):
        data=self.identity();data.update(status='MATCHED_USER_APPROVAL',routing_snapshot_matches=True,updated_at=time.time()-100)
        self.assertEqual(network_model(data)['tone'],'unknown')
    def test_disabled_dns_is_not_successful_protection_and_summary_names_it(self):
        check=disabled_dns_check({'enabled':False})
        self.assertFalse(check['ok']);self.assertFalse(check['protection_active'])
        self.assertTrue(check['configuration_valid'])
        summary=health_summary({'status':'HEALTHY','checked_at':time.time()}, {},
            {'status':'DEGRADED','updated_at':time.time(),'checks':{'dns_filter':check}})
        self.assertIn('DNS filtresi',summary['message'])
        self.assertEqual(summary['protection'],'Sorun var')
    def recovery(self,status,recorded=True,image=True):
        spec=(ROOT/'packaging/satsuma-core.spec').read_text()
        block=spec.split('# BEGIN PRE FAILURE RECOVERY\n')[1].split('# END PRE FAILURE RECOVERY')[0]
        with tempfile.TemporaryDirectory() as d:
            ledger=Path(d)/'units';ledger.write_text('satsuma-core.service\nsatsuma-reader.service\nsatsuma-self-health.timer\n')
            block=block.replace('/var/lib/satsuma-core/rpm-active-units',str(ledger))
            script='systemctl() { printf "CALL:%s\\n" "$*"; return 0; }\n'+block
            script+='\nsatsuma_stopped_recorded='+str(int(recorded))+'\nsatsuma_image_was_active='+str(int(image))+'\nexit '+str(status)+'\n'
            return subprocess.run(['/bin/bash','-c',script],capture_output=True,text=True)
    def test_failed_update_restores_image_and_recorded_consumers_preserving_error(self):
        result=self.recovery(42)
        self.assertEqual(result.returncode,42)
        calls=result.stdout.splitlines()
        self.assertEqual(calls[0],'CALL:start satsuma-image.service')
        self.assertIn('CALL:start satsuma-core.service',calls)
        self.assertIn('CALL:start satsuma-self-health.timer',calls)
        self.assertNotIn('unmask',result.stdout)
    def test_success_and_preflight_failure_do_not_restart_services(self):
        self.assertEqual(self.recovery(0).stdout,'')
        self.assertEqual(self.recovery(42,recorded=False,image=False).stdout,'')
    def test_privd_is_known_and_stopped_after_producers_before_image(self):
        spec=(ROOT/'packaging/satsuma-core.spec').read_text()
        self.assertIn('satsuma-privd.service|satsuma-ram-clamd.service|',spec)
        pre=spec.split('%preun')[0]
        units=pre.split(' for unit in ')[1].split('; do')[0].split()
        self.assertLess(units.index('satsuma-core'),units.index('satsuma-privd'))
        self.assertIn('is-active --quiet "$timer"',pre)
    def test_all_packaged_vendor_units_are_recognized_without_replaying_quarantine(self):
        import re
        spec=(ROOT/'packaging/satsuma-core.spec').read_text()
        known_line=spec.split('case "$retired" in')[1].split(' :;;')[0]
        known=set(re.findall(r'satsuma[^|\s)]+',known_line))
        vendor={p.name for p in (ROOT/'systemd').iterdir() if p.suffix in ('.service','.timer')}
        self.assertFalse(vendor-known, str(vendor-known))
        pre=spec.split('%preun')[0]
        units=pre.split(' for unit in ')[1].split('; do')[0].split()
        self.assertIn('satsuma-mitm-watch',units)
        self.assertNotIn('satsuma-quarantine-rollback',units)
        self.assertNotIn('satsuma-quarantine-confirm',units)
    def test_qt_system_health_exposes_existing_reader_identity_and_dns_state(self):
        try:from PyQt6.QtWidgets import QApplication
        except ImportError:self.skipTest('Qt6 unavailable locally; installed in Fedora CI')
        from satsuma.dashboard_qt.panels.system_health import SystemHealthPanel
        app=QApplication.instance() or QApplication([])
        backend=Mock();backend.call.return_value={'network_identity':self.identity(),
            'self_health':{'status':'DEGRADED','checks':{'dns_filter':disabled_dns_check({'enabled':False})}},
            'summary':{'overall':'Sorun var','protection':'Sorun var'}}
        panel=SystemHealthPanel(backend)
        try:
            panel.refresh();backend.call.assert_called_with('system_health')
            self.assertIn('Modem kimliği eşleşiyor',panel.cards['identity'].summary.text())
            self.assertIn('Rota',panel.cards['identity'].pill.text())
            self.assertIn('kapalı',panel.cards['dns'].summary.text())
        finally:panel.close()
