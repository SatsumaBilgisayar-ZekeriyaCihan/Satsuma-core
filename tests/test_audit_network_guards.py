"""Read-only security guard regressions / Salt okunur güvenlik kapısı regresyonları."""
import unittest
from unittest.mock import Mock, patch
from satsuma import network_control

class NetworkGuardTests(unittest.TestCase):
    def test_guard_denial_never_touches_firewall(self):
        w=Mock();w._guard.return_value={'status':'denied_fixture'}
        with patch('satsuma.network_control.run') as run:
            result=network_control.block(w,'198.51.100.10','fixture')
        self.assertEqual(result['status'],'denied_fixture');run.assert_not_called();w._protected_ip.assert_not_called()
    def test_invalid_ip_rejected_before_guard_or_firewall(self):
        w=Mock()
        with patch('satsuma.network_control.run') as run:
            with self.assertRaises(ValueError):network_control.block(w,'invalid-address','fixture')
        run.assert_not_called();w._guard.assert_not_called()
    def test_protected_dns_address_never_reaches_firewall(self):
        w=Mock();w._guard.return_value=None;w._protected_ip.return_value='protected_dns_resolver';w.config={}
        with patch('satsuma.network_control.run') as run:
            result=network_control.block(w,'192.0.2.53','fixture')
        self.assertEqual(result['status'],'protected_dns_resolver');run.assert_not_called()
    def test_operator_allowlist_not_overridden(self):
        w=Mock();w._guard.return_value=None;w._protected_ip.return_value=None;w.config={};w.store.get.return_value=['198.51.100.10']
        with patch('satsuma.network_control.run') as run:
            result=network_control.block(w,'198.51.100.10','fixture')
        self.assertEqual(result['status'],'operator_allowlisted');run.assert_not_called()
