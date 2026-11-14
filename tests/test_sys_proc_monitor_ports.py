import unittest
from satsuma.sys_proc_monitor import SysProcMonitor


class PortAlarmTests(unittest.TestCase):
    def classify(self, port):
        monitor = SysProcMonitor.__new__(SysProcMonitor)
        diff = {
            'new_ports': [port],
            'new_modules': [],
            'kernel_taint_changed': False,
            'new_usb': [],
            'new_processes': [],
        }
        return monitor._classify_alarm(diff)

    def test_ipv4_wildcard_listener_alerts(self):
        alarms = self.classify('tcp:0.0.0.0:8080')
        self.assertEqual([a['type'] for a in alarms], ['new_listening_port'])

    def test_ipv6_wildcard_listener_alerts(self):
        alarms = self.classify('tcp:[::]:8080')
        self.assertEqual([a['type'] for a in alarms], ['new_listening_port'])

    def test_star_wildcard_listener_alerts(self):
        alarms = self.classify('tcp:*:5353')
        self.assertEqual([a['type'] for a in alarms], ['new_listening_port'])

    def test_loopback_listener_does_not_alert_as_wildcard(self):
        alarms = self.classify('tcp:127.0.0.1:8080')
        self.assertEqual(alarms, [])

    def test_specific_ipv6_address_does_not_alert_as_wildcard(self):
        alarms = self.classify('tcp:[fe80::1]:8080')
        self.assertEqual(alarms, [])


if __name__ == '__main__':
    unittest.main()
