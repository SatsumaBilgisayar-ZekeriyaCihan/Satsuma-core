"""Names and user units must not impersonate privileged protection identities.

Adlar ve kullanıcı birimleri ayrıcalıklı koruma kimliklerini taklit edememeli.
"""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from satsuma import enforcement,finding_origin,process_identity

class ExemptionBoundaryTests(unittest.TestCase):
    def test_satsuma_word_in_an_argument_does_not_protect_arbitrary_code(self):
        self.assertFalse(process_identity._is_satsuma_process('/usr/bin/python3',
            'python3 -c pass satsuma-core'))
    def test_executable_name_prefix_does_not_make_a_trusted_program(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'42').mkdir();(Path(d)/'42/cgroup').write_text('0::/user.slice/user-1000.slice/app.scope\n')
            self.assertIsNone(enforcement.exempt(42,'/tmp/satsuma-anything',proc_root=d))
    def test_user_unit_cannot_be_the_authenticated_operator(self):
        self.assertFalse(finding_origin.started_by_operator({'pid':42,'source':'sys_proc'},
            cgroup_of=lambda pid:'/user.slice/user-1000.slice/user@1000.service/app.slice/satsuma-operator.service'))
    def test_mutable_comm_cannot_impersonate_systemd(self):
        with patch.object(process_identity,'read_proc_starttime',return_value=123), \
             patch.object(process_identity,'read_proc_exe',return_value='/tmp/fixture-program'), \
             patch.object(process_identity,'read_proc_comm',return_value='systemd'), \
             patch.object(process_identity,'read_proc_cmdline',return_value='fixture'), \
             patch.object(process_identity,'read_proc_cgroup',return_value='/user.slice/app.scope'):
            result=process_identity.verify_process_identity(424242,
                {'pid':424242,'starttime':123,'exe':'/tmp/fixture-program'})
        self.assertTrue(result['ok'],result)
    def test_pid_one_remains_protected(self):
        self.assertEqual(process_identity.verify_process_identity(1,{})['reason'],'protected_pid')
    def test_whitespace_inside_one_argument_cannot_become_a_script_path(self):
        from satsuma.trusted_process import satsuma_entry
        with patch('satsuma.trusted_process.trusted_path',return_value=True):
            self.assertFalse(satsuma_entry('/usr/bin/python3',
                ['python3','-X','foo -I /opt/satsuma-core/main.py']))
            self.assertTrue(satsuma_entry('/usr/bin/python3',
                ['python3','-I','/opt/satsuma-core/main.py']))
    def test_claimed_protected_exe_without_live_identity_is_not_an_exception(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d)/'42').mkdir();(Path(d)/'42/cgroup').write_text('0::/user.slice/app.scope\n')
            with patch('satsuma.trusted_process.trusted_path',return_value=True):
                self.assertIsNone(enforcement.exempt(42,'/usr/bin/anydesk',proc_root=d))
    def test_real_system_operator_group_remains_recognized(self):
        self.assertTrue(finding_origin.started_by_operator({'pid':42,'source':'sys_proc'},
            cgroup_of=lambda pid:'/system.slice/satsuma-operator.service'))
