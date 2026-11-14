"""Rollback refusal must precede remount / Geri alma reddi remount'tan önce olmalı."""
import tempfile
from pathlib import Path
from unittest.mock import Mock
import unittest
from satsuma import memory_access, memory_hardening, memory_mounts

class RollbackTests(unittest.TestCase):
    def fixture(self, directory, current_scope='3'):
        root=Path(directory)
        original={'schema':1,'sysctls':dict(memory_access.POLICY),
                  'mounts':{name:{'fstype':kind,'options':['rw']} for name,(kind,flags) in memory_mounts.POLICY.items()}}
        for name,value in original['sysctls'].items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text((current_scope if name=='kernel/yama/ptrace_scope' else value)+'\n')
        backup=Mock();backup.read.return_value=original
        mounts={name:{'fstype':kind,'options':{'rw'}} for name,(kind,flags) in memory_mounts.POLICY.items()}
        return root,backup,mounts
    def test_scope3_refuses_before_any_remount(self):
        with tempfile.TemporaryDirectory() as d:
            root,backup,mounts=self.fixture(d);runner=Mock()
            with self.assertRaisesRegex(RuntimeError,'cannot be relaxed'):
                memory_hardening.restore(backup,root,lambda:mounts,runner)
            runner.assert_not_called()
            self.assertEqual((root/'kernel/yama/ptrace_scope').read_text(),'3\n')
    def test_missing_sysctl_refuses_before_any_remount(self):
        with tempfile.TemporaryDirectory() as d:
            root,backup,mounts=self.fixture(d,'2');(root/'fs/suid_dumpable').unlink();runner=Mock()
            with self.assertRaises(OSError):memory_hardening.restore(backup,root,lambda:mounts,runner)
            runner.assert_not_called()
