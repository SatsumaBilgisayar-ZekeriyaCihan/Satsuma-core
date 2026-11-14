"""Validate RPM array/scalar inventory against the installed database.

RPM dizi/skaler envanterini kurulu gerçek veritabanıyla doğrula.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import unittest
from satsuma.binary_audit import rpm_inventory

class InstalledInventoryTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which('rpm'), 'RPM is exercised in the Fedora audit environment')
    def test_installed_rpm_binary_is_owned_and_its_digest_is_not_lost(self):
        inventory=rpm_inventory()
        entry=inventory.get('/usr/bin/rpm')
        self.assertIsNotNone(entry, 'A real installed package must not become zero package records')
        self.assertEqual(entry[0], 'rpm')
        self.assertTrue(entry[1])
        if entry[2]=='8':
            self.assertEqual(entry[1],hashlib.sha256(Path('/usr/bin/rpm').read_bytes()).hexdigest())
    @unittest.skipUnless(shutil.which('rpm'), 'RPM is exercised in the Fedora audit environment')
    def test_scalar_locking_produces_parseable_file_records(self):
        result=subprocess.run(['/usr/bin/rpm','-q','rpm','--qf',
            '[%{FILENAMES}\\t%{FILEDIGESTS}\\t%{=FILEDIGESTALGO}\\t%{=NAME}\\n]'],
            capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        rows=[s.split('\t') for s in result.stdout.splitlines()]
        self.assertTrue(rows)
        self.assertTrue(all(len(row)==4 and row[-1]=='rpm' for row in rows))
