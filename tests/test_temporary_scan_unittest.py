"""Ten-minute temporary scan wiring and inode-bound quarantine, isolated files."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from satsuma.host_store import HostStore
from satsuma import temporary_scan as scan
from satsuma import scan_quarantine as q


class TemporaryScanTests(unittest.TestCase):
    def setUp(self):
        # Quarantine storage refuses world-writable ancestors such as /tmp; use a
        # private base when one exists (root's home), else skip.
        base = Path.home()
        if os.geteuid() != 0 or base.stat().st_uid != 0 or base.stat().st_mode & 0o022:
            self.skipTest('needs root and a private root-owned base directory')
        self.temporary = tempfile.TemporaryDirectory(dir=base)
        os.chmod(self.temporary.name, 0o700)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / 'temp-area'
        self.target.mkdir()
        self.file = self.target / 'inert-fixture'
        self.file.write_bytes(b'inert test marker')
        self.store = HostStore(self.root / 'host', test=True)
        self.addCleanup(self.store.close)
        self.directory = self.root / 'quarantine'
        actual_quarantine = q.quarantine_target
        def quarantine(target, audit):
            return actual_quarantine(target, audit, directory=self.directory, pending=self.root / 'pending')
        self.patches = [patch.object(q, 'ALLOWED_ROOTS', (self.target,)),
                        patch.object(q, 'quarantine_target', quarantine)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def matched(self, fd):
        self.assertEqual(os.pread(fd, 100, 0), b'inert test marker')
        return {'status': 'SIGNATURE_MATCH', 'signature': 'Fixture.TestOnly'}

    def test_confirmed_file_match_is_automatically_quarantined(self):
        # Retain a test-owned descriptor for content verification; the payload
        # is stored with the standard private quarantine mode.
        retained=self.file.open('rb')
        self.addCleanup(retained.close)
        result = scan.run_once(self.store, roots=(self.target,), scanner=self.matched)
        self.assertEqual(result['interval_seconds'], 600)
        self.assertEqual(result['quarantined'], 1, result)
        self.assertFalse(self.file.exists())
        payloads = [p for p in self.directory.iterdir() if p.suffix != '.json']
        self.assertEqual(retained.read(), b'inert test marker')
        self.assertEqual(payloads[0].stat().st_mode & 0o777, 0o600)  # same mode as every other quarantine path

    def test_changed_during_scan_is_not_quarantined(self):
        def changing(fd):
            self.file.write_bytes(b'changed')
            return {'status': 'SIGNATURE_MATCH', 'signature': 'Fixture.TestOnly'}
        result = scan.run_once(self.store, roots=(self.target,), scanner=changing)
        self.assertEqual(result['quarantined'], 0)
        self.assertGreater(result['errors'], 0)
        self.assertTrue(self.file.exists())

    def test_replaced_path_cannot_quarantine_replacement(self):
        def replacing(fd):
            self.file.rename(self.file.with_suffix('.old'))
            self.file.write_bytes(b'new innocent file')
            return {'status': 'SIGNATURE_MATCH', 'signature': 'Fixture.TestOnly'}
        result = scan.run_once(self.store, roots=(self.target,), scanner=replacing)
        self.assertEqual(result['quarantined'], 0)
        self.assertEqual(self.file.read_bytes(), b'new innocent file')

    def test_disabled_auto_quarantine_is_respected(self):
        result = scan.run_once(self.store, roots=(self.target,), scanner=self.matched, automatic=False)
        self.assertEqual(result['matches'], 1)
        self.assertEqual(result['quarantined'], 0)
        self.assertTrue(self.file.exists())

    def test_daemon_unavailable_is_degraded_not_clean(self):
        def unavailable(fd): raise FileNotFoundError('fixture missing socket')
        result = scan.run_once(self.store, roots=(self.target,), scanner=unavailable)
        self.assertEqual(result['status'], 'DEGRADED')
        self.assertTrue(result['partial'])
        self.assertEqual(result['quarantined'], 0)

    def test_symlinks_are_not_followed(self):
        outside = self.root / 'outside'
        outside.write_bytes(b'not a target')
        (self.target / 'symlink').symlink_to(outside)
        result = scan.run_once(self.store, roots=(self.target,), scanner=lambda fd: {'status':'NO_MATCH_IN_FILE'})
        self.assertGreater(result['errors'], 0)
        self.assertEqual(outside.read_bytes(), b'not a target')

    def test_timer_and_service_preserve_host_temporary_paths(self):
        root = Path(__file__).resolve().parents[1]
        timer = (root / 'systemd/satsuma-temporary-scan.timer').read_text()
        unit = (root / 'systemd/satsuma-temporary-scan.service').read_text()
        self.assertIn('OnUnitActiveSec=10min', timer)
        self.assertIn('PrivateTmp=no', unit)
        self.assertIn('PrivateDevices=no', unit)


if __name__ == '__main__':
    unittest.main()
