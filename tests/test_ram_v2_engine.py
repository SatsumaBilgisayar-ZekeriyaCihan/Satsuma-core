import hashlib
import unittest
from unittest.mock import patch
from satsuma.ram import engine
from satsuma.ram.proc import parse_maps

class FakeProcess:
    def __init__(self, maps=None, data=None):
        self.maps = maps or '00000000-00002000 rw-p 00000000 00:00 0 [heap]\n'
        self.identity = (123, 100, '/fixture', 1, 1)
        self.data = data if data is not None else b'A' * 8192
        self.denied = False
    def snapshot(self):
        return self.identity, self.maps
    def eligible(self, r):
        return ('r' in r.perms, None if 'r' in r.perms else 'not_readable')
    def read(self, address, size):
        if self.denied:
            raise PermissionError('fixture')
        return self.data[address:address + size]

class Scanner:
    def __init__(self, signature=b'SAFE_FIXTURE'):
        self.signature = signature
        self.calls = 0
    def scan(self, data, deadline):
        self.calls += 1
        return {'status': 'SIGNATURE_MATCH', 'signature': 'Fixture'} if self.signature in data else {'status': 'NO_MATCH'}

class EngineTests(unittest.TestCase):
    def setUp(self):
        self.patches = [patch.object(engine, 'CHUNK', 1024), patch.object(engine, 'OVERLAP', 64), patch.object(engine, 'TURN_BYTES', 2048)]
        for p in self.patches:
            p.start()
            self.addCleanup(p.stop)
    def test_rotating_progress_and_unique_coverage(self):
        proc, scanner, progress = FakeProcess(), Scanner(), engine.Progress()
        reports = []
        for _ in range(20):
            r = engine.scan_turn(proc, scanner, progress)
            reports.append(r)
            self.assertLessEqual(r['read_bytes_this_turn'], 2048)
            if r['cycle_complete']:
                break
        self.assertTrue(reports[-1]['cycle_complete'])
        self.assertEqual(reports[-1]['cycle_scanned_unique_bytes'], 8192)
        self.assertFalse(any(r['clean_verdict'] for r in reports))
        self.assertEqual(progress.offset, 0)
        self.assertEqual(progress.cycles, 1)
    def test_cross_chunk_signature_and_confirmation(self):
        p = FakeProcess(data=b'A' * 1019 + b'SAFE_FIXTURE' + b'A' * 7161)
        scanner = Scanner()
        r = engine.scan_turn(p, scanner, engine.Progress())
        self.assertEqual(r['findings'][0]['status'], 'REPRODUCED_SIGNATURE')
        self.assertGreaterEqual(scanner.calls, 3)
        self.assertFalse(r['findings'][0]['automatic_action_authorized'])
    def test_shared_memory_included(self):
        r = engine.scan_turn(FakeProcess('00000000-00002000 rw-s 00000000 00:00 0\n'), Scanner(), engine.Progress())
        self.assertEqual(r['candidate_bytes'], 8192)
        self.assertGreater(r['scanner_bytes_this_turn'], 0)
    def test_access_denied_not_clean_or_scanned(self):
        p = FakeProcess();p.denied = True
        r = engine.scan_turn(p, Scanner(), engine.Progress())
        self.assertEqual(r['cycle_unreadable_bytes'], 8192)
        self.assertEqual(r['cycle_scanned_unique_bytes'], 0)
        self.assertTrue(r['cycle_complete'])
        self.assertFalse(r['clean_verdict'])
    def test_scanner_failure_retries_same_range(self):
        class Broken:
            def scan(self, *args):
                raise TimeoutError('fixture')
        progress = engine.Progress()
        r = engine.scan_turn(FakeProcess(), Broken(), progress)
        self.assertEqual(r['status'], 'SCANNER_UNAVAILABLE')
        self.assertEqual(progress.offset, 0)
        self.assertEqual(r['cycle_scanned_unique_bytes'], 0)
    def test_request_seconds_gives_every_scanner_request_its_own_deadline(self):
        # Windows passes request_seconds; Linux keeps the turn deadline (unchanged behaviour).
        class Recording(Scanner):
            def __init__(self):
                super().__init__()
                self.deadlines = []
            def scan(self, data, deadline):
                self.deadlines.append(deadline)
                return super().scan(data, deadline)
        now = [100.0]
        def clock():
            now[0] += 0.5
            return now[0]
        turn = Recording()
        engine.scan_turn(FakeProcess(), turn, engine.Progress(), clock=clock)
        self.assertGreater(len(turn.deadlines), 1)
        self.assertEqual(len(set(turn.deadlines)), 1)
        own = Recording()
        engine.scan_turn(FakeProcess(), own, engine.Progress(), clock=clock, request_seconds=3.0)
        self.assertGreater(len(own.deadlines), 1)
        self.assertEqual(len(set(own.deadlines)), len(own.deadlines))
        self.assertTrue(all(b > a for a, b in zip(own.deadlines, own.deadlines[1:])))
    def test_a_scan_limit_is_memory_not_covered_never_a_finding_or_clean(self):
        class Limited:
            def scan(self, data, deadline):
                return {'status': 'LIMIT_EXCEEDED', 'signature': 'Heuristics.Limits.Exceeded.MaxScanTime'}
        progress = engine.Progress()
        r = None
        for _ in range(8):
            r = engine.scan_turn(FakeProcess(), Limited(), progress)
            if r['cycle_complete']:
                break
        self.assertEqual(r['findings'], [])
        self.assertEqual(r['status'], 'CYCLE_FINISHED_INCOMPLETE')
        self.assertEqual(r['coverage_state'], 'INCOMPLETE')
        self.assertEqual(r['cycle_scanned_unique_bytes'], 0)
        self.assertEqual(r['cycle_limited_bytes'], 8192)
        self.assertFalse(r['clean_verdict'])
        self.assertEqual(engine.reply_status('Heuristics.Limits.Exceeded.MaxScanTime'), 'LIMIT_EXCEEDED')
        self.assertEqual(engine.reply_status('Heuristics.Encrypted.PDF'), 'REVIEW_REQUIRED')
        self.assertEqual(engine.reply_status('Win.Trojan.X'), 'SIGNATURE_MATCH')
    def test_layout_change_resets_progress(self):
        p, progress = FakeProcess(), engine.Progress()
        engine.scan_turn(p, Scanner(), progress)
        p.maps += '00002000-00003000 ---p 00000000 00:00 0\n'
        r = engine.scan_turn(p, Scanner(), progress)
        self.assertEqual(r['layout_resets'], 1)
        self.assertLessEqual(r['cycle_scanned_unique_bytes'], 2048)
    def test_reused_pid_resets_identity(self):
        p, progress = FakeProcess(), engine.Progress()
        engine.scan_turn(p, Scanner(), progress)
        p.identity = (123, 200, '/other', 1, 2)
        r = engine.scan_turn(p, Scanner(), progress)
        self.assertEqual(progress.identity[1], 200)
        self.assertEqual(r['layout_resets'], 1)
    def test_mapping_race_discards_signature(self):
        p = FakeProcess(data=b'SAFE_FIXTURE'+b'A'*8180)
        class Changing(Scanner):
            def scan(self, data, deadline):
                r = super().scan(data, deadline)
                p.maps += '\n'
                return r
        r = engine.scan_turn(p, Changing(), engine.Progress())
        self.assertEqual(r['status'], 'PROCESS_CHANGED')
        self.assertEqual(r['findings'], [])
    def test_changed_bytes_not_confirmed(self):
        p = FakeProcess(data=b'SAFE_FIXTURE'+b'A'*8180)
        class Changing(Scanner):
            def scan(self, data, deadline):
                r = super().scan(data, deadline)
                p.data = b'B' * 8192
                return r
        r = engine.scan_turn(p, Changing(), engine.Progress())
        self.assertEqual(r['findings'][0]['status'], 'REVIEW_REQUIRED')
    def test_heuristic_is_review_only(self):
        class Heuristic:
            def scan(self, *args):
                return {'status': 'REVIEW_REQUIRED', 'signature': 'Heuristics.Fixture'}
        r = engine.scan_turn(FakeProcess(), Heuristic(), engine.Progress())
        self.assertEqual(r['findings'][0]['status'], 'REVIEW_REQUIRED')
    def test_zero_candidates(self):
        r = engine.scan_turn(FakeProcess('00000000-00001000 ---p 00000000 00:00 0\n'), Scanner(), engine.Progress())
        self.assertEqual(r['status'], 'NO_ELIGIBLE_MEMORY')
        self.assertEqual(r['excluded_bytes_by_reason']['not_readable'],4096)
    def test_signals_not_a_malware_verdict(self):
        p = FakeProcess('00000000-00002000 rwxp 00000000 00:00 0 /memfd:jit (deleted)\n')
        r = engine.scan_turn(p, Scanner(), engine.Progress())
        self.assertEqual(r['signals']['writable_executable_regions'], 1)
        self.assertEqual(r['signals']['memfd_executable_regions'], 1)
        self.assertEqual(r['findings'], [])
    def test_malformed_map_refused(self):
        with self.assertRaises(ValueError):
            parse_maps('00001000-00000000 rw-p 00000000 00:00 0\n')
    def test_controlled_live_child_read(self):
        # Child explicitly supplies one benign buffer; no other processes read.
        import subprocess, sys, json, time
        from pathlib import Path
        from satsuma.ram.proc import Process, maps_hash
        source = "import ctypes,json,sys; b=ctypes.create_string_buffer(b'SAFE_FIXTURE'); print(json.dumps([ctypes.addressof(b),12]),flush=True);sys.stdin.read(1)"
        if not Path('/proc/self').exists():
            self.skipTest('runtime does not expose /proc; live memory validation unavailable')
        with subprocess.Popen([sys.executable, '-c', source], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as child:
            try:
                address, size = json.loads(child.stdout.readline())
                try:
                    with Process(child.pid) as proc:
                        identity, maps = proc.snapshot()
                        data = proc.read(address, size)
                        evidence = {'identity': identity, 'maps_sha256':maps_hash(maps), 'address':address, 'bytes':size,'sha256':hashlib.sha256(data).hexdigest(),'signature':'Fixture'}
                        self.assertTrue(engine.confirm(proc, evidence, Scanner(), time.monotonic()+2))
                        self.assertEqual(data, b'SAFE_FIXTURE')
                except PermissionError:
                    self.skipTest('host policy denies controlled child memory access')
            finally:
                child.stdin.write('x');child.stdin.flush()
                child.wait(timeout=5)
