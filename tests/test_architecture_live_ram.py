"""Real clamd + harmless memory fixture + real rule + real child termination.

Gerçek clamd, zararsız bellek örneği, gerçek kural ve geçici çocuk süreç sonlandırması.
"""
import grp
import json
import os
from pathlib import Path
import pwd
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from satsuma.ram.proc import Process
from satsuma.ram.engine import Progress,scan_turn
from satsuma.ram.clamd import Clamd
from satsuma.ram.coordinator import finding_event

ROOT=Path(__file__).resolve().parents[1]
MARKER=b'SATSUMA_ARCHITECTURE_HARMLESS_RAM_FIXTURE_20261103'

@unittest.skipUnless(os.environ.get('SATSUMA_ARCH_LIVE_CLAMD')=='1',
    'Explicit disposable Fedora audit environment required; never run on the user workstation')
class LiveRamResponseTests(unittest.TestCase):
    def test_signature_rule_revalidation_and_pidfd_exit_of_our_own_child(self):
        if os.geteuid()!=0:raise RuntimeError('isolated audit fixture requires root')
        socket_dir=Path('/run/satsuma-ram-clamd')
        if socket_dir.exists():raise RuntimeError('refusing to touch an existing scanner runtime')
        uid=pwd.getpwnam('clamscan').pw_uid;gid=grp.getgrnam('satsuma-core').gr_gid
        socket_dir.mkdir(mode=0o750);os.chown(socket_dir,uid,gid)
        scanner=child=None
        try:
            with tempfile.TemporaryDirectory(prefix='satsuma-architecture-db-',dir='/run') as db_dir, tempfile.TemporaryDirectory() as store_dir:
                db=Path(db_dir);os.chown(db,0,gid);db.chmod(0o750)
                signature=db/'fixture.ndb';signature.write_text('Satsuma.Architecture.Fixture:0:*:'+MARKER.hex()+'\n')
                os.chown(signature,0,gid);signature.chmod(0o640)
                config=db/'clamd.conf';config.write_text('Foreground yes\nDatabaseDirectory '+str(db)+'\nLocalSocket '+str(socket_dir/'clamd.sock')+'\nLocalSocketMode 660\nLocalSocketGroup satsuma-core\nPidFile '+str(socket_dir/'clamd.pid')+'\n')
                os.chown(config,0,gid);config.chmod(0o640)
                with tempfile.TemporaryFile() as daemon_log:
                    scanner=subprocess.Popen([shutil.which('clamd'),'--config-file='+str(config)],
                        stdout=daemon_log,stderr=subprocess.STDOUT,user=uid,group=gid,extra_groups=[pwd.getpwnam('clamscan').pw_gid])
                    deadline=time.monotonic()+15
                    while not (socket_dir/'clamd.sock').exists():
                        if scanner.poll() is not None or time.monotonic()>deadline:
                            daemon_log.seek(0);self.fail(daemon_log.read().decode(errors='replace'))
                        time.sleep(.05)
                    script="import mmap,ctypes,time; b=mmap.mmap(-1,65536,flags=mmap.MAP_PRIVATE|mmap.MAP_ANONYMOUS); b[:%d]=%r; print(ctypes.addressof(ctypes.c_char.from_buffer(b)),flush=True); time.sleep(60) # satsuma-core argument fixture"%(len(MARKER),MARKER)
                    child=subprocess.Popen([sys.executable,'-u','-c',script],stdout=subprocess.PIPE,text=True)
                    self.assertTrue(select.select([child.stdout],[],[],5)[0],'fixture child did not publish its address')
                    address=int(child.stdout.readline().strip())
                    class FixtureProcess(Process):
                        def eligible(self,region):
                            if not region.start<=address<region.end:return False,'outside_controlled_test_region'
                            return super().eligible(region)
                    with FixtureProcess(child.pid) as process:
                        report=scan_turn(process,Clamd(),Progress())
                    self.assertEqual(report['findings'][0]['status'],'REPRODUCED_SIGNATURE',report)
                    report['observed_at']=time.time();event=finding_event(report,report['findings'][0])
                    event_path=Path(store_dir)/'event.json';event_path.write_text(json.dumps(event));event_path.chmod(0o600)
                    service=(ROOT/'systemd/satsuma-teams.service').read_text()
                    groups=[gid] if 'SupplementaryGroups=satsuma-core' in service else []
                    result=subprocess.run([sys.executable,str(ROOT/'tests/architecture_live_client.py'),str(event_path),str(Path(store_dir)/'store')],
                        capture_output=True,text=True,timeout=30,user=0,group=0,extra_groups=groups)
                    self.assertEqual(result.returncode,0,result.stderr)
                    evidence=json.loads(result.stdout)
                    self.assertEqual(evidence['rule'],'SATSUMA-RAM-106')
                    response=evidence['result']
                    self.assertTrue(response['signal_sent'],response)
                    self.assertTrue(response['exit_verified'],response)
                    self.assertIn(child.wait(timeout=5),(-signal.SIGTERM,-signal.SIGKILL))
                    proof={'rule':evidence['rule'],'signal_sent':True,'exit_verified':True,
                        'scanner':'real_clamd_custom_harmless_signature','target':'only_test_created_child',
                        'trust':'explicit_test_fixture','malware_efficacy_test':False}
                    if os.environ.get('SATSUMA_ARCH_EVIDENCE_DIR'):
                        folder=Path(os.environ['SATSUMA_ARCH_EVIDENCE_DIR'])
                        folder.mkdir(parents=True,exist_ok=True)
                        (folder/'live-ram-response.json').write_text(json.dumps(proof,indent=2)+'\n')
                    print('AUDIT_LIVE_RAM_RESULT '+json.dumps(proof))

        finally:
            if child is not None:
                if child.poll() is None:child.terminate()
                child.wait(timeout=5)
                if child.stdout:child.stdout.close()
            if scanner is not None:
                if scanner.poll() is None:scanner.terminate()
                scanner.wait(timeout=10)
            if socket_dir.exists():
                for entry in socket_dir.iterdir():entry.unlink()
                socket_dir.rmdir()
