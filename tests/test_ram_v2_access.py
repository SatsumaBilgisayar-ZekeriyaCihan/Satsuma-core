"""Socket trust and installation access regressions / Soket güveni ve kurulum erişim testleri."""
import grp
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from satsuma.ram.clamd import Clamd
from satsuma import hash_blacklist
from installer.ram_scanner_setup import ensure_label, PATTERN

class AccessTests(unittest.TestCase):
    def test_trusted_group_socket_and_peer_are_required(self):
        scanner=Clamd('/run/satsuma-ram-clamd/clamd.sock')
        def info(path):
            if str(path).endswith('.sock'):return SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=100,st_gid=200)
            return SimpleNamespace(st_mode=stat.S_IFDIR|0o750,st_uid=0,st_gid=0)
        connection=Mock();connection.__enter__=Mock(return_value=connection);connection.__exit__=Mock(return_value=False)
        import struct
        connection.getsockopt.return_value=struct.pack('3i',123,100,200)
        connection.recv.return_value=b'stream: OK\0'
        with patch('satsuma.ram.clamd.Path.lstat',autospec=True,side_effect=info),patch('satsuma.ram.clamd.pwd.getpwnam',return_value=SimpleNamespace(pw_uid=100)),patch('satsuma.ram.clamd.grp.getgrnam',return_value=SimpleNamespace(gr_gid=200)),patch('satsuma.ram.clamd.socket.socket',return_value=connection),patch('satsuma.ram.clamd.peer_unit',side_effect=lambda pid,root:'satsuma-ram-clamd.service' if pid==123 else 'clamd@scan.service'):
            self.assertEqual(scanner.scan(b'fixture',time.monotonic()+2)['status'],'NO_MATCH')
            connection.connect.assert_called_once()
            connection.getsockopt.return_value=struct.pack('3i',123,999,200)
            with self.assertRaises(PermissionError):scanner.scan(b'fixture',time.monotonic()+2)
            # Same user, another unit (Fedora's system clamd runs as clamscan too).
            connection.getsockopt.return_value=struct.pack('3i',124,100,200)
            with self.assertRaisesRegex(PermissionError,'untrusted_scanner_unit'):scanner.scan(b'fixture',time.monotonic()+2)
    def test_owner_only_socket_is_rejected_not_silently_bypassed(self):
        def info(path):
            return SimpleNamespace(st_mode=(stat.S_IFSOCK|0o600) if str(path).endswith('.sock') else (stat.S_IFDIR|0o750),st_uid=100,st_gid=200)
        with patch('satsuma.ram.clamd.Path.lstat',autospec=True,side_effect=info),patch('satsuma.ram.clamd.pwd.getpwnam',return_value=SimpleNamespace(pw_uid=100)),patch('satsuma.ram.clamd.grp.getgrnam',return_value=SimpleNamespace(gr_gid=200)):
            with self.assertRaises(PermissionError):Clamd().scan(b'fixture',time.monotonic()+2)
    def test_blacklist_survives_restrictive_umask_and_repairs_unchanged_file(self):
        table={'a'*64:(1,'Fixture')}
        with tempfile.TemporaryDirectory() as d,patch('satsuma.hash_blacklist.grp.getgrnam',return_value=SimpleNamespace(gr_gid=os.getegid())):
            old=os.umask(0o077)
            try:hash_blacklist.install(table,Path(d))
            finally:os.umask(old)
            target=Path(d)/hash_blacklist.HSB_NAME
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o640)
            target.chmod(0o600)
            self.assertEqual(hash_blacklist.install(table,Path(d))['status'],'ACCESS_REPAIRED')
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o640)
    def test_blacklist_rejects_symlink_and_hardlink(self):
        table={'a'*64:(1,'Fixture')}
        with tempfile.TemporaryDirectory() as d,patch('satsuma.hash_blacklist.grp.getgrnam',return_value=SimpleNamespace(gr_gid=os.getegid())):
            p=Path(d);(p/'other').write_text('unchanged');target=p/hash_blacklist.HSB_NAME;target.symlink_to(p/'other')
            with self.assertRaises(OSError):hash_blacklist.install(table,p)
            target.unlink();os.link(p/'other',target)
            with self.assertRaises(PermissionError):hash_blacklist.install(table,p)
            self.assertEqual((p/'other').read_text(),'unchanged')
    def test_runtime_label_registration_is_narrow_and_idempotent(self):
        runner=Mock(return_value=SimpleNamespace(stdout=''))
        r=ensure_label(runner,lambda x:'/usr/sbin/semanage',True)
        self.assertEqual(r['status'],'LABEL_REGISTERED')
        self.assertEqual(runner.call_args.args[0][-1],PATTERN)
        runner=Mock(return_value=SimpleNamespace(stdout=PATTERN+' all files system_u:object_r:antivirus_var_run_t:s0\n'))
        self.assertEqual(ensure_label(runner,lambda x:'/usr/sbin/semanage',True)['status'],'EXISTING_LABEL_PRESERVED');self.assertEqual(runner.call_count,1)
    def test_conflicting_label_preserved_and_refused(self):
        runner=Mock(return_value=SimpleNamespace(stdout=PATTERN+' all files system_u:object_r:var_run_t:s0\n'))
        with self.assertRaises(RuntimeError):ensure_label(runner,lambda x:'/usr/sbin/semanage',True)
        self.assertEqual(runner.call_count,1)
    def test_packaged_identity_settings_agree(self):
        root=Path(__file__).resolve().parents[1]
        for service in ['satsuma-core.service','satsuma-privd.service','satsuma-teams.service']:
            text=(root/'systemd'/service).read_text();self.assertIn('SupplementaryGroups=satsuma-core',text)
        config=(root/'packaging/root/etc/clamd.d/satsuma-ram.conf').read_text()
        self.assertIn('LocalSocketMode 660',config);self.assertIn('LocalSocketGroup satsuma-core',config)
        text=(root/'systemd/satsuma-ram-clamd.service').read_text()
        self.assertIn('Group=satsuma-core',text);self.assertIn('RuntimeDirectoryMode=0750',text)

class RealUnixSocketTests(unittest.TestCase):
    def test_client_without_capabilities_uses_only_named_group(self):
        # Disposable fixture server, not a real ClamAV efficacy test.
        if os.geteuid()!=0 or not Path('/run').is_dir() or not hasattr(os,'fork'):
            self.skipTest('requires isolated Linux root test runner with /run')
        import ctypes,pwd,socket,struct
        uid=pwd.getpwnam('nobody').pw_uid
        directory=Path(tempfile.mkdtemp(prefix='satsuma-socket-test-',dir='/run'))
        directory.chmod(0o750);os.chown(directory,uid,0)
        path=directory/'scanner.sock';read_ready,write_ready=os.pipe()
        server=os.fork()
        if server==0:
            os.close(read_ready)
            try:
                os.setgroups([]);os.setgid(0);os.setuid(uid)
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
                    listener.settimeout(5);listener.bind(str(path));path.chmod(0o660);listener.listen(1)
                    os.write(write_ready,b'1');os.close(write_ready)
                    connection,_=listener.accept()
                    with connection:
                        connection.settimeout(5)
                        def recv(n):
                            result=b''
                            while len(result)<n:
                                part=connection.recv(n-len(result))
                                if not part:raise RuntimeError('fixture short read')
                                result+=part
                            return result
                        if recv(10)!=b'zINSTREAM\0':raise RuntimeError('fixture protocol')
                        size=struct.unpack('>I',recv(4))[0]
                        if recv(size)!=b'fixture':raise RuntimeError('fixture data')
                        if recv(4)!=b'\0'*4:raise RuntimeError('fixture termination')
                        connection.sendall(b'stream: OK\0')
                os._exit(0)
            except BaseException:
                try:os.write(write_ready,b'0')
                except OSError:pass
                os._exit(1)
        os.close(write_ready)
        try:
            ready=os.read(read_ready,1);self.assertEqual(ready,b'1')
            result_read,result_write=os.pipe();client=os.fork()
            if client==0:
                os.close(result_read)
                try:
                    os.setgid(pwd.getpwnam('nobody').pw_gid)
                    os.setgroups([0])
                    class Header(ctypes.Structure):_fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
                    class Caps(ctypes.Structure):_fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
                    libc=ctypes.CDLL(None,use_errno=True);header=Header(0x20080522,0);caps=(Caps*2)()
                    if libc.capset(ctypes.byref(header),ctypes.byref(caps))!=0:raise OSError(ctypes.get_errno(),'capset fixture')
                    from satsuma.ram.clamd import peer_unit
                    result=Clamd(path,account='nobody',client_group='root',unit=peer_unit(os.getpid())).scan(b'fixture',time.monotonic()+3)
                    os.write(result_write,b'1' if result['status']=='NO_MATCH' else b'0');os._exit(0)
                except BaseException:
                    os.write(result_write,b'0');os._exit(1)
            os.close(result_write)
            try:self.assertEqual(os.read(result_read,1),b'1')
            finally:os.close(result_read);_,status=os.waitpid(client,0);self.assertEqual(os.waitstatus_to_exitcode(status),0)
        finally:
            os.close(read_ready);_,status=os.waitpid(server,0)
            path.unlink(missing_ok=True);directory.rmdir()
        self.assertEqual(os.waitstatus_to_exitcode(status),0)
