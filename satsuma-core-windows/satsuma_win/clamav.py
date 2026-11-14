"""ClamAV for the memory signature scan (RAM v2 on Windows): installation, database, private clamd.

Installation (Satsuma installs what it needs, owner's rule 2026-11-11): the
official ClamAV 1.5.4 Windows release is downloaded from the ClamAV project's
GitHub releases. Its Windows programs carry no publisher signature, so the
archive must have the SHA-256 pinned here (checked byte for byte against the
official release on 2026-11-11), and every file taken from it must have its
own pinned SHA-256; otherwise nothing is installed and the reason is
reported. Only the files clamd and freshclam need are installed, to
%ProgramFiles%\\Satsuma\\ClamAV; the folder may hold no other program or DLL.
Before every start of clamd the files are checked again.

Database: freshclam downloads it into %ProgramData%\\Satsuma\\clamav\\database
(SYSTEM and Administrators only) and verifies the digital signature of each
database itself; it runs at installation and every four hours.

clamd: started by the service as its own child in a Windows job object (it
dies with the service, at most 2 GiB of memory, as on Linux), listening only
on 127.0.0.1. Before every request the service checks that the other end of
the connection is that child, never trusting the port alone. Any local
program can still connect to 127.0.0.1 and keep clamd busy; the scan then
reports SCANNER_UNAVAILABLE, never a clean result.

Bellek imza taraması için ClamAV (Windows'ta RAM v2): kurulum, veritabanı,
özel clamd. Kurulum (Satsuma gerekeni kendisi kurar, sahibinin kuralı
2026-11-11): resmi ClamAV 1.5.4 Windows sürümü ClamAV projesinin GitHub
sürümlerinden indirilir. Windows programlarında yayıncı imzası yoktur; bu
yüzden arşivin SHA-256'sı burada sabittir (2026-11-11'de resmi sürümle bayt
bayt karşılaştırıldı) ve arşivden alınan her dosyanın da kendi sabit
SHA-256'sı vardır; tutmazsa hiçbir şey kurulmaz, nedeni bildirilir. Yalnızca
clamd ve freshclam'ın gereksindiği dosyalar %ProgramFiles%\\Satsuma\\ClamAV
klasörüne kurulur; klasörde başka program ya da DLL bulunamaz. clamd her
başlatılmadan önce dosyalar yeniden denetlenir. Veritabanı: freshclam onu
%ProgramData%\\Satsuma\\clamav\\database klasörüne (yalnızca SYSTEM ve
Yöneticiler) indirir ve her veritabanının dijital imzasını kendisi doğrular;
kurulumda ve dört saatte bir çalışır. clamd: hizmetin kendi alt süreci olarak
bir Windows iş nesnesinde başlar (hizmetle birlikte kapanır, Linux'taki gibi
en çok 2 GiB bellek), yalnızca 127.0.0.1'i dinler. Her istekten önce
bağlantının öteki ucunun bu alt süreç olduğu denetlenir; yalnızca porta
güvenilmez. Yerel herhangi bir program yine de 127.0.0.1'e bağlanıp clamd'yi
meşgul edebilir; tarama o zaman SCANNER_UNAVAILABLE bildirir, asla temiz
sonuç vermez.
"""
import hashlib
import os
import re
import shutil
import socket
import struct
import subprocess
import time
import urllib.request
import zipfile
from pathlib import Path

VERSION = '1.5.4'
URL = ('https://github.com/Cisco-Talos/clamav/releases/download/clamav-1.5.4/'
       'clamav-1.5.4.win.x64.zip')
ARCHIVE_SHA256 = '0d9e0228b2674137ea1a2853566c98a0278ad52ab2582c3d6dbd75373848c395'
ARCHIVE_TOP = 'clamav-1.5.4.win.x64/'
# The files Satsuma installs from the archive, each with its pinned SHA-256.
# Satsuma'nın arşivden kurduğu dosyalar, her biri sabit SHA-256'sıyla.
FILES = {
    'COPYING.txt': '0c4fd2fa9733fc9122503797648710851e4ee6d9e4969dd33fcbd8c63cd2f584',
    'certs/clamav.crt': '60200e4b4b1b1b7257bb4550487aeb142034341f3300a8526e77a3134a940e9d',
    'clamd.exe': 'd052be9cb42b3798e7a7a65c48a51a4253d8685d7720679b4279007fd6a1aa3f',
    'concrt140.dll': '4f500992a53c41a0ba44a11c33c481d8763505a7453be12d85107856ab8fb332',
    'freshclam.exe': '4032fdd45184333d7c963eec87664a8339c6f31dc5ae94bb5008fe5e88feaf1f',
    'json-c.dll': '08e0518f7e4ef40fd7b90a2846825974cffb2dacec62fa881404c0cc3e7866b8',
    'libbz2.dll': '2838dc37de3174f9c23b4828e037e64975490e377cec79f40a90d1ac01ffda71',
    'libclamav.dll': '5d7e525494e8a5c27282ce015b3444dfe230b982feecf7e477142a45be85b41a',
    'libclammspack.dll': '52ab290affa5f734ddcfbd20723e279fb71a412c3ecd518fe8814990957be5ba',
    'libclamunrar.dll': 'fa35ccd05b9c82c0b000af12716ef3819d67516ddd5e940ed22221d627e3718e',
    'libclamunrar_iface.dll': '032d5eabad191243218830ce05360b8de82f14b3abe0b52179acfff47d291ae3',
    'libcrypto-3-x64.dll': '283a0f725ea2f0187de8a4be49c70eb211f9b759d3174429fb28d2235e9e4e31',
    'libcurl.dll': '07642f8668ff23fe987c33a92ad92d52ad8c7c58e0e2306af6332e38a7433876',
    'libfreshclam.dll': '6cf691eac0473c1392edcc7189ac9075ce76d85de6cb95253b48559744e8e0eb',
    'libssh2.dll': '832813cd782ce2327753e0208e8053391bc0795093045f8c476913ff757fcdd3',
    'libssl-3-x64.dll': 'db1119dcf3d2c85d2031c7413e7f6a4cbd67fb6380ba816b59ec129d1e14b16d',
    'libxml2.dll': '222bee0a9763efba1bd8291d0e1762f70417f0c4fc38bc4f4d4dd546ed866dfd',
    'msvcp140.dll': 'a4c2229bdc2a2a630acdc095b4d86008e5c3e3bc7773174354f3da4f5beb9cde',
    'msvcp140_1.dll': '91cd05c16c61c39788c47434602a59c17f5b08dbb3eee04ce85f8d5b70e8e604',
    'msvcp140_2.dll': '713f17b253d802d283d306ce75647e37d83a546aeb1a881e5d9e529e856c007e',
    'msvcp140_atomic_wait.dll': 'aede4ec454a82f146eb4a721e616e2086870107d88aabc6b0bd1eea0a505d935',
    'msvcp140_codecvt_ids.dll': 'd52d349fbbe6abc61965c07e04cc82d8ee0cea1de7faf90a838964e3f40acedd',
    'nghttp2.dll': '9b408e9346718e52ac09b92ee3e2e277c1d20941071946324cafee5585323893',
    'pcre2-8.dll': 'e5628f9a9f55ecf367db84cb25609ecc7dfa8245b3fc49d05781a2f0ac38280a',
    'pdcurses.dll': 'e114dafaad1895adff84cc6c9d294df34eca4e02c05ce0f62229234cfd6300f8',
    'pthreadVC3.dll': '4eccadb925b73eb08c8041f856be6c3d162f22183e6cb08449c7ef1746d8a17f',
    'vcruntime140.dll': '02c6aa0e6e624411a9f19b0360a7865ab15908e26024510e5c38a9c08362c35a',
    'vcruntime140_1.dll': '7dd9aa02e271c68ca6d5f18d651d23a15d7259715af43326578f7dde27f37637',
}
PORT = 3311
MEMORY_LIMIT = 2 * 1024 ** 3
UPDATE_EVERY = 4 * 3600.0
DAILY = ('daily.cvd', 'daily.cld')
MAIN = ('main.cvd', 'main.cld')
MAX_CHUNK = 4 * 1024 * 1024
CODE_SUFFIXES = ('.exe', '.dll', '.sys', '.com', '.scr', '.cpl', '.ocx')


def engine_dir():
    return Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Satsuma' / 'ClamAV'


def data_dir(state_dir):
    return Path(state_dir) / 'clamav'


def _sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def verify_engine(engine, files=None):
    """What is wrong with the installed engine: missing or changed files, foreign programs. [] when sound."""
    files = FILES if files is None else files
    engine = Path(engine)
    problems = []
    for name, digest in sorted(files.items()):
        path = engine / name
        try:
            if _sha256(path) != digest:
                problems.append('changed:' + name)
        except OSError:
            problems.append('missing:' + name)
    if engine.is_dir():
        listed = {name.lower() for name in files}
        for path in engine.rglob('*'):
            relative = path.relative_to(engine).as_posix().lower()
            if path.is_file() and relative not in listed and relative.endswith(CODE_SUFFIXES):
                problems.append('foreign:' + relative)
    return problems


def download(url, target):
    """Stream ``url`` into ``target``. İndirir; belleğe tümüyle almaz."""
    with urllib.request.urlopen(url, timeout=120) as response, open(target, 'wb') as stream:
        shutil.copyfileobj(response, stream, 1 << 20)


def install_engine(engine, fetch=download, archive_sha256=ARCHIVE_SHA256, files=None, top=ARCHIVE_TOP):
    """Download, verify and install the ClamAV programs; never installs an unverified file."""
    files = FILES if files is None else files
    engine = Path(engine)
    if not verify_engine(engine, files):
        return {'ok': True, 'status': 'PRESENT', 'version': VERSION}
    engine.parent.mkdir(parents=True, exist_ok=True)
    part = engine.parent / 'clamav-download.zip.part'
    staging = engine.parent / 'ClamAV.staging'
    try:
        try:
            fetch(URL, part)
        except OSError as exc:
            return {'ok': False, 'status': 'DOWNLOAD_FAILED', 'error': str(exc)[:300]}
        got = _sha256(part)
        if got != archive_sha256:
            return {'ok': False, 'status': 'ARCHIVE_REJECTED', 'expected': archive_sha256, 'got': got}
        shutil.rmtree(staging, ignore_errors=True)
        try:
            with zipfile.ZipFile(part) as archive:
                for name, digest in files.items():
                    data = archive.read(top + name)
                    if hashlib.sha256(data).hexdigest() != digest:
                        return {'ok': False, 'status': 'FILE_REJECTED', 'file': name}
                    target = staging / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(data)
        except (zipfile.BadZipFile, KeyError) as exc:
            return {'ok': False, 'status': 'ARCHIVE_UNREADABLE', 'error': str(exc)[:300]}
        shutil.rmtree(engine, ignore_errors=True)
        os.replace(staging, engine)
    finally:
        for leftover in (part,):
            try:
                leftover.unlink()
            except OSError:
                pass
        shutil.rmtree(staging, ignore_errors=True)
    problems = verify_engine(engine, files)
    if problems:
        return {'ok': False, 'status': 'VERIFY_FAILED', 'problems': problems[:20]}
    return {'ok': True, 'status': 'INSTALLED', 'version': VERSION}


def _quoted(path):
    text = str(path)
    if any(c in text for c in '"\r\n'):
        raise ValueError('invalid path for a ClamAV configuration: ' + text)
    return '"' + text + '"'


def clamd_config(engine, data, port=PORT):
    data = Path(data)
    return '\n'.join([
        'TCPAddr 127.0.0.1', 'TCPSocket %d' % int(port),
        'DatabaseDirectory ' + _quoted(data / 'database'),
        'TemporaryDirectory ' + _quoted(data / 'scratch'),
        'CVDCertsDirectory ' + _quoted(Path(engine) / 'certs'),
        'LogFile ' + _quoted(data / 'logs' / 'clamd.log'),
        'LogTime yes', 'LogFileMaxSize 10M', 'LogRotate yes', 'Foreground yes',
        'LeaveTemporaryFiles no', 'StreamMaxLength 4M', 'MaxFileSize 16M', 'MaxScanSize 32M',
        'MaxScanTime 1500', 'MaxThreads 2', 'MaxQueue 4', 'ReadTimeout 3', 'CommandReadTimeout 3',
        'ConcurrentDatabaseReload no', 'AlertExceedsMax yes', 'DetectPUA no', 'SelfCheck 600', '',
    ])


def freshclam_config(engine, data):
    data = Path(data)
    return '\n'.join([
        'DatabaseDirectory ' + _quoted(data / 'database'),
        'CVDCertsDirectory ' + _quoted(Path(engine) / 'certs'),
        'UpdateLogFile ' + _quoted(data / 'logs' / 'freshclam.log'),
        'LogTime yes', 'LogFileMaxSize 10M', 'LogRotate yes',
        'DatabaseMirror database.clamav.net', 'ConnectTimeout 60', 'ReceiveTimeout 600', '',
    ])


def prepare(engine, data, port=PORT):
    """Create the data folders and write both configurations (rewritten every time: never trusted as found)."""
    data = Path(data)
    for folder in (data / 'database', data / 'scratch', data / 'logs'):
        folder.mkdir(parents=True, exist_ok=True)
    (data / 'clamd.conf').write_text(clamd_config(engine, data, port), encoding='utf-8')
    (data / 'freshclam.conf').write_text(freshclam_config(engine, data), encoding='utf-8')
    return data / 'clamd.conf', data / 'freshclam.conf'


def database_present(data):
    folder = Path(data) / 'database'
    return (any((folder / name).is_file() for name in DAILY)
            and any((folder / name).is_file() for name in MAIN))


def update_database(engine, data, runner=subprocess.run, timeout=1800):
    """Run freshclam once (it verifies every database's signature itself)."""
    _, config = prepare(engine, data)
    done = runner([str(Path(engine) / 'freshclam.exe'), '--config-file=' + str(config), '--stdout'],
                  cwd=str(engine), capture_output=True, text=True, errors='replace', timeout=timeout,
                  creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    ok = done.returncode == 0 and database_present(data)
    return {'ok': ok, 'status': 'UPDATED' if ok else 'UPDATE_FAILED', 'code': done.returncode,
            **({} if ok else {'output': ((done.stdout or '') + (done.stderr or ''))[-600:]})}


def install(engine, data, fetch=download, runner=subprocess.run):
    """Engine, configuration and database: what --install and the service run."""
    result = install_engine(engine, fetch)
    if not result['ok']:
        return result
    prepare(engine, data)
    if database_present(data):
        return {**result, 'database': 'PRESENT'}
    try:
        database = update_database(engine, data, runner)
    except (OSError, subprocess.SubprocessError) as exc:
        database = {'ok': False, 'status': 'UPDATE_FAILED', 'error': str(exc)[:300]}
    return {**result, 'ok': database['ok'], 'database': database}


def uninstall(engine, data):
    shutil.rmtree(engine, ignore_errors=True)
    shutil.rmtree(data, ignore_errors=True)
    gone = not Path(engine).exists() and not Path(data).exists()
    return {'ok': gone, 'status': 'REMOVED' if gone else 'REMOVE_FAILED'}


# -- clamd connection ---------------------------------------------------------

def parse_reply(reply):
    text = reply.decode('utf-8', 'strict')
    if text == 'stream: OK':
        return {'status': 'NO_MATCH'}
    match = re.fullmatch(r'stream: ([^\x00-\x1f\x7f]{1,256}) FOUND', text)
    if match:
        from satsuma.ram.engine import reply_status
        return {'status': reply_status(match[1]), 'signature': match[1]}
    raise RuntimeError('scanner_error_or_unsupported_reply: ' + text[:200])


def verify_peer(client, child, connections=None):
    """The other end of ``client`` must be ``child`` (matched by its own TCP table, not by port)."""
    if child is None or child.poll() is not None:
        raise PermissionError('scanner_child_not_running')
    if connections is None:
        import psutil
        try:
            connections = psutil.Process(child.pid).net_connections(kind='tcp4')
        except psutil.Error as exc:
            raise PermissionError('scanner_peer_identity_unavailable') from exc
    local, remote = client.getsockname(), client.getpeername()
    if not any(getattr(c, 'status', '') == 'ESTABLISHED' and tuple(c.laddr) == tuple(remote)
               and tuple(c.raddr) == tuple(local) for c in connections):
        raise PermissionError('scanner_peer_pid_mismatch')


class Clamd:
    """INSTREAM to the private clamd; every request has an absolute deadline."""

    def __init__(self, port, child, verifier=verify_peer):
        if type(port) is not int or not 1024 <= port <= 65535:
            raise ValueError('invalid_scanner_port')
        self.port, self.child, self.verifier = port, child, verifier

    def _exchange(self, command, payload, deadline):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
            def budget():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('clamd_deadline')
                client.settimeout(remaining)
            budget()
            client.connect(('127.0.0.1', self.port))
            self.verifier(client, self.child)
            budget()
            client.sendall(command)
            if payload is not None:
                for offset in range(0, len(payload), 65536):
                    chunk = payload[offset:offset + 65536]
                    budget()
                    client.sendall(struct.pack('>I', len(chunk)) + chunk)
                budget()
                client.sendall(b'\0\0\0\0')
            answer = bytearray()
            while b'\0' not in answer:
                budget()
                block = client.recv(1024)
                if not block:
                    raise RuntimeError('scanner_disconnected')
                answer.extend(block)
                if len(answer) > 4096:
                    raise ValueError('scanner_reply_limit')
            return bytes(answer).split(b'\0', 1)[0]

    def ping(self, deadline):
        if self._exchange(b'zPING\0', None, deadline) != b'PONG':
            raise RuntimeError('invalid_scanner_ping')

    def reload(self, deadline):
        if self._exchange(b'zRELOAD\0', None, deadline) != b'RELOADING':
            raise RuntimeError('invalid_scanner_reload')

    def scan(self, payload, deadline):
        if not 0 < len(payload) <= MAX_CHUNK:
            raise ValueError('invalid_payload_size')
        return parse_reply(self._exchange(b'zINSTREAM\0', payload, deadline))


class Runtime:
    """The private clamd: verified start in a job object, readiness, database updates, restart with backoff."""

    LOAD_SECONDS = 300

    def __init__(self, engine, data, port=PORT, installer=None, updater=None, clock=time.monotonic,
                 popen=subprocess.Popen, job_factory=None):
        self.engine, self.data, self.port = Path(engine), Path(data), port
        self.installer = installer or (lambda: install(self.engine, self.data))
        self.updater = updater or (lambda: update_database(self.engine, self.data))
        self.clock, self.popen = clock, popen
        self.job_factory = job_factory or kill_on_close_job
        self.child = self.job = self.scanner = None
        self.state, self.error = 'STARTING', None
        self.started_at = self.retry_at = 0.0
        self.install_at = self.update_at = None
        self.restarts = 0
        self.last_install = self.last_update = None

    def _start(self):
        problems = verify_engine(self.engine)
        if problems:
            raise FileNotFoundError('clamav_engine_not_sound: ' + ','.join(problems[:5]))
        config, _ = prepare(self.engine, self.data, self.port)
        if not database_present(self.data):
            raise FileNotFoundError('clamav_database_missing')
        self.job = self.job_factory()
        self.child = self.popen([str(self.engine / 'clamd.exe'), '--config-file=' + str(config)],
                                cwd=str(self.engine), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
        try:
            if self.job is not None:
                self.job.assign(self.child)
        except BaseException:
            self.close()
            raise
        self.scanner = Clamd(self.port, self.child)
        self.started_at = self.clock()
        self.state = 'LOADING_DATABASE'

    def maintain(self):
        """Install when missing (every ten minutes), update every four hours. Runs in the scan thread."""
        now = self.clock()
        if (verify_engine(self.engine) or not database_present(self.data)) and (
                self.install_at is None or now - self.install_at >= 600):
            self.install_at = now
            self.close()   # a running clamd holds its files; Windows cannot replace them
            try:
                self.last_install = self.installer()
            except Exception as exc:  # recorded in health; tried again in ten minutes
                self.last_install = {'ok': False, 'status': 'ERROR', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
            self.update_at = now
            return self.last_install
        if self.update_at is None:
            self.update_at = now
        if now - self.update_at >= UPDATE_EVERY:
            self.update_at = now
            try:
                self.last_update = self.updater()
            except Exception as exc:  # recorded; the running database stays in use
                self.last_update = {'ok': False, 'status': 'ERROR', 'error': type(exc).__name__ + ': ' + str(exc)[:300]}
            if self.last_update.get('ok') and self.scanner is not None:
                try:
                    self.scanner.reload(self.clock() + 10)
                    self.state, self.started_at = 'LOADING_DATABASE', self.clock()
                except (OSError, RuntimeError, ValueError):
                    self.close()
            return self.last_update
        return None

    def ensure_ready(self):
        now = self.clock()
        if now < self.retry_at:
            return False
        try:
            if self.child is None:
                self._start()
            if self.child.poll() is not None:
                raise RuntimeError('clamd_exited: %s' % self.child.returncode)
            try:
                self.scanner.ping(self.clock() + 2.0)
            except (OSError, RuntimeError, ValueError):
                if self.clock() - self.started_at < self.LOAD_SECONDS:
                    self.state = 'LOADING_DATABASE'
                    return False
                raise
            self.state, self.error = 'READY', None
            return True
        except Exception as exc:  # reported in health; retried with a growing pause
            self.close()
            self.restarts += 1
            self.state = 'UNAVAILABLE'
            self.error = type(exc).__name__ + ': ' + str(exc)[:240]
            self.retry_at = self.clock() + min(60, 2 ** min(self.restarts, 6))
            return False

    def health(self):
        alive = self.child is not None and self.child.poll() is None
        return {'state': self.state, 'error': self.error, 'pid': self.child.pid if alive else None,
                'restarts': self.restarts, 'version': VERSION, 'database': database_present(self.data),
                'last_install': self.last_install, 'last_update': self.last_update}

    def close(self):
        if self.child is not None:
            if self.child.poll() is None:
                self.child.terminate()
                try:
                    self.child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.child.kill()
            self.child = None
        if self.job is not None:
            self.job.close()
            self.job = None
        self.scanner = None


class _Job:
    def __init__(self, handle, win32job, win32api):
        self.handle, self.win32job, self.win32api = handle, win32job, win32api

    def assign(self, child):
        self.win32job.AssignProcessToJobObject(self.handle, int(child._handle))

    def close(self):
        self.win32api.CloseHandle(self.handle)


def kill_on_close_job(memory_limit=MEMORY_LIMIT):
    """A job object: its process dies with the service and may use at most ``memory_limit`` bytes."""
    import win32api
    import win32job
    job = win32job.CreateJobObject(None, '')
    info = win32job.QueryInformationJobObject(job, win32job.JobObjectExtendedLimitInformation)
    info['BasicLimitInformation']['LimitFlags'] |= (win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                                                    | win32job.JOB_OBJECT_LIMIT_PROCESS_MEMORY)
    info['ProcessMemoryLimit'] = memory_limit
    win32job.SetInformationJobObject(job, win32job.JobObjectExtendedLimitInformation, info)
    return _Job(job, win32job, win32api)
