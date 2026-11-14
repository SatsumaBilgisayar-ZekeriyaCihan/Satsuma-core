"""Verify NFQUEUE 100 is held by the expected managed Suricata process.

These checks detect local inconsistencies; they cannot attest a compromised kernel.
"""
import json
import os
import tempfile
from pathlib import Path
import stat
import subprocess
import time

QUEUE_FILE = Path('/proc/net/netfilter/nfnetlink_queue')


def listener_status(proc=Path('/proc'), runner=subprocess.run, binary=Path('/usr/bin/suricata')):
    try:
        queues = [line.split() for line in (proc/'net/netfilter/nfnetlink_queue').read_text().splitlines()]
        row = next((row for row in queues if row and row[0] == '100'), None)
        if row is None:
            return {'ready': False, 'reason': 'queue_100_missing'}
        service = runner(['/usr/bin/systemctl', 'show', '--property=MainPID', '--value',
                          'satsuma-suricata-ips.service'], capture_output=True, text=True, timeout=5, check=True)
        pid = int(service.stdout.strip())
        if pid <= 1:
            raise ValueError('Missing Suricata MainPID')
        process = proc/str(pid)
        if (process/'exe').resolve(strict=True) != binary.resolve(strict=True):
            return {'ready': False, 'reason': 'unexpected_queue_process'}
        info = binary.stat()
        if info.st_uid != 0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
            return {'ready': False, 'reason': 'unsafe_suricata_binary'}
        # Map the NFQUEUE peer port ID to a NETLINK_NETFILTER socket inode.
        sockets = set()
        for line in (proc/'net/netlink').read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 10 and fields[1] == '12' and fields[2] == row[1]:
                sockets.add('socket:['+fields[-1]+']')
        descriptors = {os.readlink(fd) for fd in (process/'fd').iterdir()}
        if not sockets.intersection(descriptors):
            return {'ready': False, 'reason': 'queue_not_owned_by_suricata'}
        return {'ready': True, 'reason': 'managed_suricata_listener', 'pid': pid, 'queue': 100, 'peer_portid': row[1],
                'traffic_drop_verified': False, 'host_cleanliness_verified': False}
    except (OSError, ValueError, IndexError, subprocess.SubprocessError) as exc:
        return {'ready': False, 'reason': 'listener_verification_failed', 'error': str(exc)[:200]}


def listening():
    return listener_status()['ready']


def wait_for_listener(timeout=30, probe=listening, sleep=time.sleep, clock=time.monotonic):
    deadline = clock() + timeout
    while not probe():
        if clock() >= deadline:
            raise RuntimeError('Managed Suricata NFQUEUE 100 listener is not verified; traffic remains fail-closed')
        sleep(.1)


def process_writer_uid(process):
    """Filesystem UID of the verified writer; never inferred from an existing log."""
    for line in (process/'status').read_text().splitlines():
        if line.startswith('Uid:'):
            values=line.split()[1:]
            if len(values)!=4 or not all(value.isdecimal() for value in values):
                break
            return int(values[3])
    raise RuntimeError('Suricata filesystem UID is unavailable')


READY_FILE = Path('/run/satsuma-suricata/ready.json')


def wait_for_eve(path, writer_uid, timeout=10, opener=None, sleep=time.sleep, clock=time.monotonic):
    from .source_guard import open_eve
    opener = opener or open_eve
    deadline = clock() + timeout
    while True:
        try:
            with opener(path, writer_uid):
                return
        except FileNotFoundError as exc:
            if clock() >= deadline:
                raise RuntimeError('Suricata is listening but EVE was not created: ' + str(path)) from exc
            sleep(.1)


def write_ready(path=READY_FILE):
    status = listener_status()
    if not status['ready']:
        raise RuntimeError('Suricata queue identity is not verified')
    status['boot_id'] = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    process = Path('/proc')/str(status['pid'])
    status['start_ticks'] = (process/'stat').read_text().rsplit(')',1)[1].split()[19]
    status['writer_uid'] = process_writer_uid(process)
    # A queue listener alone is insufficient: Core also requires an existing,
    # protected EVE source. Never create or change ownership of a log here.
    from .config import load_with_policy
    config, _, _ = load_with_policy()
    wait_for_eve(config['eve_path'], status['writer_uid'])
    status['eve_path'] = config['eve_path']
    fd, temporary = tempfile.mkstemp(prefix='.ready-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(status,stream);stream.flush();os.fsync(stream.fileno())
        os.chmod(temporary,0o600)
        os.replace(temporary,path)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def read_ready(path=READY_FILE, runner=subprocess.run):
    """Read the privileged startup attestation without granting Core ptrace rights."""
    try:
        fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022 or info.st_nlink!=1:
                raise PermissionError('Unsafe IPS readiness record')
            with os.fdopen(os.dup(fd)) as stream:status=json.load(stream)
        finally:os.close(fd)
        if status.get('ready') is not True or status.get('boot_id') != Path('/proc/sys/kernel/random/boot_id').read_text().strip():
            raise RuntimeError('IPS readiness record is stale')
        current=runner(['/usr/bin/systemctl','show','--property=MainPID','--value','satsuma-suricata-ips.service'],capture_output=True,text=True,timeout=5,check=True)
        pid=int(current.stdout.strip())
        if pid<=1 or pid!=status['pid']:
            raise RuntimeError('IPS process has changed')
        ticks=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()[19]
        if ticks!=status['start_ticks']:
            raise RuntimeError('IPS process identity is stale')
        if status.get('writer_uid') != process_writer_uid(Path('/proc')/str(pid)):
            raise RuntimeError('Suricata writer UID changed or is missing')
        rows=[line.split() for line in QUEUE_FILE.read_text().splitlines()]
        if not any(row and row[0]=='100' and row[1]==status['peer_portid'] for row in rows):
            raise RuntimeError('IPS queue peer has changed')
        return status
    except (OSError,ValueError,KeyError,IndexError,RuntimeError,subprocess.SubprocessError) as exc:
        return {'ready':False,'reason':'ips_readiness_unverified','error':str(exc)[:200]}
