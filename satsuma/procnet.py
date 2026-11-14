"""Read sockets from /proc/net and find the programs that own them.

Taken from the yeni-yazim branch (satsuma/common/procnet.py and the
listener part of privd/attribution.py). Read only. Naming another user's
socket owner needs root (CAP_SYS_PTRACE); without it the owner is None.

/proc/net içindeki soketleri okur ve sahibi olan programları bulur.
yeni-yazim dalından alındı (common/procnet.py ve privd/attribution.py'nin
dinleyici bölümü). Salt okunur. Başka kullanıcının soket sahibini
görebilmek için root gerekir; yoksa sahip None olur.
"""
import ipaddress
import os
import struct

TCP_LISTEN = '0A'
TABLES = (('tcp', 4, '/proc/net/tcp'), ('tcp', 6, '/proc/net/tcp6'),
          ('udp', 4, '/proc/net/udp'), ('udp', 6, '/proc/net/udp6'))
SUSPICIOUS_PREFIXES = ('/tmp/', '/var/tmp/', '/dev/shm/', '/home/', '/run/user/', 'memfd:')


def _address(text, version):
    host, port = text.split(':')
    raw = bytes.fromhex(host)
    # The kernel prints each 32-bit word in host (little-endian) order.
    words = struct.unpack('<' + 'I' * (len(raw) // 4), raw)
    packed = struct.pack('>' + 'I' * len(words), *words)
    if version != (4 if len(packed) == 4 else 6):
        raise ValueError('address family mismatch')
    return ipaddress.ip_address(packed), int(port, 16)


def parse(text, proto, version):
    sockets = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 10:
            continue
        try:
            local, remote = _address(fields[1], version), _address(fields[2], version)
            sockets.append({'proto': proto, 'local': local, 'remote': remote, 'state': fields[3],
                            'uid': int(fields[7]), 'inode': int(fields[9])})
        except ValueError:
            continue
    return sockets


def read_all(tables=TABLES):
    sockets = []
    for proto, version, path in tables:
        try:
            with open(path) as stream:
                sockets += parse(stream.read(), proto, version)
        except OSError:
            pass  # e.g. IPv6 disabled
    return sockets


def owners(inodes, proc='/proc', max_processes=65536):
    """Map socket inodes to {pid, exe, comm, uid} by scanning /proc/<pid>/fd."""
    wanted = {f'socket:[{inode}]': inode for inode in inodes if inode}
    found = {}
    try:
        pids = [name for name in os.listdir(proc) if name.isdigit()][:max_processes]
    except OSError:
        return found
    for pid in pids:
        if len(found) == len(wanted):
            break
        base = os.path.join(proc, pid)
        try:
            links = os.listdir(os.path.join(base, 'fd'))
        except OSError:
            continue
        for fd in links:
            try:
                target = os.readlink(os.path.join(base, 'fd', fd))
            except OSError:
                continue
            inode = wanted.get(target)
            if inode is None or inode in found:
                continue
            found[inode] = _process(base, int(pid))
    return found


def _process(base, pid):
    info = {'pid': pid, 'exe': None, 'comm': None, 'uid': None}
    try:
        info['exe'] = os.readlink(os.path.join(base, 'exe'))
    except OSError:
        pass
    try:
        with open(os.path.join(base, 'comm')) as stream:
            info['comm'] = stream.read(64).strip()
        info['uid'] = os.stat(base).st_uid
    except OSError:
        pass
    return info


def exposed_listeners(read=read_all, owner_lookup=owners):
    """Sockets that accept traffic from other machines: TCP listening and
    unconnected UDP on any address other than loopback."""
    def wanted(sock):
        if sock['local'][0].is_loopback:
            return False
        if sock['proto'] == 'tcp':
            return sock['state'] == TCP_LISTEN
        return sock['remote'][1] == 0  # a connected UDP socket is a client
    listening = [sock for sock in read() if wanted(sock)]
    identities = owner_lookup({sock['inode'] for sock in listening})
    result = []
    for sock in listening:
        process = identities.get(sock['inode'])
        exe = (process or {}).get('exe') or ''
        result.append({'proto': sock['proto'], 'address': str(sock['local'][0]), 'port': sock['local'][1],
                       'uid': sock['uid'], 'process': process,
                       'suspicious': exe.startswith(SUSPICIOUS_PREFIXES) or exe.endswith(' (deleted)')})
    return sorted(result, key=lambda item: (item['proto'], item['address'], item['port']))
