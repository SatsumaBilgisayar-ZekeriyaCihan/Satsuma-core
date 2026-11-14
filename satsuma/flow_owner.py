"""Find the one live process that owns a network connection.

A Suricata alert names addresses and ports, never a process. Without a
process identity the automatic stop gate (auto_process.respond) has nothing to
act on. This module looks the connection up in /proc/net by its full
4-tuple (both directions of the flow are tried), finds the processes that
hold that socket, and returns pid, start time (jiffies) and executable.

Fail-safe rules: no match, a closed connection, more than one distinct
process sharing the socket, or a process that changed while it was read all
give None. A guess is never returned, so a wrong process is never stopped.
Read only; it never sends a signal.

Ağ bağlantısının sahibi olan tek canlı süreci bulur.

Suricata uyarısı adres ve port bildirir, süreç bildirmez; süreç kimliği
olmadan otomatik durdurma kapısı (auto_process.respond) üzerinde işlem
yapacağı bir şey bulamaz. Bu modül bağlantıyı /proc/net içinde tam 4'lü
(akışın iki yönü de denenir) ile bulur, soketi tutan süreçleri bulur ve
pid, başlangıç zamanı (jiffies) ve çalıştırılabilir dosyayı döndürür.

Güvenli başarısızlık: eşleşme yok, bağlantı kapanmış, soketi birden çok
farklı süreç paylaşıyor ya da süreç okunurken değişmişse sonuç None'dur.
Tahmin asla döndürülmez; yanlış süreç durdurulmaz. Yalnızca okur, sinyal
göndermez.
"""
import ipaddress
import os

from .procnet import TABLES, parse
from .process_identity import read_proc_exe, read_proc_starttime

MAX_PROCESSES = 65536


def _ip(value):
    """Address as an ip_address; IPv4-mapped IPv6 becomes plain IPv4."""
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    mapped = getattr(address, 'ipv4_mapped', None)
    return mapped or address


def _port(value):
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    return number if 0 < number < 65536 else None


def _sockets(proto, proc):
    sockets = []
    for table_proto, version, path in TABLES:
        if table_proto != proto:
            continue
        try:
            with open(os.path.join(proc, 'net', os.path.basename(path))) as stream:
                sockets += parse(stream.read(), table_proto, version)
        except OSError:
            continue
    return sockets


def _holders(inode, proc):
    """Every pid holding the socket inode in an open file descriptor."""
    target = f'socket:[{inode}]'
    pids = set()
    try:
        names = [name for name in os.listdir(proc) if name.isdigit()][:MAX_PROCESSES]
    except OSError:
        return pids
    for name in names:
        base = os.path.join(proc, name, 'fd')
        try:
            descriptors = os.listdir(base)
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                if os.readlink(os.path.join(base, descriptor)) == target:
                    pids.add(int(name))
                    break
            except OSError:
                continue
    return pids


def find_owner(src_ip, src_port, dst_ip, dst_port, proto, proc='/proc'):
    """Identity of the single process owning the connection, or None."""
    proto = str(proto or '').lower()
    if proto not in ('tcp', 'udp'):
        return None
    a, b = (_ip(src_ip), _port(src_port)), (_ip(dst_ip), _port(dst_port))
    if None in (a[0], a[1], b[0], b[1]):
        return None
    inodes = set()
    for sock in _sockets(proto, proc):
        local = (_mapped(sock['local'][0]), sock['local'][1])
        remote = (_mapped(sock['remote'][0]), sock['remote'][1])
        # A TCP/UDP socket matches only when both ends agree: no port-only guess.
        if (local, remote) in ((a, b), (b, a)) and sock['inode']:
            inodes.add(sock['inode'])
    if len(inodes) != 1:
        return None  # not found, or the 4-tuple is not unambiguous
    inode = next(iter(inodes))
    pids = _holders(inode, proc)
    if len(pids) != 1:
        return None  # closed meanwhile, or shared by several processes
    pid = next(iter(pids))
    start = read_proc_starttime(pid)
    exe = read_proc_exe(pid)
    if start is None or not exe:
        return None
    # The process must be the same one after the identity was read.
    if read_proc_starttime(pid) != start or pid not in _holders(inode, proc):
        return None
    return {'pid': pid, 'starttime': start, 'exe': exe}


def _mapped(address):
    return getattr(address, 'ipv4_mapped', None) or address
