"""Remote peers from the Windows connection table, each tied to its program.

psutil reads the same table as "netstat -ano"; every TCP connection or
connection request (ESTABLISHED, SYN_SENT, SYN_RECV) and every connected UDP
socket is returned with its process id and program name. Only public remote
addresses are returned by default.

Windows bağlantı tablosundan uzak uçlar, her biri programına bağlı. psutil
"netstat -ano" ile aynı tabloyu okur; her TCP bağlantısı ya da bağlantı
isteği ve bağlı her UDP soketi süreç numarası ve program adıyla döner.
Varsayılan olarak yalnızca genel (internet) uzak adresler döner.
"""
import ipaddress

STATES = ('ESTABLISHED', 'SYN_SENT', 'SYN_RECV')


def _plain(text):
    address = ipaddress.ip_address(text)
    return getattr(address, 'ipv4_mapped', None) or address


def read(psutil_module=None, public_only=True):
    psutil = psutil_module
    if psutil is None:
        import psutil
    names, result = {}, []
    for sock in psutil.net_connections(kind='inet'):
        if not sock.raddr:
            continue
        tcp = sock.type == getattr(psutil, 'SOCK_STREAM', 1) or str(sock.type).endswith('SOCK_STREAM')
        if tcp and sock.status not in STATES:
            continue
        try:
            remote, local = _plain(sock.raddr.ip), _plain(sock.laddr.ip)
        except ValueError:
            continue
        if public_only and not remote.is_global:
            continue
        pid = sock.pid
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name() if pid else ''
            except Exception:  # the process ended or is protected
                names[pid] = ''
        result.append({'remote': str(remote), 'remote_port': sock.raddr.port, 'local': str(local),
                       'local_port': sock.laddr.port, 'protocol': 'tcp' if tcp else 'udp',
                       'state': sock.status, 'pid': pid, 'process': names[pid]})
    return result
