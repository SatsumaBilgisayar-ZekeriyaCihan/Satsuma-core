"""Watch every remote peer from /proc; block no-PTR peers that open too many connections.

The operator's fixed rules (2026-11-03):
1. Active connections are read from /proc, never from ss. Every remote
   address is tied to the processes that hold its sockets (pid, program,
   start time and the parent program that started it).
2. A process behind a connection is confirmed alive by reading its memory
   (satsuma.memory_validation compares the running code with the file).
3. Alerts are verified against live processes and Satsuma's own DNS records
   (see alert_verify).
4. A peer with no PTR record is tracked. While the peer stays connected it may
   make at most 5 connections; the 6th (a possible port scan) gets it blocked
   without waiting for Suricata or OTX. Connections open now and connections
   that were opened and closed earlier in the same visit all count. A visit
   ends when the peer has had no connection for IDLE_GRACE_SECONDS.

Fail-safe: an unreadable DNS answer (timeout, SERVFAIL) is UNKNOWN, never
"no PTR", so a DNS outage cannot block anyone. Private, loopback, own, DNS
resolver, trusted, allow-listed and remote-support addresses are never
decided here. The PTR query reveals the peer address to the resolver.

Uzak uçların hepsini /proc'tan izler; çok bağlantı açan PTR'siz uçları engeller.

Operatörün değişmez kuralları (2026-11-03):
1. Etkin bağlantılar ss'ten değil /proc'tan okunur. Her uzak adres, soketlerini
   tutan süreçlere (pid, program, başlangıç zamanı ve onu başlatan üst program)
   bağlanır.
2. Bağlantının arkasındaki sürecin canlı olduğu belleği okunarak doğrulanır
   (satsuma.memory_validation çalışan kodu dosyayla karşılaştırır).
3. Uyarılar canlı süreçlere ve Satsuma'nın kendi DNS kayıtlarına karşı
   doğrulanır (bkz. alert_verify).
4. PTR kaydı olmayan uç izlenir. Uç bağlı kaldığı sürece en çok 5 bağlantı
   yapabilir; 6.sı (olası port tarama) Suricata veya OTX beklenmeden engellenir.
   Şu an açık olan bağlantılar ile aynı ziyarette daha önce açılıp kapananların
   hepsi sayılır. Uç IDLE_GRACE_SECONDS boyunca hiç bağlantı yapmazsa ziyaret
   biter.

Güvenli başarısızlık: okunamayan DNS yanıtı (zaman aşımı, SERVFAIL) "PTR yok"
değil BİLİNMİYOR sayılır; DNS kesintisi kimseyi engelleyemez. Özel, geri
döngü, kendi, DNS çözümleyici, güvenilen, izin listesindeki ve uzak destek
adresleri burada asla karara bağlanmaz. PTR sorgusu uç adresi çözümleyiciye
bildirir.
"""
import ipaddress
import os
import socket
import struct
import time

from .procnet import TABLES, parse

THRESHOLD = 5            # a peer may make at most this many connections per visit
IDLE_GRACE_SECONDS = 10.0  # a visit ends after this long without any connection
FLOW_MEMORY_SECONDS = 60.0  # how long a flow's process identity is kept for alert checks
MAX_TRACKED = 1000       # connections remembered per visit (6 already decides)
STATES = ('01', '02', '03')  # ESTABLISHED, SYN_SENT, SYN_RECV: a connection or its request
PTR, NO_PTR, UNKNOWN = 'PTR', 'NO_PTR', 'UNKNOWN'
CACHE_SECONDS = {PTR: 3600.0, NO_PTR: 600.0, UNKNOWN: 30.0}
MEMORY_BYTES = 256 * 1024


def _plain(address):
    return getattr(address, 'ipv4_mapped', None) or address


# --- 1. connections and their processes, from /proc -------------------------

def read_connections(proc='/proc', public_only=True):
    """TCP connections and connection requests as dicts, read from /proc/net."""
    result = []
    for proto, version, path in TABLES:
        if proto != 'tcp':
            continue
        try:
            with open(os.path.join(proc, 'net', os.path.basename(path))) as stream:
                sockets = parse(stream.read(), proto, version)
        except OSError:
            continue
        for sock in sockets:
            if sock['state'] not in STATES or not sock['remote'][1]:
                continue
            remote, local = _plain(sock['remote'][0]), _plain(sock['local'][0])
            if public_only and not remote.is_global:
                continue
            result.append({'remote': str(remote), 'remote_port': sock['remote'][1],
                           'local': str(local), 'local_port': sock['local'][1],
                           'state': sock['state'], 'inode': sock['inode']})
    return result


def listening_ports(proc='/proc'):
    """TCP ports this host is listening on: a flow on one of them is served here, not started here."""
    ports = set()
    for proto, version, path in TABLES:
        if proto != 'tcp':
            continue
        try:
            with open(os.path.join(proc, 'net', os.path.basename(path))) as stream:
                sockets = parse(stream.read(), proto, version)
        except OSError:
            continue
        ports.update(sock['local'][1] for sock in sockets if sock['state'] == '0A')
    return ports


def holders_for(inodes, proc='/proc'):
    """One pass over /proc/*/fd: socket inode -> set of pids holding it."""
    wanted = {f'socket:[{inode}]': inode for inode in inodes if inode}
    found = {}
    if not wanted:
        return found
    try:
        names = [name for name in os.listdir(proc) if name.isdigit()]
    except OSError:
        return found
    for name in names:
        base = os.path.join(proc, name, 'fd')
        try:
            descriptors = os.listdir(base)
        except OSError:
            continue
        for descriptor in descriptors:
            try:
                inode = wanted.get(os.readlink(os.path.join(base, descriptor)))
            except OSError:
                continue
            if inode is not None:
                found.setdefault(inode, set()).add(int(name))
    return found


def _exe(pid, proc):
    try:
        return os.readlink(os.path.join(proc, str(pid), 'exe')).removesuffix(' (deleted)')
    except OSError:
        return None


def process_identity(pid, proc='/proc'):
    """pid, program, start time (jiffies) and the parent program that started it."""
    info = {'pid': pid, 'exe': _exe(pid, proc), 'starttime': None, 'ppid': None, 'parent_exe': None}
    try:
        with open(os.path.join(proc, str(pid), 'stat')) as stream:
            fields = stream.read().rsplit(')', 1)[1].split()
        info['ppid'], info['starttime'] = int(fields[1]), int(fields[19])
        info['parent_exe'] = _exe(info['ppid'], proc)
    except (OSError, ValueError, IndexError):
        pass
    return info


# --- 2. live confirmation from process memory --------------------------------

def verify_live(pid):
    """Read the running process's memory and compare its code with its file.

    live is True when process memory was really read. A busy program can
    change its mappings between the two reads (status UNVERIFIED), but the
    bytes were still read from RAM, so it is live. A changed process identity
    (a reused PID) is never live. code_mismatch reports a verified code
    difference.

    Çalışan sürecin belleğini okur ve kodunu dosyasıyla karşılaştırır. Süreç
    belleği gerçekten okunduysa canlıdır. Yoğun bir program iki okuma arasında
    haritasını değiştirebilir (durum UNVERIFIED) ama baytlar yine RAM'den
    okunmuştur. Değişen süreç kimliği (yeniden kullanılan PID) asla canlı
    değildir. code_mismatch doğrulanmış kod farkını bildirir.
    """
    from .memory_validation import validate_executable
    result = validate_executable(f'/proc/{int(pid)}', byte_limit=MEMORY_BYTES)
    read = result.get('checked_bytes', 0) > 0 and result.get('reason') != 'process_identity_changed'
    return {'pid': pid, 'status': result.get('status'), 'reason': result.get('reason'),
            'checked_bytes': result.get('checked_bytes', 0), 'live': read,
            'code_mismatch': result.get('status') == 'CODE_MISMATCH'}


# --- 4. PTR lookup -----------------------------------------------------------

def _query(name, ident):
    labels = b''.join(bytes([len(part)]) + part.encode('ascii') for part in name.rstrip('.').split('.'))
    return struct.pack('>HHHHHH', ident, 0x0100, 1, 0, 0, 0) + labels + b'\0' + struct.pack('>HH', 12, 1)


def _skip_name(data, offset):
    while True:
        length = data[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        if length == 0:
            return offset + 1
        offset += length + 1


def _classify(data, ident):
    """PTR, NO_PTR or UNKNOWN from one DNS response."""
    if len(data) < 12:
        return UNKNOWN
    rid, flags, questions, answers = struct.unpack('>HHHH', data[:8])
    if rid != ident or not flags & 0x8000 or flags & 0x0200:  # not our answer, or truncated
        return UNKNOWN
    rcode = flags & 0x000F
    if rcode == 3:
        return NO_PTR
    if rcode != 0:
        return UNKNOWN
    try:
        offset = 12
        for _ in range(questions):
            offset = _skip_name(data, offset) + 4
        for _ in range(answers):
            offset = _skip_name(data, offset)
            rtype, _, _, length = struct.unpack('>HHIH', data[offset:offset + 10])
            if rtype == 12:
                return PTR
            offset += 10 + length
    except (IndexError, struct.error):
        return UNKNOWN
    return NO_PTR


class PtrResolver:
    """Ask the configured resolvers for the PTR record; cache by verdict."""

    def __init__(self, servers, timeout=2.0, clock=time.monotonic):
        self.servers, self.timeout, self.clock = servers, timeout, clock
        self.cache = {}

    def lookup(self, ip):
        now = self.clock()
        hit = self.cache.get(ip)
        if hit and now - hit[1] < CACHE_SECONDS[hit[0]]:
            return hit[0]
        state = self._ask(ip)
        self.cache[ip] = (state, now)
        return state

    def _ask(self, ip):
        try:
            name = ipaddress.ip_address(ip).reverse_pointer
        except ValueError:
            return UNKNOWN
        ident = struct.unpack('>H', os.urandom(2))[0]
        for server in self.servers():
            host, port = server if isinstance(server, tuple) else (server, 53)
            try:
                family = socket.AF_INET6 if ':' in host else socket.AF_INET
                with socket.socket(family, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(self.timeout)
                    sock.sendto(_query(name, ident), (host, port))
                    data, _ = sock.recvfrom(4096)
            except (OSError, UnicodeError):
                continue
            state = _classify(data, ident)
            if state != UNKNOWN:
                return state
        return UNKNOWN


# --- tracking and the decision -----------------------------------------------

class PeerTable:
    """Distinct connections per remote address during one visit.

    A visit lasts while the peer has at least one connection, plus
    IDLE_GRACE_SECONDS so a scanner that reconnects right after each close is
    still the same visit.
    """

    def __init__(self, idle=IDLE_GRACE_SECONDS):
        self.idle, self.visits = idle, {}

    def observe(self, connections, now):
        for item in connections:
            key = (item['local'], item['local_port'], item['remote_port'])
            visit = self.visits.setdefault(item['remote'], {'keys': set(), 'last_active': now})
            if len(visit['keys']) < MAX_TRACKED:
                visit['keys'].add(key)
            visit['last_active'] = now
        for ip in [ip for ip, v in self.visits.items() if now - v['last_active'] > self.idle]:
            del self.visits[ip]

    def count(self, ip):
        return len(self.visits.get(ip, {}).get('keys', ()))


class PeerWatch:
    def __init__(self, ptr, eligible, support_ips=lambda: set(), proc='/proc', clock=time.time,
                 verifier=verify_live, max_ptr_per_poll=8, cooldown=300.0):
        self.ptr, self.eligible, self.support_ips = ptr, eligible, support_ips
        self.proc, self.clock, self.verifier = proc, clock, verifier
        self.max_ptr, self.cooldown = max_ptr_per_poll, cooldown
        self.table, self.owners, self.decided = PeerTable(), {}, {}
        self.flows = {}  # (local, lport, remote, rport) -> (seen at, [process identities])

    def flow(self, src_ip, src_port, dst_ip, dst_port):
        """Process identities of a flow seen in the window (either direction); None if unseen."""
        found = self.flow_local(src_ip, src_port, dst_ip, dst_port)
        return None if found is None else found[0]

    def flow_local(self, src_ip, src_port, dst_ip, dst_port):
        """(process identities, local port) of a flow seen in the window; None if unseen."""
        for key in ((src_ip, src_port, dst_ip, dst_port), (dst_ip, dst_port, src_ip, src_port)):
            try:
                key = (str(_plain(ipaddress.ip_address(key[0]))), int(key[1]),
                       str(_plain(ipaddress.ip_address(key[2]))), int(key[3]))
            except (ValueError, TypeError):
                return None
            if key in self.flows:
                return self.flows[key][1], key[1]
        return None

    def watchlist(self):
        """No-PTR peers being tracked: ip -> number of connections in the current visit."""
        return {ip: self.table.count(ip) for ip, (state, _) in self.ptr.cache.items()
                if state == NO_PTR and self.table.count(ip)}

    def poll(self, connections=None):
        """Observe once; return the block decisions that the fixed rule demands."""
        now = self.clock()
        connections = read_connections(self.proc) if connections is None else connections
        support = self.support_ips()
        live = [c for c in connections if c['remote'] not in support]
        self.table.observe(live, now)
        by_peer = {}
        for item in live:
            by_peer.setdefault(item['remote'], []).append(item)
        fresh = {c['inode'] for c in live if c['inode'] and c['inode'] not in self.owners}
        for inode, pids in holders_for(fresh, self.proc).items():
            self.owners[inode] = [process_identity(pid, self.proc) for pid in sorted(pids)]
        for item in live:
            self.flows[(item['local'], item['local_port'], item['remote'], item['remote_port'])] = (
                now, self.owners.get(item['inode'], []))
        for key in [k for k, (seen, _) in self.flows.items() if now - seen > FLOW_MEMORY_SECONDS]:
            del self.flows[key]
        budget, decisions = self.max_ptr, []
        for ip, items in sorted(by_peer.items()):
            try:
                if not self.eligible(ip, items[0]['local']):
                    continue
            except ValueError:
                continue
            if self.table.count(ip) <= THRESHOLD and ip not in self.ptr.cache:
                if budget <= 0:
                    continue
                budget -= 1
            state = self.ptr.lookup(ip)
            if state != NO_PTR or self.table.count(ip) <= THRESHOLD:
                continue
            if now - self.decided.get(ip, -self.cooldown) < self.cooldown:
                continue
            self.decided[ip] = now
            processes = [p for item in items for p in self.owners.get(item['inode'], [])]
            unique = {p['pid']: p for p in processes}.values()
            decisions.append({
                'ip': ip, 'rule': 'no_ptr_connection_flood', 'ptr': state,
                'connections_in_visit': self.table.count(ip), 'threshold': THRESHOLD,
                'connections': [(c['local'], c['local_port'], c['remote_port']) for c in items],
                'processes': list(unique),
                'memory_verification': [self.verifier(p['pid']) for p in unique]})
        open_inodes = {c['inode'] for c in connections}
        for inode in [i for i in self.owners if i not in open_inodes]:
            del self.owners[inode]
        return decisions
