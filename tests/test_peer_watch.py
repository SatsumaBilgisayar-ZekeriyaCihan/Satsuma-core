"""Fixed operator rules: /proc connections, PID per peer, live memory read, no-PTR flood block.

Real UDP DNS server on loopback, real sockets, real process memory reads.

Değişmez operatör kuralları: /proc bağlantıları, uç başına PID, canlı bellek
okuma, PTR'siz bağlantı seli engeli. Geri döngüde gerçek UDP DNS sunucusu,
gerçek soketler, gerçek süreç belleği okuması.
"""
import os
import socket
import struct
import subprocess
import sys
import threading

from satsuma import peer_watch as pw


class FakeDNS:
    """Answers every PTR query with the configured behaviour."""
    def __init__(self, mode):
        self.mode, self.sock, self.queries = mode, socket.socket(socket.AF_INET, socket.SOCK_DGRAM), 0
        self.sock.bind(('127.0.0.1', 0))
        self.sock.settimeout(0.3)
        self.port, self.running = self.sock.getsockname()[1], True
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(512)
            except OSError:
                continue
            self.queries += 1
            if self.mode == 'silent':
                continue
            ident = data[:2]
            question = data[12:]
            rcode = {'nxdomain': 3, 'servfail': 2}.get(self.mode, 0)
            answers = 1 if self.mode == 'ptr' else 0
            head = ident + struct.pack('>HHHHH', 0x8180 | rcode, 1, answers, 0, 0)
            body = b''
            if answers:
                target = b'\x04host\x07example\x03com\x00'
                body = b'\xc0\x0c' + struct.pack('>HHIH', 12, 1, 60, len(target)) + target
            self.sock.sendto(head + question + body, addr)

    def close(self):
        self.running = False
        self.thread.join(timeout=2)
        self.sock.close()


def resolver(dns, timeout=1.0):
    return pw.PtrResolver(lambda: [('127.0.0.1', dns.port)], timeout=timeout)


def test_ptr_states_come_from_real_dns_answers():
    for mode, expected in (('ptr', pw.PTR), ('nxdomain', pw.NO_PTR), ('empty', pw.NO_PTR),
                           ('servfail', pw.UNKNOWN), ('silent', pw.UNKNOWN)):
        dns = FakeDNS(mode)
        try:
            assert resolver(dns, timeout=0.5).lookup('203.0.113.9') == expected, mode
        finally:
            dns.close()


def test_answers_are_cached_by_verdict():
    dns = FakeDNS('nxdomain')
    try:
        r = resolver(dns)
        r.lookup('203.0.113.9'), r.lookup('203.0.113.9')
        assert dns.queries == 1
    finally:
        dns.close()


def test_read_connections_uses_proc_and_finds_its_holder_with_parent():
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(2)
    port = listener.getsockname()[1]
    client = socket.create_connection(('127.0.0.1', port))
    try:
        mine = [c for c in pw.read_connections(public_only=False) if c['remote_port'] == port]
        assert len(mine) == 1 and mine[0]['state'] == '01'
        owners = pw.holders_for({mine[0]['inode']})
        assert owners == {mine[0]['inode']: {os.getpid()}}
        identity = pw.process_identity(os.getpid())
        assert identity['exe'] and identity['starttime'] and identity['ppid'] == os.getppid()
        assert identity['parent_exe'] is not None or os.getppid() == 0
        # Loopback is never a public peer.
        assert not [c for c in pw.read_connections() if c['remote_port'] == port]
    finally:
        client.close()
        listener.close()


def test_live_check_reads_real_memory_or_says_why_not():
    child = subprocess.Popen([sys.executable, '-c', 'import time;print(1,flush=True);time.sleep(30)'],
                             stdout=subprocess.PIPE)
    try:
        child.stdout.readline()  # the child is running its own program now
        result = pw.verify_live(child.pid)
        assert result['pid'] == child.pid
        assert result['live'] == (result['checked_bytes'] > 0 and result['reason'] != 'process_identity_changed')
        if result['status'] != 'ACCESS_DENIED' and os.geteuid() == 0:
            assert result['live'] is True and result['checked_bytes'] > 0
    finally:
        child.kill()
        child.wait(timeout=5)
    assert pw.verify_live(2 ** 22 + 12345)['live'] is False


def row(ip, n):
    return {'remote': ip, 'local': '10.0.0.2', 'local_port': 40000 + n, 'remote_port': 443}


def test_connections_count_for_as_long_as_the_peer_stays_connected():
    table = pw.PeerTable()
    # One long-lived connection stays open for 10 minutes; short ones come and go.
    for i in range(5):
        table.observe([row('203.0.113.9', 0), row('203.0.113.9', i + 1)], now=i * 120)
    # Every earlier connection is still part of the same visit: 6 distinct ones.
    assert table.count('203.0.113.9') == 6


def test_back_to_back_reconnects_are_one_visit_and_a_long_gap_ends_it():
    table = pw.PeerTable(idle=10)
    for i in range(4):
        table.observe([row('203.0.113.9', i)], now=100 + i * 2)  # each closes before the next opens
    assert table.count('203.0.113.9') == 4
    table.observe([], now=115)           # 9 s since the last connection: still the visit
    assert table.count('203.0.113.9') == 4
    table.observe([], now=117)           # more than 10 s with nothing: the visit is over
    assert table.count('203.0.113.9') == 0
    table.observe([row('203.0.113.9', 9)], now=130)
    assert table.count('203.0.113.9') == 1  # a new visit starts from one


def test_the_sixth_connection_of_a_visit_is_the_trigger_not_the_fifth():
    dns = FakeDNS('nxdomain')
    try:
        w = watch(dns)
        five = [conn('203.0.113.9', n) for n in range(5)]
        assert w.poll(five) == []
        decisions = w.poll(five + [conn('203.0.113.9', 5)])
        assert len(decisions) == 1 and decisions[0]['connections_in_visit'] == 6
    finally:
        dns.close()


def conn(ip, n, inode=0):
    return {'remote': ip, 'remote_port': 443, 'local': '10.0.0.2', 'local_port': 40000 + n,
            'state': '01', 'inode': inode}


def watch(dns, **kw):
    clock = kw.pop('clock', None)
    args = dict(ptr=resolver(dns), eligible=lambda ip, local: True,
                verifier=lambda pid: {'pid': pid, 'live': True})
    if clock:
        args['clock'] = clock
    args.update(kw)
    return pw.PeerWatch(**args)


def test_no_ptr_peer_over_five_connections_is_blocked_with_its_processes():
    dns = FakeDNS('nxdomain')
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen(8)
    client = socket.create_connection(('127.0.0.1', listener.getsockname()[1]))
    try:
        inode = [c for c in pw.read_connections(public_only=False)
                 if c['remote_port'] == listener.getsockname()[1]][0]['inode']
        decisions = watch(dns).poll([conn('203.0.113.9', n, inode if n == 0 else 0) for n in range(6)])
        assert len(decisions) == 1
        d = decisions[0]
        assert d['ip'] == '203.0.113.9' and d['rule'] == 'no_ptr_connection_flood'
        assert d['connections_in_visit'] == 6 and len(d['connections']) == 6
        assert [p['pid'] for p in d['processes']] == [os.getpid()]
        assert d['memory_verification'] == [{'pid': os.getpid(), 'live': True}]
    finally:
        client.close()
        listener.close()
        dns.close()


def test_exactly_five_connections_or_a_ptr_record_never_blocks():
    for mode, count in (('nxdomain', 5), ('ptr', 20), ('servfail', 20), ('silent', 20)):
        dns = FakeDNS(mode)
        try:
            w = watch(dns)
            w.ptr.timeout = 0.3
            assert w.poll([conn('203.0.113.9', n) for n in range(count)]) == [], mode
        finally:
            dns.close()


def test_consecutive_connections_over_time_trigger_once_then_cool_down():
    dns = FakeDNS('nxdomain')
    try:
        now = [1000.0]
        w = watch(dns, clock=lambda: now[0])
        results = []
        for n in range(8):
            now[0] += 2
            results.append(w.poll([conn('203.0.113.9', n)]))  # one connection per poll, then it closes
        assert [len(r) for r in results] == [0, 0, 0, 0, 0, 1, 0, 0]
        assert w.watchlist() == {'203.0.113.9': 8}
    finally:
        dns.close()


def test_protected_peers_are_not_decided_and_not_even_queried():
    dns = FakeDNS('nxdomain')
    try:
        w = watch(dns, eligible=lambda ip, local: ip != '203.0.113.9',
                  support_ips=lambda: {'198.51.100.7'})
        batch = [conn('203.0.113.9', n) for n in range(8)] + [conn('198.51.100.7', n) for n in range(8)]
        assert w.poll(batch) == []
        assert dns.queries == 0
    finally:
        dns.close()


def test_new_ptr_lookups_per_poll_are_limited():
    dns = FakeDNS('ptr')
    try:
        w = watch(dns, max_ptr_per_poll=3)
        w.poll([conn(f'203.0.113.{n}', 0) for n in range(10, 20)])
        assert dns.queries == 3
    finally:
        dns.close()
