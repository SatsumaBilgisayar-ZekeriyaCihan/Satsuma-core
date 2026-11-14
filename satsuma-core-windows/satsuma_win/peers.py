"""The owner's fixed rule on Windows: a peer with no PTR record is blocked at its 6th connection.

Shared with the Linux product (satsuma.peer_watch): the PTR lookup
(PtrResolver: an unreadable DNS answer is UNKNOWN, never "no PTR", so a DNS
outage blocks nobody), the per-visit connection counter (PeerTable) and the
threshold (THRESHOLD = 5: the 6th connection decides). CDNs are not
exempted; the rule is the owner's fixed rule. Protected addresses (gateway,
DNS servers, remote support) are never decided.

Sahibinin sabit kuralı Windows'ta: PTR kaydı olmayan uç 6. bağlantısında
engellenir. PTR sorgusu, ziyaret başına bağlantı sayacı ve eşik Linux
ürünüyle ortaktır (satsuma.peer_watch); okunamayan DNS yanıtı "PTR yok"
değil BİLİNMİYOR sayılır, DNS kesintisi kimseyi engellemez. CDN'ler muaf
tutulmaz; kural sahibinin sabit kuralıdır. Korunan adresler (ağ geçidi, DNS
sunucuları, uzak destek) asla karara bağlanmaz.
"""
import time

from satsuma.peer_watch import NO_PTR, THRESHOLD, PeerTable, PtrResolver

from .dns import SERVERS


class PeerRule:
    def __init__(self, protected, resolver=None, clock=time.time, max_ptr_per_poll=8, cooldown=300.0):
        self.protected = protected          # ip -> reason or None
        self.ptr = resolver or PtrResolver(lambda: list(SERVERS))
        self.clock, self.max_ptr, self.cooldown = clock, max_ptr_per_poll, cooldown
        self.table, self.decided = PeerTable(), {}

    def poll(self, connections):
        """Observe the connections once; return the blocks the fixed rule demands."""
        now = self.clock()
        live = [dict(c, inode=None) for c in connections if c.get('protocol', 'tcp') == 'tcp']
        self.table.observe(live, now)
        by_peer = {}
        for item in live:
            by_peer.setdefault(item['remote'], []).append(item)
        budget, decisions = self.max_ptr, []
        for ip, items in sorted(by_peer.items()):
            if self.protected(ip):
                continue
            count = self.table.count(ip)
            if count <= THRESHOLD and ip not in self.ptr.cache:
                if budget <= 0:
                    continue
                budget -= 1
            state = self.ptr.lookup(ip)
            if state != NO_PTR or count <= THRESHOLD:
                continue
            if now - self.decided.get(ip, -self.cooldown) < self.cooldown:
                continue
            self.decided[ip] = now
            decisions.append({'ip': ip, 'rule': 'no_ptr_connection_flood', 'ptr': state,
                              'connections_in_visit': count, 'threshold': THRESHOLD,
                              'processes': sorted({(c['pid'], c['process']) for c in items})})
        return decisions
