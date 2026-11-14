"""Subnet limit on Windows: ten distinct connected peers in one /24 get blocked.

The same rule as the Linux product (satsuma.subnet_protection): peers seen in
the last 300 seconds count, so a sequence of short connections is counted as
well as simultaneous ones; the threshold never goes below 10. Protected
addresses are never blocked and a blocked address is not retried for 300
seconds.

Windows'ta alt ağ sınırı: aynı /24 içinde bağlı on farklı uç engellenir.
Linux ürünüyle aynı kural: son 300 saniyede görülen uçlar sayılır, böylece
art arda kısa bağlantılar da eşzamanlılar gibi sayılır; eşik 10'un altına
inmez. Korunan adresler asla engellenmez; engellenen adres 300 saniye
yeniden denenmez.
"""
import ipaddress
import time

THRESHOLD = 10
WINDOW_SECONDS = 300.0


class SubnetRule:
    def __init__(self, protected, threshold=THRESHOLD, clock=time.time):
        if threshold < THRESHOLD:
            raise ValueError('Subnet threshold cannot be below 10')
        self.protected, self.threshold, self.clock = protected, threshold, clock
        self.recent, self.decided = {}, {}

    def poll(self, connections):
        now = self.clock()
        for item in connections:
            self.recent[item['remote']] = now
        self.recent = {ip: seen for ip, seen in self.recent.items() if now - seen < WINDOW_SECONDS}
        groups = {}
        for ip in self.recent:
            address = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(f'{address}/{24 if address.version == 4 else 64}', strict=False)
            groups.setdefault(str(network), []).append(ip)
        decisions = []
        for network, ips in sorted(groups.items()):
            if len(ips) < self.threshold:
                continue
            for ip in sorted(ips):
                if self.protected(ip) or now - self.decided.get(ip, -WINDOW_SECONDS) < WINDOW_SECONDS:
                    continue
                self.decided[ip] = now
                decisions.append({'ip': ip, 'rule': 'subnet_distinct_ip_limit', 'subnet': network,
                                  'ip_count': len(ips), 'threshold': self.threshold})
        return decisions
