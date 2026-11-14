"""Satsuma Core for Windows 11: network and interception protection first.

The fixed rules of the Linux product (subnet limit, no-PTR peer blocked at its
6th connection, port 853 closed, DNS locked) are applied with Windows
Firewall, the Windows connection table and the Windows DNS client. The PTR
lookup and the per-visit connection counter are shared with the Linux
product (satsuma.peer_watch), so the two cannot drift apart.

Windows 11 için Satsuma Core: önce ağ ve araya girme koruması. Linux
ürününün sabit kuralları (alt ağ sınırı, PTR'siz uç 6. bağlantıda engellenir,
853 kapalı, DNS kilitli) Windows Güvenlik Duvarı, Windows bağlantı tablosu ve
Windows DNS istemcisiyle uygulanır. PTR sorgusu ve ziyaret başına bağlantı
sayacı Linux ürünüyle ortaktır (satsuma.peer_watch); iki ürün birbirinden
kopamaz.
"""
__version__ = '0.1.0'
