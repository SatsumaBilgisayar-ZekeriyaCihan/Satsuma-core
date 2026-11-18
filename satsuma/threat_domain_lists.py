"""Downloaded malware/ransomware domain feeds: retired.

2.2.44 (owner's decision 2026-11-13): the product downloads no list by itself
and carries no list address. The two downloaded feeds of 2.2.37 and their
bundled snapshots are gone. Blocked names come from Satsuma's own findings and
from lists the user adds (satsuma.custom_dns_lists).

İndirilen zararlı yazılım/fidye yazılımı alan adı listeleri kaldırıldı; ürün
kendiliğinden liste indirmez ve liste adresi taşımaz.
"""
FEEDS = {}
REFRESH_SECONDS = 8 * 3600


def blocked_domains(store, *args, **kwargs):
    return set()
