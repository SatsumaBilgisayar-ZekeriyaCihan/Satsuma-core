"""Domain name checks; the HaGeZi list download is retired.

Since 2.2.38 (owner, 2026-11-13) no domain list is downloaded: a list someone
can change steers what this machine may resolve, the MITM Satsuma guards
against. update() records that and fetches nothing; since 2.2.44 no list address is
left in the product. domain() and parse() stay
for the names Satsuma still checks.

Alan adı denetimleri; HaGeZi listesi indirme kaldırıldı. 2.2.38'den beri
(sahibi, 2026-11-13) hiçbir alan adı listesi indirilmez: başkasının
değiştirebildiği bir liste bu makinenin neyi çözebileceğini yönlendirir.
update() bunu kaydeder ve hiçbir şey indirmez.
"""
import re
import time

def domain(value):
    if not isinstance(value, str):
        raise ValueError("Invalid domain")
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    labels = value.split(".")
    if len(value) > 253 or len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in labels):
        raise ValueError("Invalid domain")
    return value





def parse(text):
    names = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '!')):
            continue
        try:
            name = domain(line)
        except ValueError:
            raise ValueError('Invalid domain list entry') from None
        if '.' not in name or name.endswith(('.local', '.lan', '.home.arpa', '.arpa')):
            continue
        names.add(name)
    if not names:
        raise ValueError('Empty domain list')
    return sorted(names)


RETIRED = 'retired_in_2.2.38'


def update(store, *args, state_key='hagezi_list', **kwargs):
    """Nothing is downloaded (2.2.38; the address was removed in 2.2.44). Hiçbir şey indirilmez."""
    info = {'status': RETIRED, 'source': None, 'count': 0, 'updated_at': time.time()}
    store.set(state_key, info)
    return info
