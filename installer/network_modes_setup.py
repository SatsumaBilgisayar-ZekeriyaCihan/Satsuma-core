"""Restore selected modes and verify DNS without removing protection on failure.

2.2.44: the DNS lock redirects to Satsuma's dnsmasq filter in its own network
namespace (169.254.53.2:53). The filter is brought up and probed first; only a
working filter gets the lock (an existing lock is never removed on failure).
Then system DNS through the lock is checked and recorded in dns_filter_health.

Seçili ağ kiplerini geri yükle; DNS hatasında mevcut korumayı kaldırma.
2.2.44: DNS kilidi kendi ağ ad alanındaki dnsmasq filtresine yönlendirir. Önce
filtre başlatılıp sınanır; kilit yalnızca çalışan filtreye uygulanır. Ardından
sistem DNS'i kilit üzerinden denetlenir.
"""
import sys
sys.path.insert(0, '/opt/satsuma-core')
from satsuma.store import Store
from satsuma.network_modes import NetworkModes, LAN_TABLE, DNS_TABLE


def record_lock(store, probe=None):
    """System DNS through the lock to the filter in its namespace."""
    import time
    from satsuma.dns_readiness import probe_system
    from satsuma.dns_netns import DNS_ADDR
    result = {'status': 'ACTIVE', 'ok': True, 'local_ready': True,
              'filter': 'dnsmasq ' + DNS_ADDR + ':53 (own network namespace)',
              'updated_at': time.time(), **(probe or probe_system)()}
    previous = store.get('dns_filter_health', {}) or {}
    if 'blocked_count' in previous:
        result['blocked_count'] = previous['blocked_count']
    store.set('dns_filter_health', result)
    return result


def _filter(store):
    from satsuma.dnsmasq_control import refresh
    return refresh(store)


def configure(store, modes=None, probe=None, dns_filter=_filter):
    modes = modes or NetworkModes(store)
    modes.apply(LAN_TABLE, bool((store.get(LAN_TABLE + '_state', {}) or {}).get('enabled')))
    dns = store.get('dns_policy', {}) or {}
    try:
        if dns.get('enabled'):
            # A filter that does not answer gets no new redirect.
            dns_filter(store)
        result = modes.apply(DNS_TABLE, bool(dns.get('enabled')))
        if dns.get('enabled'):record_lock(store, probe)
        return result
    except (OSError, RuntimeError) as exc:
        import time
        # Preserve the selected policy and any existing redirect. Failure is not
        # operator authorization to remove filtering or open an alternate path.
        store.set('dns_filter_health', {'ok':False,'status':'FAILED','system_ready':False,
                  'error':str(exc)[:1000],'updated_at':time.time()})
        raise


def main():
    store = Store()
    try:configure(store)
    finally:store.close()


if __name__ == '__main__':main()
