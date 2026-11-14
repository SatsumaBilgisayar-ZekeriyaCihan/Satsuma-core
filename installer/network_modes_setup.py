"""Restore selected modes and verify DNS without removing protection on failure.

Since 2.2.38 the DNS lock sends every query straight to the pinned resolver;
there is no local dnsmasq to probe first. The lock is applied, then system DNS
through it is checked and recorded in dns_filter_health.

Seçili ağ kiplerini geri yükle; DNS hatasında mevcut korumayı kaldırma.
2.2.38'den beri DNS kilidi her sorguyu doğrudan sabit çözümleyiciye gönderir;
önce sınanacak yerel dnsmasq yoktur. Kilit uygulanır, ardından onun üzerinden
sistem DNS'i denetlenir ve dns_filter_health'e yazılır.
"""
import sys
sys.path.insert(0, '/opt/satsuma-core')
from satsuma.store import Store
from satsuma.network_modes import NetworkModes, LAN_TABLE, DNS_TABLE


def record_lock(store, probe=None):
    """System DNS through the lock; no local filter exists any more."""
    import time
    from satsuma.dns_readiness import probe_system
    result = {'status': 'LOCK_ACTIVE', 'ok': True, 'filter': 'none (dnsmasq and HaGeZi retired in 2.2.38)',
              'updated_at': time.time(), **(probe or probe_system)()}
    store.set('dns_filter_health', result)
    return result


def configure(store, modes=None, probe=None):
    modes = modes or NetworkModes(store)
    modes.apply(LAN_TABLE, bool((store.get(LAN_TABLE + '_state', {}) or {}).get('enabled')))
    dns = store.get('dns_policy', {}) or {}
    try:
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
