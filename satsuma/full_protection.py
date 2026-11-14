"""Full protection: every Satsuma function is on and acts, from the product itself.

The user's decision (2026-10-26): the product runs with 100% of its functions
active, without locks, installer switches or extra conditions. This module is
the single place that turns them on. It is applied to every configuration the
product loads, so an older policy file or an installer that wrote "off" can no
longer leave protection disabled. Switching a function off stays possible only
from the dashboard (those choices live in the store and still win).

What blocking still never touches, because hitting it would cut the user off
rather than an attacker: loopback, multicast and unspecified addresses, this
machine's own default gateway (the modem) and the DNS servers it uses.

Tam koruma: Satsuma'nın bütün işlevleri ürünün kendisi tarafından açılır ve
çalışır.

Kullanıcının kararı (2026-10-26): ürün işlevlerinin %100'ü etkin, kilitsiz,
kurulum anahtarına ya da ek koşula bağlı olmadan çalışır. Bu modül hepsini
açan tek yerdir. Ürünün yüklediği her yapılandırmaya uygulanır; eski bir
policy dosyası ya da "kapalı" yazan bir kurulum betiği korumayı artık kapalı
bırakamaz. Bir işlevi kapatmak yalnızca panelden mümkündür (bu seçimler
depoda tutulur ve geçerli kalır).

Engellemenin yine dokunmadığı yerler, çünkü bunları engellemek saldırganı
değil kullanıcıyı keser: loopback, multicast ve belirsiz adresler, bu
makinenin kendi varsayılan ağ geçidi (modem) ve kullandığı DNS sunucuları.
"""
import ipaddress
from pathlib import Path

from .action_contract import DESTRUCTIVE_ACTIONS

FULL_PROTECTION = {
    'response_enabled': True,
    'destructive_response_enabled': True,
    'auto_action_network_enabled': True,
    'auto_action_process_enabled': True,
    'otx_enabled': True,
    'otx_blocker_mode': True,
    'sudo_autoblock_enabled': True,
    'rule_adapter_enabled': True,
    'deepseek_enabled': True,
}


def apply(config):
    """Return ``config`` with every function switched on."""
    allowed = list(config.get('destructive_allowed_actions') or [])
    for action in sorted(DESTRUCTIVE_ACTIONS):
        if action not in allowed:
            allowed.append(action)
    result = {**config, **FULL_PROTECTION, 'destructive_allowed_actions': allowed}
    if isinstance(config.get('scheduled_scans'), dict):
        result['scheduled_scans'] = {**config['scheduled_scans'], 'enabled': True, 'automatic_quarantine': True}
    return result


def _gateways(route_path='/proc/net/route', route6_path='/proc/net/ipv6_route'):
    found = set()
    try:
        for line in Path(route_path).read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) > 2 and parts[1] == '00000000' and parts[2] != '00000000':
                found.add(str(ipaddress.IPv4Address(bytes.fromhex(parts[2])[::-1])))
    except (OSError, ValueError):
        pass
    try:
        for line in Path(route6_path).read_text().splitlines():
            parts = line.split()
            if len(parts) > 4 and parts[0] == '0' * 32 and parts[1] == '00' and parts[4] != '0' * 32:
                found.add(str(ipaddress.IPv6Address(bytes.fromhex(parts[4]))))
    except (OSError, ValueError):
        pass
    return found


def _resolvers(paths=('/etc/resolv.conf', '/run/systemd/resolve/resolv.conf')):
    found = set()
    for path in paths:
        try:
            for line in Path(path).read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == 'nameserver':
                    try:
                        found.add(str(ipaddress.ip_address(parts[1].split('%')[0])))
                    except ValueError:
                        continue
        except OSError:
            continue
    return found


def protected_local_targets():
    """Addresses whose block would cut this machine off: gateway and DNS."""
    return _gateways() | _resolvers()


def protected_reason(addr, protected=None):
    """Why ``addr`` must not be blocked automatically, or None."""
    addr = ipaddress.ip_address(addr)
    if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
        return 'protected_target'
    if str(addr) in (protected_local_targets() if protected is None else protected):
        return 'protected_gateway_or_dns'
    return None
