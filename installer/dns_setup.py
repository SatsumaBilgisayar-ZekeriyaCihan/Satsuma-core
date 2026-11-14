"""Configure Satsuma's DNS filter; OpenDNS is the default upstream.

2.2.15 (user decision 2026-10-26): a new installation starts with OpenDNS
(208.67.222.222, with 208.67.220.220 beside it). An upstream the operator
chose is kept. existing_resolver() remains for the operator's own choice.

Satsuma DNS filtresini yapılandırır; varsayılan üst sunucu OpenDNS'tir.
Yeni kurulum OpenDNS ile başlar; operatörün seçtiği üst sunucu korunur.
"""
import ipaddress
from pathlib import Path
import sys
sys.path.insert(0,'/opt/satsuma-core')


def existing_resolver(paths=(Path('/run/NetworkManager/no-stub-resolv.conf'),Path('/etc/resolv.conf'))):
    for path in paths:
        try:lines=path.read_text().splitlines()
        except FileNotFoundError:continue
        for line in lines:
            fields=line.split('#',1)[0].split()
            if len(fields)!=2 or fields[0]!='nameserver':continue
            try:address=ipaddress.ip_address(fields[1])
            except ValueError:continue
            if not (address.is_loopback or address.is_unspecified or address.is_multicast):return str(address)
    raise RuntimeError('No usable existing upstream resolver; DNS setup is incomplete')


def opendns():
    from satsuma.dnsmasq_control import OPENDNS
    return OPENDNS[0]


def opensnitch_rule():
    from satsuma.opensnitch import ensure_dns_rule
    ensure_dns_rule()


def configure(store,resolver=opendns,refresh=None,rule=opensnitch_rule):
    if refresh is None:
        from satsuma.dnsmasq_control import refresh
    # The DNS filter's OpenSnitch allow rule must exist before dnsmasq is probed
    # (2.2.36); failing to write it never stops DNS setup.
    # DNS filtresinin OpenSnitch izin kuralı dnsmasq sınanmadan önce var olmalı
    # (2.2.36); yazılamaması DNS kurulumunu durdurmaz.
    try:rule()
    except Exception:pass
    policy=store.get('dns_policy',{}) or {}
    policy.setdefault('threat_lists_enabled',True)
    # Preserve an explicit operator decision, including a deliberate disable.
    if 'enabled' not in policy:
        policy={**policy,'enabled':True,'upstream':policy.get('upstream') or resolver()}
    store.set('dns_policy',policy)
    if policy.get('enabled'):return refresh(store)
    return {'status':'DISABLED_BY_OPERATOR'}


def main():
    from satsuma.store import Store
    store=Store()
    try:configure(store)
    except Exception as exc:
        import time
        store.set('dns_filter_health',{'status':'FAILED','error':str(exc)[:1000],'updated_at':time.time()})
        raise
    finally:store.close()


if __name__=='__main__':main()
