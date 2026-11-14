"""Read-only gateway/ARP integrity monitor for multiple WAN interfaces.

The first observation is saved and kept across restarts: a restart, or a
boot with an attacker already in the middle, no longer becomes the new
normal. The user-approved modem check lives in network_identity; this
monitor adds per-interface history.

A gateway MAC that is no longer visible (the neighbour entry expired or the
link went down) is reported as "gateway_mac_unobserved", not as a MAC change:
an empty observation proves nothing about the modem's address. A MAC seen
for the first time against an empty baseline is "gateway_mac_first_observed".

Birden çok WAN arayüzü için salt okunur ağ geçidi/ARP bütünlük izleyicisi.

İlk gözlem kaydedilir ve yeniden başlatmalarda korunur: bir yeniden başlatma
ya da saldırganın zaten arada olduğu bir açılış artık yeni "normal" olmaz.
Kullanıcının onayladığı modem denetimi network_identity'dedir; bu izleyici
arayüz başına geçmiş ekler.

Artık görünmeyen ağ geçidi MAC'i (komşu kaydının süresi doldu ya da bağlantı
koptu) MAC değişikliği olarak değil "gateway_mac_unobserved" olarak bildirilir:
boş bir gözlem modemin adresi hakkında hiçbir şey kanıtlamaz. Boş bir temel
kayda karşı ilk kez görülen MAC "gateway_mac_first_observed" olur.
"""
from dataclasses import dataclass, asdict
import json
import subprocess
import time

KINDS = {'gateway':'gateway_ip_changed','gateway_mac':'gateway_mac_changed',
         'gateway_mac_unobserved':'gateway_mac_unobserved',
         'gateway_mac_first_observed':'gateway_mac_first_observed','dhcp_server':'dhcp_server_changed',
         'route_metric':'route_metric_changed'}

@dataclass
class Profile:
    interface: str
    gateway: str
    gateway_mac: str
    dhcp_server: str = ''
    route_metric: int | None = None

def _json(command):
    p = subprocess.run(command, capture_output=True, text=True, timeout=5, check=True)
    return json.loads(p.stdout or '[]')

def snapshot():
    routes = _json(['ip','-j','route','show','default'])
    neigh = _json(['ip','-j','neigh','show'])
    result = {}
    for route in routes:
        dev, gateway = route.get('dev'), route.get('gateway')
        if not dev or not gateway: continue
        found = [n for n in neigh if n.get('dev') == dev and n.get('dst') == gateway]
        result[dev] = Profile(dev, gateway, found[0].get('lladdr','') if found else '', route_metric=route.get('metric'))
    return result

class Guard:
    def __init__(self, profiles=None):
        self.profiles, self.last = profiles or {}, {}
    def enroll(self, current=None):
        current = current if current is not None else snapshot()
        if not self.profiles:
            self.profiles = current; self.last = {k: asdict(v) for k,v in current.items()}; return []
        return self.check(current)
    def check(self, current=None):
        current = current if current is not None else snapshot(); events=[]
        for interface in sorted(set(self.profiles)|set(current)):
            expected, actual = self.profiles.get(interface), current.get(interface)
            if expected is None: events.append(self._event(interface,'new_wan',None,actual)); continue
            if actual is None: events.append(self._event(interface,'wan_missing',expected,None)); continue
            changes={}
            for key in ('gateway','gateway_mac','dhcp_server','route_metric'):
                old,new=getattr(expected,key),getattr(actual,key)
                if old != new: changes[key]={'previous':old,'current':new}
            if 'gateway_mac' in changes and 'gateway' not in changes:
                if not actual.gateway_mac: changes['gateway_mac_unobserved']=changes.pop('gateway_mac')
                elif not expected.gateway_mac: changes['gateway_mac_first_observed']=changes.pop('gateway_mac')
            if changes:
                events.append({'type':'gateway_integrity_change','interface':interface,'changes':changes,
                               'change_kinds':sorted(KINDS[key] for key in changes),
                               'severity':self._severity(changes),'automatic_action':'none','timestamp':time.time()})
        self.last={k:asdict(v) for k,v in current.items()}; return events
    @staticmethod
    def _severity(changes):
        return 'critical' if {'gateway','gateway_mac'} <= set(changes) else ('high' if {'gateway','gateway_mac'} & set(changes) else 'review')
    @staticmethod
    def _event(interface,kind,old,new):
        return {'type':kind,'interface':interface,'previous':asdict(old) if old else None,'current':asdict(new) if new else None,'severity':'high','automatic_action':'none','timestamp':time.time()}

def load_profiles(path):
    """Saved baseline, or None when there is none or it cannot be trusted as data."""
    try:
        with open(path, encoding='utf-8') as h: raw=json.load(h)
        return {name: Profile(**{k: value[k] for k in ('interface','gateway','gateway_mac','dhcp_server','route_metric') if k in value})
                for name, value in raw.items()}
    except (OSError, ValueError, TypeError, AttributeError):
        return None

def save_profiles(path, profiles):
    with open(path,'w',encoding='utf-8') as h: json.dump({k:asdict(v) for k,v in profiles.items()},h,indent=2,sort_keys=True)
