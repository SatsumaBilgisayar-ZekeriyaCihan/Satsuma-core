"""Process-wide stop request for the brain cycle.

SIGTERM used to wait for the running cycle to finish, so every stop or
restart of satsuma-teams stayed about 20 seconds in "deactivating" and
self-health reported it unhealthy. The signal handler sets this flag; the
correlation manager checks it before each team, each team before each
worker, and the cycle before correlation and smart rules. Findings already
written are still dispatched, and the smart-rule cursor is left where it
was, so unread events are processed after the restart.

Beyin turu için süreç genelinde durdurma isteği.

SIGTERM eskiden çalışan turun bitmesini bekliyordu; bu yüzden satsuma-teams
her durdurma ya da yeniden başlatmada yaklaşık 20 saniye "deactivating"
kalıyor, self-health de onu sağlıksız bildiriyordu. Sinyal işleyicisi bu
bayrağı kurar; korelasyon yöneticisi her takımdan, her takım her işçiden,
tur da korelasyon ve smart kurallarından önce bakar. Önceden yazılmış
bulgular yine dağıtılır, smart kural imleci olduğu yerde kalır; okunmamış
olaylar yeniden başlatmadan sonra işlenir.
"""
import threading

_STOP = threading.Event()


def request():
    _STOP.set()


def requested():
    return _STOP.is_set()


def clear():
    _STOP.clear()
