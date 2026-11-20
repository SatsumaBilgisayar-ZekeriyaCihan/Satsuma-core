"""One restart ledger for every Satsuma watcher (faz 3, without merging units).

self-health, maintenance, flow-guard and firewall-watch each restarted units on their own, so one
could restart a unit another had just restarted. Each now asks here first.

There is no cap (owner 2026-11-20, "ürün zayıflıyor"): a cap of 3 restarts per 30 minutes let
anyone who kills a protection service four times keep it down for half an hour. A unit is always
restarted again; only the gap grows when it keeps falling:

- the first PER_UNIT restarts in WINDOW: at least SETTLE seconds apart (watchers cannot fight);
- after that: 2, 4, 8 minutes ... at most MAX_GAP apart, and the unit is listed under "storms",
  which teams turns into a critical finding (something keeps stopping it).

The claim is written before the restart (a crash mid-repair still counts). The ledger is guarded
by a file lock. The units stay separate: merging them would have given each watcher the others'
privileges.

Yeniden başlatma hiç durmaz; tekrar tekrar düşen birimde yalnız aralık büyür ve kritik bulgu açılır.
"""
import fcntl
import json
import os
import time
from pathlib import Path

LEDGER = Path('/var/lib/satsuma-core/repair-ledger.json')
WINDOW = 1800
PER_UNIT = 3
SETTLE = 60
MAX_GAP = 600


def gap(count):
    """Seconds that must pass since the last restart when ``count`` restarts are in the window."""
    if count < PER_UNIT:
        return SETTLE
    return min(MAX_GAP, SETTLE * 2 ** (count - PER_UNIT + 1))


def _load(ledger):
    try:
        data = json.loads(Path(ledger).read_text())
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def claim(units, actor, now=None, ledger=None):
    """(True, '') when ``actor`` may restart ``units`` now, recording it; else (False, why) - try later."""
    ledger = Path(ledger or LEDGER)
    now = time.time() if now is None else now
    units = [str(u) for u in units]
    if not ledger.parent.is_dir():
        return True, 'no_ledger'
    lock_fd = os.open(str(ledger) + '.lock', os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        data = _load(ledger)
        restarts = data.get('restarts') if isinstance(data.get('restarts'), dict) else {}
        storms = data.get('storms') if isinstance(data.get('storms'), dict) else {}
        for unit in units:
            recent = [e for e in restarts.get(unit, [])
                      if isinstance(e, list) and len(e) == 2 and 0 <= now - e[0] < WINDOW]
            restarts[unit] = recent
            wait = gap(len(recent))
            if recent and now - recent[-1][0] < wait:
                return False, (f'{unit}: {int(now - recent[-1][0])} sn önce {recent[-1][1]} yeniden başlattı; '
                               f'sıradaki deneme {int(wait - (now - recent[-1][0]))} sn sonra')
        for unit in units:
            restarts[unit].append([now, actor])
            if len(restarts[unit]) > PER_UNIT:
                storms[unit] = {'count': len(restarts[unit]), 'last': now, 'actor': actor}
        storms = {u: s for u, s in storms.items() if isinstance(s, dict) and now - float(s.get('last', 0)) < WINDOW}
        tmp = ledger.with_name(ledger.name + '.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as fh:
            json.dump({'restarts': restarts, 'storms': storms}, fh)
        os.replace(tmp, ledger)
        return True, ''
    finally:
        os.close(lock_fd)


def storms(now=None, ledger=None):
    """Units restarted more than PER_UNIT times in WINDOW: {unit: {count, last, actor}}."""
    now = time.time() if now is None else now
    data = _load(ledger or LEDGER).get('storms')
    if not isinstance(data, dict):
        return {}
    return {u: s for u, s in data.items() if isinstance(s, dict) and now - float(s.get('last', 0)) < WINDOW}
