"""Firewall table watch: a Satsuma table removed while its service runs is put back (2.2.50).

Field 2026-11-19: every Satsuma nftables table was removed by hand; only
"table inet firewalld" was left. The services that build them are one-shot
units ("active (exited)"), so they still looked healthy, self-health restarted
nothing, the DNS filter could no longer reach its resolver and the firewall
filtered nothing. An attacker could switch protection off the same way.

Every minute each table is checked against the service that owns it. A table
is expected only while that service is active, so a service the owner stopped
on purpose is left alone. A missing table restarts its service (which builds
it again under the same boot-time rules: emergency DROP first, then the
policy). At most three repairs of one group in 30 minutes; after that the
watch only reports, so it can never loop. Every repair is recorded as an
action ("Satsuma'nın işlemleri" and Kayıtlar).

Güvenlik duvarı tablo bekçisi: servisi çalışırken silinen Satsuma tablosu
geri kurulur. Tablo yalnızca sahibi olan servis etkinken beklenir; sahibin
bilerek durdurduğu servise dokunulmaz. Bir grup 30 dakikada en çok üç kez
onarılır, sonra yalnızca bildirilir. Her onarım kaydedilir.
"""
import json
import os
import subprocess
import time
from pathlib import Path

STATE = Path('/var/lib/satsuma-core/firewall-watch.json')
WINDOW = 1800
BUDGET = 3
# group: (service that must be active, tables it owns, units restarted to rebuild them)
GROUPS = {
    'network': ('satsuma-network.service', ('satsuma_core', 'satsuma_netblock'), ('satsuma-network.service',)),
    'dns': ('satsuma-dns-netns.service', ('satsuma_dns_ns',), ('satsuma-dns-netns.service', 'satsuma-core-dns.service')),
    'guard': ('satsuma-suricata-otx-guard.service', ('satsuma_otx_guard',), ('satsuma-suricata-otx-guard.service',)),
}
NFT = '/usr/sbin/nft'
SYSTEMCTL = '/usr/bin/systemctl'


def present_tables(runner=subprocess.run):
    result = runner([NFT, '-j', 'list', 'tables'], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError('nft list tables failed: ' + (result.stderr or '')[:200])
    return {row['table'].get('name') for row in json.loads(result.stdout or '{}').get('nftables', [])
            if 'table' in row and row['table'].get('family') == 'inet'}


def active(unit, runner=subprocess.run):
    return runner([SYSTEMCTL, 'is-active', '--quiet', unit], capture_output=True, text=True, timeout=10).returncode == 0


def _history(path):
    try:
        data = json.loads(Path(path).read_text())
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(path.name + '.tmp')
    tmp.write_text(json.dumps(data))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def check(runner=subprocess.run, record=None, state=STATE, clock=time.time):
    """One pass: what is missing, what was repaired, what was only reported."""
    now = clock()
    tables = present_tables(runner)
    history = _history(state)
    report = {'checked_at': now, 'missing': {}, 'repaired': [], 'reported': []}
    for group, (owner, owned, units) in GROUPS.items():
        if not active(owner, runner):
            continue
        missing = [name for name in owned if name not in tables]
        if not missing:
            continue
        report['missing'][group] = missing
        recent = [t for t in history.get(group, []) if now - t < WINDOW]
        if len(recent) >= BUDGET:
            report['reported'].append(group)
            outcome = {'status': 'budget_exhausted'}
        else:
            # The budget is written before acting, so a crash mid-repair still counts.
            history[group] = recent + [now]
            _save(state, history)
            restarted = runner([SYSTEMCTL, 'restart', *units], capture_output=True, text=True, timeout=120)
            after = present_tables(runner)
            back = [name for name in missing if name in after]
            outcome = {'status': 'restored' if len(back) == len(missing) else 'restore_failed',
                       'restored': back, 'returncode': restarted.returncode,
                       'error': (restarted.stderr or '')[:300] if restarted.returncode else ''}
            report['repaired'].append({'group': group, **outcome})
        if record is not None:
            record({'action': 'firewall.restore', 'group': group, 'missing_tables': missing, 'units': list(units),
                    'reason': 'Güvenlik duvarı tablosu servisi çalışırken silinmişti', 'timestamp': now, **outcome})
    return report


def main():
    from .store import Store
    store = Store()
    try:
        report = check(record=lambda row: store.add('actions', row))
        store.set('firewall_watch', report)
    finally:
        store.close()
    print(json.dumps(report))
    return 1 if any(r.get('status') == 'restore_failed' for r in report['repaired']) else 0


if __name__ == '__main__':
    raise SystemExit(main())
