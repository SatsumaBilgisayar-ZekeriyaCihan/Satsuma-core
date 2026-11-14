"""Windows device guard: devices the owner does not allow are disabled at once (owner's decision 2026-11-11).

Every minute the device list (Win32_PnPEntity: instance id, class, name,
driver service, state) is read, together with the network adapters that
carry a default route (the internet connection). The shared decision
(satsuma.device_policy) names the devices that are not allowed: virtual
machine devices, WWAN, PPPoE, VPN and IPsec adapters, smart card readers,
wireless transmitters and Bluetooth devices. Each one that is enabled is
disabled with Disable-PnpDevice and read back; every finding and every
result is recorded. A device the owner approved with the administrator
password (signed with the machine key) stays enabled; the internet adapter
and the devices Windows needs to start are never disabled, only recorded.
Uninstall enables again exactly the devices Satsuma disabled.

Windows aygıt bekçisi: sahibinin izin vermediği aygıtlar hemen kapatılır
(sahibinin kararı 2026-11-11). Dakikada bir aygıt listesi ve varsayılan
rotayı taşıyan ağ bağdaştırıcıları okunur. Ortak karar izin verilmeyen
aygıtları adlandırır: sanal makine aygıtları, WWAN, PPPoE, VPN ve IPsec
bağdaştırıcıları, akıllı kart okuyucuları, kablosuz aktarıcılar ve
Bluetooth aygıtları. Açık olan her biri Disable-PnpDevice ile kapatılır ve
geri okunur; her bulgu ve sonuç kaydedilir. Sahibinin yönetici parolasıyla
onayladığı aygıt (makine anahtarıyla imzalı) açık kalır; internet
bağdaştırıcısı ve Windows'un açılmak için gerektirdiği aygıtlar asla
kapatılmaz, yalnızca kaydedilir. Kaldırma, yalnızca Satsuma'nın kapattığı
aygıtları yeniden açar.
"""
import json
import subprocess
from pathlib import Path

from satsuma import device_policy

from .firewall import FirewallError, run_powershell, safe_run

APPROVED = 'approved-devices.json'
DISABLED_BY_SATSUMA = 'disabled-devices.json'
DISABLED_CODE = 22

READ_SCRIPT = (
    "$d = @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.Present } | ForEach-Object { "
    "@{id=[string]$_.DeviceID; class=[string]$_.PNPClass; name=[string]$_.Name; service=[string]$_.Service; "
    "code=[int]$_.ConfigManagerErrorCode} }); "
    "$n = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
    "ForEach-Object { (Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue).PnPDeviceID } "
    "| Where-Object { $_ } | Select-Object -Unique); "
    "@{devices=$d; internet=@($n)} | ConvertTo-Json -Compress -Depth 4")


def _quote(text):
    return "'" + str(text).replace("'", "''") + "'"


def disable_script(device_id):
    if '\n' in device_id or '\r' in device_id or not device_id:
        raise ValueError('invalid device id')
    # Some USB devices refuse Disable-PnpDevice ("Generic failure", owner's machine 2026-11-11);
    # pnputil is tried next, and exit code 3010 means the device is disabled at the next restart.
    # Bazı USB aygıtlar reddeder; sonra pnputil denenir, 3010 yeniden başlatınca kapanır demektir.
    return (f"$how = 'Disable-PnpDevice'; $exit = 0; "
            f"try {{ Disable-PnpDevice -InstanceId {_quote(device_id)} -Confirm:$false -ErrorAction Stop }} "
            f"catch {{ $how = 'pnputil'; & pnputil.exe /disable-device {_quote(device_id)} | Out-Null; "
            "$exit = $LASTEXITCODE }; "
            f"$e = Get-CimInstance Win32_PnPEntity | Where-Object {{ $_.DeviceID -eq {_quote(device_id)} }}; "
            "@{code=[int]$e.ConfigManagerErrorCode; how=$how; exit=[int]$exit} | ConvertTo-Json -Compress")


def _text(device_id):
    return ('satsuma-approved-device:' + device_id.upper()).encode('utf-8')


def approve_device(directory, device_id, key):
    path = Path(directory) / APPROVED
    try:
        rows = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        rows = []
    rows = [r for r in rows if isinstance(r, dict) and str(r.get('id', '')).upper() != device_id.upper()]
    rows.append({'id': device_id, 'signature': key.sign(_text(device_id))})
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(rows), encoding='utf-8')
    temporary.replace(path)
    return device_id


def load_approved(directory, key):
    if key is None:
        return frozenset()
    try:
        rows = json.loads((Path(directory) / APPROVED).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return frozenset()
    return frozenset(str(r['id']) for r in rows if isinstance(r, dict) and r.get('id')
                     and key.verify(_text(str(r['id'])), r.get('signature', '')))


def enable_script(device_id):
    if '\n' in device_id or '\r' in device_id or not device_id:
        raise ValueError('invalid device id')
    return f"Enable-PnpDevice -InstanceId {_quote(device_id)} -Confirm:$false -ErrorAction SilentlyContinue"


def restore(directory, runner=safe_run):
    """At uninstall: enable again exactly the devices Satsuma disabled."""
    path = Path(directory) / DISABLED_BY_SATSUMA
    try:
        ids = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {'ok': True, 'status': 'NOTHING_DISABLED'}
    for device_id in ids:
        run_powershell(enable_script(str(device_id)), runner, timeout=120)
    path.unlink()
    return {'ok': True, 'status': 'ENABLED_AGAIN', 'devices': ids}


class Devices:
    def __init__(self, directory, key, runner=safe_run, record=None):
        self.directory, self.key, self.runner = Path(directory), key, runner
        self.record = record or (lambda kind, **f: f)
        self.reported, self.pending_restart = set(), set()
        self.counts = {'disabled': 0, 'disable_failed': 0, 'kept': 0}

    def remember(self, device_id):
        path = self.directory / DISABLED_BY_SATSUMA
        try:
            ids = json.loads(path.read_text(encoding='utf-8'))
        except (OSError, ValueError):
            ids = []
        if device_id not in ids:
            ids.append(device_id)
            path.write_text(json.dumps(ids), encoding='utf-8')

    def read(self):
        state = json.loads(run_powershell(READ_SCRIPT, self.runner, timeout=120) or '{}')
        devices = state.get('devices') or []
        internet = state.get('internet') or []
        return (devices if isinstance(devices, list) else [devices],
                frozenset(internet if isinstance(internet, list) else [internet]))

    def check(self):
        devices, internet = self.read()
        approved = load_approved(self.directory, self.key)
        events = []
        for device in devices:
            decision = device_policy.decide(device, approved, internet)
            if decision is None:
                continue
            if not decision['disable']:
                key = (decision['id'], decision.get('kept'))
                if key not in self.reported:
                    self.reported.add(key)
                    self.counts['kept'] += 1
                    events.append(self.record('device_not_allowed_kept', **decision, cls=device.get('class')))
                continue
            if device.get('code') == DISABLED_CODE or decision['id'] in self.pending_restart:
                continue
            try:
                result = json.loads(run_powershell(disable_script(decision['id']), self.runner, timeout=120) or '{}')
                ok = result.get('code') == DISABLED_CODE or result.get('exit') == 3010
            except (FirewallError, ValueError, OSError) as exc:
                ok, result = False, {'error': str(exc)[:300]}
            self.counts['disabled' if ok else 'disable_failed'] += 1
            if ok:
                self.remember(decision['id'])
            kind = 'device_disable_failed'
            if ok:
                kind = 'device_disabled' if result.get('code') == DISABLED_CODE else 'device_disabled_after_restart'
                self.pending_restart.add(decision['id'])
            events.append(self.record(kind, **decision, cls=device.get('class'), detail=result))
        return events
