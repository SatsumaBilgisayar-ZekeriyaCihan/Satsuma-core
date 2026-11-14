"""Windows MITM guard: the approved modem is pinned; routes, DNS and proxy are written back (owner's decision 2026-11-11).

At the first start (during installation) the default gateway and its MAC
address are approved and signed with the machine key; a later change needs
the panel and the administrator password. Every two seconds the default
routes ("route print") and the neighbour table ("arp -a") are read; numbers
and addresses only, so a Turkish Windows reads the same. Every ten seconds
the DNS servers and the proxy settings (WinHTTP and every loaded user's
Internet settings, including automatic configuration scripts) are read.
The shared decision (satsuma.gateway_decision) says what is wrong; this
module writes it back:

* the approved gateway MAC as a permanent neighbour entry (ARP spoofing has
  no effect on a permanent entry),
* extra default routes deleted, the approved one restored,
* the DNS lock (satsuma_win.dns) applied again,
* proxies and automatic configuration scripts removed.

Every finding and every write-back, successful or not, is recorded.

Windows MITM bekçisi: onaylı modem sabitlenir; rota, DNS ve proxy geri
yazılır (sahibinin kararı 2026-11-11). İlk açılışta (kurulum sırasında)
varsayılan ağ geçidi ve MAC adresi onaylanır ve makine anahtarıyla
imzalanır; sonraki değişiklik panel ve yönetici parolası ister. İki saniyede
bir varsayılan rotalar ve komşu tablosu okunur (yalnızca sayılar ve
adresler; Türkçe Windows da aynı okunur). On saniyede bir DNS sunucuları ve
proxy ayarları (WinHTTP ve yüklü her kullanıcının İnternet ayarları,
otomatik yapılandırma betikleri dahil) okunur. Neyin yanlış olduğunu ortak
karar söyler; bu modül geri yazar: onaylı MAC kalıcı komşu kaydı olarak
(ARP sahteciliği kalıcı kayda işlemez), fazla varsayılan rotalar silinir ve
onaylı olan geri konur, DNS kilidi yeniden uygulanır, proxy ve otomatik
yapılandırma betikleri kaldırılır. Her bulgu ve her geri yazma, başarılı
olsun olmasın, kaydedilir.
"""
import ipaddress
import json
import re
import subprocess
from pathlib import Path

from satsuma import gateway_decision

from . import dns
from .firewall import FirewallError, run_powershell, safe_run

APPROVED = 'approved-gateway.json'
ROUTE_LINE = re.compile(r'^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s*$')
ARP_LINE = re.compile(r'^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2})\b')
SLOW_EVERY = 10.0

SETTINGS_SCRIPT = (
    "$p = @(); "
    "$w = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Connections' "
    "-Name WinHttpSettings -ErrorAction SilentlyContinue).WinHttpSettings; "
    "if ($w -and $w.Length -gt 8 -and ($w[8] -band 6)) { $p += 'winhttp' }; "
    "Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[0-9-]+$' } | ForEach-Object { "
    "$k = Get-ItemProperty -Path ($_.PSPath + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings') "
    "-ErrorAction SilentlyContinue; "
    "if ($k.ProxyEnable -eq 1) { $p += ('user:' + $_.PSChildName + ':' + [string]$k.ProxyServer) }; "
    "if ($k.AutoConfigURL) { $p += ('pac:' + $_.PSChildName + ':' + [string]$k.AutoConfigURL) } }; "
    "$d = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | "
    "ForEach-Object { $_.ServerAddresses }); "
    "@{proxies=@($p); dns=@($d | Select-Object -Unique)} | ConvertTo-Json -Compress")

REMOVE_PROXY_SCRIPT = (
    "& netsh.exe winhttp reset proxy | Out-Null; "
    "Get-ChildItem Registry::HKEY_USERS | Where-Object { $_.PSChildName -match '^S-1-5-21-[0-9-]+$' } | ForEach-Object { "
    "$path = $_.PSPath + '\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'; "
    "if (Test-Path $path) { Set-ItemProperty -Path $path -Name ProxyEnable -Value 0 -Type DWord; "
    "Remove-ItemProperty -Path $path -Name AutoConfigURL -ErrorAction SilentlyContinue } }; " + SETTINGS_SCRIPT)


def parse_routes(text):
    return [{'ip': m.group(1), 'interface': m.group(2), 'metric': int(m.group(3))}
            for m in (ROUTE_LINE.match(line) for line in text.splitlines()) if m]


def parse_neighbours(text):
    return {m.group(1): gateway_decision.mac(m.group(2))
            for m in (ARP_LINE.match(line) for line in text.splitlines()) if m}


def pin_script(gateway, mac, interface_ip):
    gateway, interface_ip = str(ipaddress.IPv4Address(gateway)), str(ipaddress.IPv4Address(interface_ip))
    mac = gateway_decision.mac(mac)
    if mac is None:
        raise ValueError('invalid MAC address')
    return (f"$i = (Get-NetIPAddress -IPAddress '{interface_ip}' -ErrorAction Stop).InterfaceIndex; "
            f"Remove-NetNeighbor -InterfaceIndex $i -IPAddress '{gateway}' -Confirm:$false -ErrorAction SilentlyContinue; "
            f"New-NetNeighbor -InterfaceIndex $i -IPAddress '{gateway}' -LinkLayerAddress '{mac}' -State Permanent "
            "| Out-Null; "
            f"$n = Get-NetNeighbor -InterfaceIndex $i -IPAddress '{gateway}'; "
            "@{state=[string]$n.State; mac=[string]$n.LinkLayerAddress} | ConvertTo-Json -Compress")


UNPIN_SCRIPT = (
    "$n = @(Get-NetNeighbor -AddressFamily IPv4 -State Permanent -ErrorAction SilentlyContinue | "
    "Where-Object {{ $_.IPAddress -eq '{gateway}' }}); "
    "$n | ForEach-Object {{ Remove-NetNeighbor -InputObject $_ -Confirm:$false }}; "
    "@{{removed=$n.Count}} | ConvertTo-Json -Compress")


def unpin(directory, runner=safe_run):
    """At uninstall: remove the permanent entry of the approved gateway, so a new modem works without Satsuma."""
    try:
        row = json.loads((Path(directory) / APPROVED).read_text(encoding='utf-8'))
        address = str(ipaddress.IPv4Address(row['gateway']))
    except (OSError, ValueError, KeyError, TypeError):
        return {'ok': True, 'status': 'NOTHING_PINNED'}
    result = json.loads(run_powershell(UNPIN_SCRIPT.format(gateway=address), runner) or '{}')
    return {'ok': True, 'status': 'UNPINNED', 'gateway': address, 'removed': result.get('removed', 0)}


class Gateway:
    def __init__(self, directory, key, runner=safe_run, record=None, clock=None):
        import time
        self.directory, self.key, self.runner = Path(directory), key, runner
        self.record = record or (lambda kind, **fields: fields)
        self.clock = clock or time.time
        self.approved, self.pinned, self.slow_at, self.slow = None, {}, None, {'dns': [], 'proxies': []}
        self.counts = {'findings': 0, 'written_back': 0, 'write_back_failed': 0}

    # -- approval ---------------------------------------------------------------------------------
    def _text(self, approved):
        return ('satsuma-approved-gateway:%s:%s:%s' % (approved['gateway'], approved['mac'],
                                                       approved.get('interface'))).encode()

    def load(self):
        try:
            row = json.loads((self.directory / APPROVED).read_text(encoding='utf-8'))
            approved = {'gateway': row['gateway'], 'mac': row['mac'], 'interface': row.get('interface')}
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if self.key is None or not self.key.verify(self._text(approved), row.get('signature', '')):
            return None
        self.approved = approved
        return approved

    def approve_now(self):
        """Approve the modem seen now (first start during installation, or the panel after the password)."""
        approved = gateway_decision.approve(self.observe(fast_only=True))
        row = {**approved, 'signature': self.key.sign(self._text(approved))}
        temporary = self.directory / (APPROVED + '.tmp')
        temporary.write_text(json.dumps(row), encoding='utf-8')
        temporary.replace(self.directory / APPROVED)
        self.approved = approved
        return approved

    # -- reading ----------------------------------------------------------------------------------
    def _native(self, argv):
        result = self.runner(argv, capture_output=True, text=True, timeout=15)
        if result.returncode != 0:
            raise FirewallError((result.stderr or result.stdout or ' '.join(argv))[:300])
        return result.stdout or ''

    def observe(self, fast_only=False):
        routes = parse_routes(self._native(['route.exe', 'print', '-4']))
        neighbours = parse_neighbours(self._native(['arp.exe', '-a']))
        observation = {'gateways': routes, 'neighbours': neighbours, 'pinned': dict(self.pinned)}
        if not fast_only:
            now = self.clock()
            if self.slow_at is None or now - self.slow_at >= SLOW_EVERY:
                self.slow_at = now
                self.slow = json.loads(run_powershell(SETTINGS_SCRIPT, self.runner) or '{}')
            observation['dns'] = self.slow.get('dns') or []
            observation['proxies'] = self.slow.get('proxies') or []
        return observation

    # -- writing back -----------------------------------------------------------------------------
    def apply(self, action):
        kind = action['action']
        if kind == 'pin_gateway_mac':
            result = json.loads(run_powershell(pin_script(action['gateway'], action['mac'], action['interface']),
                                               self.runner) or '{}')
            ok = result.get('state') == 'Permanent' and gateway_decision.mac(result.get('mac')) == action['mac']
            self.pinned[action['gateway']] = ok
            return ok, result
        if kind == 'remove_default_route':
            gateway = str(ipaddress.IPv4Address(action['gateway']))
            self._native(['route.exe', 'delete', '0.0.0.0', 'mask', '0.0.0.0', gateway])
            return True, {}
        if kind == 'restore_default_route':
            gateway = str(ipaddress.IPv4Address(action['gateway']))
            self._native(['route.exe', 'add', '0.0.0.0', 'mask', '0.0.0.0', gateway])
            return True, {}
        if kind == 'lock_dns':
            result = dns.lock(self.runner)
            self.slow_at = None
            return bool(result.get('ok', result.get('status') == 'LOCKED')), result
        if kind == 'remove_proxy':
            result = json.loads(run_powershell(REMOVE_PROXY_SCRIPT, self.runner) or '{}')
            self.slow_at = None
            return not result.get('proxies'), result
        raise ValueError('unknown write-back ' + kind)

    def check(self):
        if self.approved is None:
            return []
        try:
            observation = self.observe()
        except (FirewallError, ValueError, OSError) as exc:
            return [self.record('gateway_unreadable', error=str(exc)[:300])]
        findings, actions = gateway_decision.decide(self.approved, observation, dns.SERVERS)
        events = []
        for finding in findings:
            self.counts['findings'] += 1
            events.append(self.record('mitm_' + finding.pop('kind'), **finding))
        for action in actions:
            try:
                ok, detail = self.apply(action)
            except (FirewallError, ValueError, OSError) as exc:
                ok, detail = False, {'error': str(exc)[:300]}
            self.counts['written_back' if ok else 'write_back_failed'] += 1
            if findings or not ok:
                events.append(self.record('mitm_written_back' if ok else 'mitm_write_back_failed',
                                          **action, detail=detail))
        return events
