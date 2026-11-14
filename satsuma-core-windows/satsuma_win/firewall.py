"""Windows Firewall rules owned by Satsuma: address blocks and port 853.

Every rule is in the "Satsuma" group and has a fixed Name derived from what it
blocks, so it is created once and found again. Commands are built only from
values that passed ipaddress validation; nothing a peer sends can reach the
PowerShell text. A block rule in Windows Firewall wins over any allow rule.

Port 853 (DNS over TLS) is blocked outbound for TCP and UDP: command and
control over 853 was proven on the owner's machine and no Satsuma table
allows it.

Satsuma'nın Windows Güvenlik Duvarı kuralları: adres engelleri ve 853 portu.
Her kural "Satsuma" grubundadır ve neyi engellediğinden türeyen sabit bir
adı vardır; bir kez oluşturulur ve yeniden bulunur. Komutlar yalnızca
ipaddress denetiminden geçmiş değerlerle kurulur; uç tarafın gönderdiği
hiçbir şey PowerShell metnine ulaşamaz. Windows Güvenlik Duvarı'nda engel
kuralı her izin kuralından üstündür. 853 portu (TLS üzerinden DNS) TCP ve
UDP için dışa kapalıdır: sahibinin makinesinde 853 üzerinden komut-kontrol
trafiği kanıtlandı ve hiçbir Satsuma tablosu ona izin vermez.
"""
import ipaddress
import json
import subprocess

GROUP = 'Satsuma'
POWERSHELL = ['powershell.exe', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command']
PORT_853_RULES = (('Satsuma-Block-853-TCP', 'TCP'), ('Satsuma-Block-853-UDP', 'UDP'))


class FirewallError(RuntimeError):
    pass


def powershell_environment(environ=None):
    """The environment without PSModulePath: Windows PowerShell 5.1 started from PowerShell 7 inherits 7's
    module path and then cannot load its own modules (Get-AuthenticodeSignature returned nothing on
    GitHub's Windows server). Without it, 5.1 builds its own default path.

    PSModulePath olmadan ortam: PowerShell 7'den başlatılan 5.1, 7'nin modül yolunu devralır ve kendi
    modüllerini yükleyemez; değişken olmadan kendi varsayılan yolunu kurar.
    """
    import os
    env = dict(os.environ if environ is None else environ)
    for name in list(env):
        if name.upper() == 'PSMODULEPATH':
            del env[name]
    return env


UTF8_OUTPUT = '[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; '


def safe_run(argv, **kwargs):
    """subprocess.run that never fails on a localised console: PowerShell output is UTF-8 (UTF8_OUTPUT),
    native tools use the OEM code page, and an undecodable byte becomes a replacement character.

    Türkçe Windows'ta çıktı okunurken asla çökmez: PowerShell UTF-8, yerel araçlar OEM kod sayfası;
    çözülemeyen bayt yerine geçen karakter olur (cp1254 hatası 2026-11-11, sahibinin makinesi).
    """
    if kwargs.get('text') or kwargs.get('universal_newlines'):
        powershell = str(argv[0]).lower().endswith(('powershell.exe', 'pwsh.exe'))
        if 'encoding' not in kwargs:
            import codecs
            try:
                codecs.lookup('oem')
                native = 'oem'
            except LookupError:
                native = 'utf-8'
            kwargs['encoding'] = 'utf-8' if powershell else native
        kwargs.setdefault('errors', 'replace')
    return subprocess.run(argv, **kwargs)


def run_powershell(script, runner=safe_run, timeout=60):
    """Run one PowerShell script; return its standard output or raise FirewallError."""
    result = runner(POWERSHELL + [UTF8_OUTPUT + script], capture_output=True, text=True, timeout=timeout,
                    env=powershell_environment())
    if result.returncode != 0:
        raise FirewallError((result.stderr or result.stdout or 'PowerShell failed').strip()[:500])
    return result.stdout or ''


def _address(value):
    address = ipaddress.ip_address(str(value))
    address = getattr(address, 'ipv4_mapped', None) or address
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise ValueError('refusing to block a loopback, unspecified or multicast address: ' + str(address))
    return str(address)


def rule_names(ip):
    key = _address(ip).replace(':', '_')
    return 'Satsuma-Block-' + key + '-Out', 'Satsuma-Block-' + key + '-In'


def block_script(ip, reason):
    """PowerShell that blocks ``ip`` both ways, once. ``reason`` is reduced to a safe tag."""
    address = _address(ip)
    tag = ''.join(ch for ch in str(reason) if ch.isalnum() or ch in '_-')[:60] or 'satsuma'
    out_name, in_name = rule_names(address)
    parts = []
    for name, direction in ((out_name, 'Outbound'), (in_name, 'Inbound')):
        parts.append(
            f"if (-not (Get-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue)) {{ "
            f"New-NetFirewallRule -Name '{name}' -DisplayName 'Satsuma engeli {address} ({tag})' "
            f"-Group '{GROUP}' -Direction {direction} -Action Block -RemoteAddress '{address}' "
            f"-Profile Any -Enabled True | Out-Null }}")
    parts.append(f"Get-NetFirewallRule -Name '{out_name}','{in_name}' | Select-Object Name,Enabled,Action "
                 "| ConvertTo-Json -Compress")
    return '; '.join(parts)


def block_ip(ip, reason, runner=safe_run):
    """Block ``ip`` inbound and outbound; confirmed only when both rules read back enabled."""
    output = run_powershell(block_script(ip, reason), runner)
    try:
        rows = json.loads(output or '[]')
    except ValueError:
        raise FirewallError('Firewall readback was not JSON')
    rows = rows if isinstance(rows, list) else [rows]
    wanted = set(rule_names(ip))
    confirmed = {row.get('Name') for row in rows if isinstance(row, dict)
                 and str(row.get('Enabled')) in ('True', '1') and str(row.get('Action')) in ('Block', '4')}
    if not wanted <= confirmed:
        raise FirewallError('Block rules for ' + str(ip) + ' did not read back enabled')
    return {'ip': _address(ip), 'status': 'blocked', 'rules': sorted(wanted)}


def port_853_script():
    parts = []
    for name, protocol in PORT_853_RULES:
        parts.append(
            f"if (-not (Get-NetFirewallRule -Name '{name}' -ErrorAction SilentlyContinue)) {{ "
            f"New-NetFirewallRule -Name '{name}' -DisplayName 'Satsuma: 853 kapali ({protocol})' "
            f"-Group '{GROUP}' -Direction Outbound -Action Block -Protocol {protocol} -RemotePort 853 "
            f"-Profile Any -Enabled True | Out-Null }} else {{ Enable-NetFirewallRule -Name '{name}' }}")
    names = "','".join(name for name, _ in PORT_853_RULES)
    parts.append(f"Get-NetFirewallRule -Name '{names}' | Select-Object Name,Enabled,Action | ConvertTo-Json -Compress")
    return '; '.join(parts)


def close_port_853(runner=safe_run):
    """Block outbound 853 for TCP and UDP; confirmed by reading the rules back."""
    rows = json.loads(run_powershell(port_853_script(), runner) or '[]')
    rows = rows if isinstance(rows, list) else [rows]
    enabled = {row.get('Name') for row in rows if str(row.get('Enabled')) in ('True', '1')
               and str(row.get('Action')) in ('Block', '4')}
    missing = [name for name, _ in PORT_853_RULES if name not in enabled]
    if missing:
        raise FirewallError('853 rules not enabled: ' + ', '.join(missing))
    return {'status': 'closed', 'rules': [name for name, _ in PORT_853_RULES]}
