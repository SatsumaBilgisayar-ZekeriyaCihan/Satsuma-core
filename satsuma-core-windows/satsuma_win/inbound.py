"""No incoming connections on Windows: the owner's rule for remote support.

The owner works with remote support that connects outward (TeamViewer,
AnyDesk); nothing from outside may connect in. Applied and checked:

* Windows Firewall on for the Domain, Private and Public profiles, incoming
  connections blocked by default and the allowed-apps list ignored
  (AllowInboundRules False). Replies to connections this machine starts keep
  working, so outward remote support works.
* Remote Desktop and Remote Assistance refused (registry), and the services
  that accept connections from outside stopped and disabled: TermService
  (Remote Desktop), WinRM (remote PowerShell), LanmanServer (file and printer
  sharing; SMB1 off as well), RemoteRegistry and the OpenSSH server (sshd).

* Windows Terminal's Azure Cloud Shell profile is disabled for every user by
  machine policy (DisabledProfileSources = Windows.Terminal.Azure): it opens
  a shell on Azure from this machine (owner's decision 2026-11-11).

Every setting is read back after it is written. The guard checks again every
minute and writes back what was changed, recording it.

Windows'ta gelen bağlantı yok: sahibinin uzak destek kuralı. Sahibi dışarıya
bağlanan uzak destekle çalışır (TeamViewer, AnyDesk); dışarıdan içeriye
hiçbir şey bağlanamaz. Güvenlik duvarı üç profilde açık, gelen bağlantılar
varsayılan olarak engelli ve izinli uygulamalar listesi yok sayılır; bu
makinenin başlattığı bağlantıların yanıtları çalışır. Uzak Masaüstü ve Uzak
Yardım reddedilir; Windows Terminal'in Azure Cloud Shell profili her kullanıcı
için makine ilkesiyle kapatılır; dışarıdan bağlantı kabul eden hizmetler (Uzak Masaüstü,
WinRM, dosya ve yazıcı paylaşımı, SMB1, Uzak Kayıt Defteri) durdurulur ve
kapatılır. Her ayar yazıldıktan sonra geri okunur. Bekçi dakikada bir
yeniden denetler, değiştirileni geri yazar ve kaydeder.
"""
import json
import subprocess

from .firewall import run_powershell, safe_run

SERVICES = ('TermService', 'WinRM', 'LanmanServer', 'RemoteRegistry', 'sshd')
TERMINAL_POLICY = r'HKLM:\SOFTWARE\Policies\Microsoft\Windows Terminal'
TERMINAL_DISABLED = 'Windows.Terminal.Azure'
REGISTRY = (
    (r'HKLM:\System\CurrentControlSet\Control\Terminal Server', 'fDenyTSConnections', 1),
    (r'HKLM:\System\CurrentControlSet\Control\Remote Assistance', 'fAllowToGetHelp', 0),
)

CHECK_SCRIPT = (
    "$p = @(Get-NetFirewallProfile | ForEach-Object { @{name=[string]$_.Name; enabled=[string]$_.Enabled; "
    "inbound=[string]$_.DefaultInboundAction; rules=[string]$_.AllowInboundRules} }); "
    "$s = @(Get-Service -Name " + ','.join(f"'{n}'" for n in SERVICES) + " -ErrorAction SilentlyContinue "
    "| ForEach-Object { @{name=$_.Name; status=[string]$_.Status; start=[string]$_.StartType} }); "
    "$r = @(" + ', '.join(
        f"@{{path='{path}'; name='{name}'; value=(Get-ItemProperty -Path '{path}' -Name '{name}' "
        f"-ErrorAction SilentlyContinue).'{name}'}}" for path, name, _ in REGISTRY) + "); "
    "$smb1 = $null; try { $smb1 = [string](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch {}; "
    f"$t = @((Get-ItemProperty -Path '{TERMINAL_POLICY}' -Name DisabledProfileSources -ErrorAction SilentlyContinue)"
    ".DisabledProfileSources); "
    "@{profiles=$p; services=$s; registry=$r; smb1=$smb1; terminal=$t} | ConvertTo-Json -Compress -Depth 4")


def apply_script():
    parts = ["Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True "
             "-DefaultInboundAction Block -AllowInboundRules False"]
    for path, name, value in REGISTRY:
        parts.append(f"if (-not (Test-Path '{path}')) {{ New-Item -Path '{path}' -Force | Out-Null }}; "
                     f"Set-ItemProperty -Path '{path}' -Name '{name}' -Value {value} -Type DWord")
    parts.append("try { Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction Stop } catch {}")
    parts.append(f"if (-not (Test-Path '{TERMINAL_POLICY}')) {{ New-Item -Path '{TERMINAL_POLICY}' -Force | Out-Null }}; "
                 f"$old = @((Get-ItemProperty -Path '{TERMINAL_POLICY}' -Name DisabledProfileSources "
                 "-ErrorAction SilentlyContinue).DisabledProfileSources | Where-Object { $_ }); "
                 f"$new = @($old + '{TERMINAL_DISABLED}' | Select-Object -Unique); "
                 f"New-ItemProperty -Path '{TERMINAL_POLICY}' -Name DisabledProfileSources -PropertyType MultiString "
                 "-Value $new -Force | Out-Null")
    for name in SERVICES:
        parts.append(f"$svc = Get-Service -Name '{name}' -ErrorAction SilentlyContinue; "
                     f"if ($svc) {{ Stop-Service -Name '{name}' -Force -ErrorAction SilentlyContinue; "
                     f"Set-Service -Name '{name}' -StartupType Disabled }}")
    return '; '.join(parts) + '; ' + CHECK_SCRIPT


def evaluate(state):
    """What is still open: a list of plain descriptions; empty means locked."""
    problems = []
    profiles = state.get('profiles') or []
    profiles = profiles if isinstance(profiles, list) else [profiles]
    if not profiles:
        problems.append('güvenlik duvarı profilleri okunamadı')
    for row in profiles:
        name = row.get('name')
        if row.get('enabled') not in ('True', '1'):
            problems.append(f'{name} profilinde güvenlik duvarı kapalı')
        if row.get('inbound') not in ('Block', '4'):
            problems.append(f'{name} profilinde gelen bağlantı varsayılanı engel değil')
        if row.get('rules') not in ('False', '0'):
            problems.append(f'{name} profilinde izinli uygulamalar gelen bağlantı alabiliyor')
    services = state.get('services') or []
    services = services if isinstance(services, list) else [services]
    for row in services:
        if row.get('status') != 'Stopped' or row.get('start') != 'Disabled':
            problems.append(f"{row.get('name')} hizmeti çalışıyor ya da kapalı değil "
                            f"({row.get('status')}, {row.get('start')})")
    registry = state.get('registry') or []
    registry = registry if isinstance(registry, list) else [registry]
    wanted = {name: value for _, name, value in REGISTRY}
    for row in registry:
        if row.get('name') in wanted and row.get('value') != wanted[row['name']]:
            problems.append(f"{row.get('name')} = {row.get('value')} (olması gereken {wanted[row['name']]})")
    if state.get('smb1') not in (None, 'False'):
        problems.append('SMB1 açık')
    terminal = state.get('terminal') or []
    terminal = terminal if isinstance(terminal, list) else [terminal]
    if TERMINAL_DISABLED not in terminal:
        problems.append('Windows Terminal Azure Cloud Shell profili açık')
    return problems


def _state(output):
    try:
        return json.loads(output or '{}')
    except ValueError:
        return {}


def check(runner=safe_run):
    state = _state(run_powershell(CHECK_SCRIPT, runner))
    problems = evaluate(state)
    return {'ok': not problems, 'status': 'LOCKED' if not problems else 'OPEN', 'open': problems}


def lock(runner=safe_run):
    """Apply every setting, then read them back; ok only when nothing is left open."""
    state = _state(run_powershell(apply_script(), runner, timeout=180))
    problems = evaluate(state)
    return {'ok': not problems, 'status': 'LOCKED' if not problems else 'OPEN', 'open': problems}
