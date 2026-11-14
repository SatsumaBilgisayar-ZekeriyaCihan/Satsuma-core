"""Install the guard as the Windows service "Satsuma Core" (owner's decision 2026-11-11).

The exe is copied to %ProgramFiles%\\Satsuma and registered as the service
SatsumaCore: automatic start, LocalSystem, restarted one minute after any
failure (recovery actions, also on a non-crash stop). Because LocalSystem runs
it, the install is refused when anyone but SYSTEM, Administrators,
TrustedInstaller or the creator-owner can write the folder or the exe;
accounts are compared by SID, since group names are translated on a Turkish
Windows. The earlier Task Scheduler task, if present, is removed. Every setting
is read back.

Bekçiyi "Satsuma Core" Windows hizmeti olarak kurar (sahibinin kararı
2026-11-11). Exe %ProgramFiles%\\Satsuma klasörüne kopyalanır ve SatsumaCore
hizmeti olarak kaydedilir: otomatik başlar, LocalSystem olarak çalışır, her
hatadan bir dakika sonra yeniden başlatılır. LocalSystem çalıştırdığı için
klasöre ya da exe'ye SYSTEM, Yöneticiler, TrustedInstaller ve oluşturan sahip
dışında biri yazabiliyorsa kurulum reddedilir; hesaplar SID ile
karşılaştırılır. Önceki Görev Zamanlayıcı görevi varsa kaldırılır. Her ayar
geri okunur.
"""
import json
import subprocess
from pathlib import PureWindowsPath

from .firewall import FirewallError, run_powershell, safe_run

SERVICE_NAME = 'SatsumaCore'
DISPLAY_NAME = 'Satsuma Core'
EXE_NAME = 'satsuma-core-windows.exe'
LEGACY_TASK = ('\\Satsuma\\', 'Satsuma Core')
TRUSTED_SIDS = ('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0',
                'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')


def _quote(text):
    """A PowerShell single-quoted literal."""
    return "'" + str(text).replace("'", "''") + "'"


def status_body():
    return (
        f"$s = Get-CimInstance Win32_Service -Filter \"Name='{SERVICE_NAME}'\"; "
        "if (-not $s) { @{ok=$false; status='NOT_INSTALLED'} | ConvertTo-Json -Compress } else { "
        f"$q = (& sc.exe qfailure {SERVICE_NAME}) -join ' '; "
        "@{ok=$true; status=[string]$s.State; start=[string]$s.StartMode; account=[string]$s.StartName; "
        "program=[string]$s.PathName; restarts=([regex]::Matches($q, 'RESTART').Count)} | ConvertTo-Json -Compress }")


def install_script(source):
    source = str(source)
    if PureWindowsPath(source).suffix.lower() != '.exe' or '\n' in source or '\r' in source:
        raise ValueError('Kurulacak dosya bir .exe olmalı: ' + source)
    trusted = ','.join(f"'{sid}'" for sid in TRUSTED_SIDS)
    task_path, task_name = LEGACY_TASK
    return (
        "$dir = Join-Path $env:ProgramFiles 'Satsuma'; "
        "New-Item -ItemType Directory -Force -Path $dir | Out-Null; "
        f"$target = Join-Path $dir '{EXE_NAME}'; "
        f"$old = Get-CimInstance Win32_Service -Filter \"Name='{SERVICE_NAME}'\"; "
        f"if ($old -and $old.State -ne 'Stopped') {{ Stop-Service -Name '{SERVICE_NAME}' -Force }}; "
        f"if ((Resolve-Path -LiteralPath {_quote(source)}).Path -ne $target) {{ "
        f"Copy-Item -LiteralPath {_quote(source)} -Destination $target -Force }}; "
        # Refuse when a non-administrator can change the program LocalSystem will run.
        # Compared by SID: group names are translated on a Turkish Windows ("Yöneticiler").
        f"$trusted = @({trusted}); "
        "$weak = @((Get-Acl -LiteralPath $dir).Access + (Get-Acl -LiteralPath $target).Access | Where-Object { "
        "$ace = $_; try { $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } "
        "catch { $sid = $ace.IdentityReference.Value }; "
        "$ace.AccessControlType -eq 'Allow' -and -not ($trusted -contains $sid) -and $sid -notlike 'S-1-15-2-*' -and "
        "($ace.FileSystemRights.ToString() -match 'Write|Modify|FullControl|ChangePermissions|TakeOwnership') } "
        "| ForEach-Object { $_.IdentityReference.Value + ':' + $_.FileSystemRights }); "
        "if ($weak.Count -gt 0) { @{ok=$false; status='UNSAFE_FOLDER'; writable=$weak} | ConvertTo-Json -Compress; exit 0 }; "
        # The temporary Task Scheduler task of the first builds gives way to the service.
        f"Unregister-ScheduledTask -TaskPath {_quote(task_path)} -TaskName {_quote(task_name)} -Confirm:$false "
        "-ErrorAction SilentlyContinue; "
        "$bin = '\"' + $target + '\" --service'; "
        "if ($old) { "
        "Invoke-CimMethod -InputObject $old -MethodName Change -Arguments @{PathName=$bin; StartMode='Automatic'; "
        "StartName='LocalSystem'; DisplayName='" + DISPLAY_NAME + "'} | Out-Null } else { "
        f"New-Service -Name '{SERVICE_NAME}' -BinaryPathName $bin -DisplayName '{DISPLAY_NAME}' "
        "-StartupType Automatic -Description 'Satsuma Core ag ve sistem korumasi' | Out-Null }; "
        f"& sc.exe failure {SERVICE_NAME} reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null; "
        f"& sc.exe failureflag {SERVICE_NAME} 1 | Out-Null; "
        f"Start-Service -Name '{SERVICE_NAME}'; "
        + status_body())


def uninstall_script():
    # The service now also stops its ClamAV scan thread and clamd: wait until it has really stopped.
    # Hizmet artık ClamAV tarama iş parçacığını ve clamd'yi de durdurur: gerçekten durana kadar beklenir.
    return (f"$s = Get-Service -Name '{SERVICE_NAME}' -ErrorAction SilentlyContinue; "
            f"if ($s) {{ Stop-Service -Name '{SERVICE_NAME}' -Force -NoWait -ErrorAction SilentlyContinue; "
            "try { $s.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(90)) } catch { }; "
            f"& sc.exe delete {SERVICE_NAME} | Out-Null; Start-Sleep -Seconds 2 }}; " + status_body())


def _result(output):
    try:
        return json.loads(output or '{}')
    except ValueError:
        raise FirewallError('Hizmet yöneticisi yanıtı okunamadı: ' + repr((output or '')[:200]))


def verify(result):
    """True when the service reads back running, automatic, LocalSystem, from Program Files, with restarts."""
    program = result.get('program', '').lower()
    return (result.get('ok') is True and result.get('status') == 'Running' and result.get('start') == 'Auto'
            and result.get('account', '').lower() in ('localsystem', 'nt authority\\system')
            and ('\\satsuma\\' + EXE_NAME) in program and program.endswith('--service')
            and int(result.get('restarts') or 0) >= 1)


def current_user_sid(runner=safe_run):
    """The SID of the account running the installation: the owner (whoami /user)."""
    result = runner(['whoami.exe', '/user', '/fo', 'csv', '/nh'], capture_output=True, text=True, timeout=30)
    sid = (result.stdout or '').strip().rsplit(',', 1)[-1].strip().strip('"')
    if result.returncode != 0 or not sid.startswith('S-1-5-21-'):
        raise ValueError('the installing account could not be read: ' + (result.stdout or result.stderr or '')[:200])
    return sid


def write_install_approvals(directory, locations=(), files=(), owner=None):
    """Hand the wizard's approvals to the service's first start, which signs them with its new key."""
    import hashlib
    import os
    from pathlib import Path
    from .memory import PENDING, _folder
    if not locations and not files and not owner:
        return None
    request = {'locations': [_folder(f) for f in locations], 'setups': [], 'owner': owner}
    for path in files:
        request['setups'].append(hashlib.sha256(Path(path).read_bytes()).hexdigest())
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / (PENDING + '.tmp')
    temporary.write_text(json.dumps(request), encoding='utf-8')
    os.replace(temporary, directory / PENDING)
    return request


def install(source, runner=safe_run, locations=(), files=(), directory=None, owner=None):
    from .guard import state_dir
    owner = owner or current_user_sid(runner)
    write_install_approvals(directory or state_dir(), locations, files, owner)
    result = _result(run_powershell(install_script(source), runner, timeout=180))
    if result.get('status') == 'UNSAFE_FOLDER':
        return result
    return {**result, 'ok': verify(result)}


def status(runner=safe_run):
    result = _result(run_powershell(status_body(), runner))
    return {**result, 'ok': verify(result)} if result.get('ok') else result


def uninstall(runner=safe_run, wait=None):
    """Stop and delete the service; an empty answer is asked again, never taken as removed.

    Hizmeti durdurup siler; boş yanıt yeniden sorulur, asla kaldırıldı sayılmaz (GitHub, 2026-11-11).
    """
    import time
    wait = wait or time.sleep
    output = run_powershell(uninstall_script(), runner, timeout=180)
    for _ in range(6):
        if (output or '').strip():
            break
        wait(5)
        output = run_powershell(status_body(), runner)
    if not (output or '').strip():
        return {'ok': False, 'status': 'NO_ANSWER'}
    result = _result(output)
    return {**result, 'ok': result.get('status') == 'NOT_INSTALLED'}
