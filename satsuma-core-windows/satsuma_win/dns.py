"""DNS lock on Windows: the trusted OpenDNS servers on every connected adapter.

The same servers as the Linux product (208.67.222.222, 208.67.220.220). The
modem's DHCP DNS is replaced, so a modem that answers with forged addresses
is not asked. Port 853 stays closed (firewall.close_port_853), so encrypted
DNS to an unknown server cannot bypass the lock. Name resolution is tested
after the change; a lock that breaks DNS is reported, never left silent.

Windows'ta DNS kilidi: bağlı her ağ bağdaştırıcısında güvenilir OpenDNS
sunucuları. Linux ürünüyle aynı sunucular. Modemin DHCP ile verdiği DNS
değiştirilir; sahte adres döndüren bir modeme sorulmaz. 853 portu kapalı
kalır; bilinmeyen bir sunucuya şifreli DNS kilidi aşamaz. Değişiklikten sonra
ad çözümlemesi sınanır; DNS'i bozan kilit sessiz bırakılmaz, bildirilir.
"""
import json
import subprocess

from .firewall import run_powershell, safe_run

SERVERS = ('208.67.222.222', '208.67.220.220')
TEST_NAME = 'fedoraproject.org'


def lock_script():
    servers = "','".join(SERVERS)
    return (
        "$ifs = @(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -ne $null -and "
        "$_.NetAdapter.Status -eq 'Up' } | ForEach-Object { $_.InterfaceIndex }); "
        f"foreach ($i in $ifs) {{ Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses @('{servers}') }}; "
        "Clear-DnsClientCache; "
        "$now = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $ifs -contains $_.InterfaceIndex } "
        "| ForEach-Object { @{index=$_.InterfaceIndex; servers=@($_.ServerAddresses)} }); "
        f"$ok = $null -ne (Resolve-DnsName -Name '{TEST_NAME}' -Type A -DnsOnly -ErrorAction SilentlyContinue); "
        "@{interfaces=$now; resolves=$ok} | ConvertTo-Json -Compress -Depth 4")


def lock(runner=safe_run):
    """Set the trusted servers; verified by reading them back and resolving a name."""
    data = json.loads(run_powershell(lock_script(), runner) or '{}')
    interfaces = data.get('interfaces') or []
    interfaces = interfaces if isinstance(interfaces, list) else [interfaces]
    wrong = [row for row in interfaces if tuple(row.get('servers') or ()) != SERVERS]
    if not interfaces:
        return {'ok': False, 'status': 'NO_CONNECTED_ADAPTER', 'servers': list(SERVERS)}
    if wrong:
        return {'ok': False, 'status': 'SERVERS_NOT_SET', 'interfaces': interfaces}
    if data.get('resolves') is not True:
        return {'ok': False, 'status': 'RESOLUTION_FAILED', 'interfaces': interfaces}
    return {'ok': True, 'status': 'LOCKED', 'servers': list(SERVERS), 'interfaces': interfaces}
