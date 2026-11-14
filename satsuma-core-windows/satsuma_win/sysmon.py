"""Sysmon: process monitoring on Windows (owner's decisions 2026-11-11).

Installation: Sysmon is downloaded from Microsoft (download.sysinternals.com)
at install time, its Authenticode signature must be valid and signed by
Microsoft Corporation, otherwise it is not installed and the reason is
reported. It is installed with Satsuma's configuration, which records:

* 1  process creation (every process),
* 7  image loads only from Temp and C:\\Users\\Public,
* 8  CreateRemoteThread (a thread started in another process),
* 10 process access with rights that allow writing another process's memory
  or starting threads in it,
* 25 process tampering (hollowing, herpaderping).

Reading: the service reads the new events every poll (EvtQuery on
Microsoft-Windows-Sysmon/Operational, from the last record read). A new
process is checked against the shared compile tool decision
(satsuma.build_tools) and stopped through its own handle unless Windows
Installer or Windows Update runs; for events 1, 7, 8, 10 and 25 the process
concerned is memory scanned at once instead of waiting for the next scan.

Sysmon: Windows'ta süreç izleme (sahibinin kararları 2026-11-11). Kurulum:
Sysmon kurulum sırasında Microsoft'tan (download.sysinternals.com) indirilir;
Authenticode imzası geçerli ve Microsoft Corporation imzalı olmalıdır, değilse
kurulmaz ve nedeni bildirilir. Satsuma yapılandırmasıyla kurulur: süreç
oluşturma, yalnızca Temp ve C:\\Users\\Public'ten DLL yükleme, uzak iş
parçacığı, başka sürecin belleğine yazma hakkıyla erişim ve süreç kurcalama
kaydedilir. Okuma: hizmet her turda yeni olayları okur. Yeni süreç ortak
derleme aracı kararıyla denetlenir ve Windows Installer ya da Windows Update
çalışmıyorsa kendi tutamacıyla durdurulur; 1, 7, 8, 10 ve 25 olaylarında
ilgili süreç bir sonraki taramayı beklemeden hemen bellek taramasından geçer.
"""
import io
import json
import subprocess
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from .firewall import run_powershell, safe_run

URL = 'https://download.sysinternals.com/files/Sysmon.zip'
CHANNEL = 'Microsoft-Windows-Sysmon/Operational'
EXE = 'Sysmon64.exe'
SCAN_EVENTS = (1, 7, 8, 10, 25)
PACKAGE_MANAGERS = frozenset(('msiexec.exe', 'trustedinstaller.exe', 'tiworker.exe'))
NS = '{http://schemas.microsoft.com/win/2004/08/events/event}'

CONFIG = """<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <EventFiltering>
    <RuleGroup name="satsuma-process" groupRelation="or">
      <ProcessCreate onmatch="exclude" />
    </RuleGroup>
    <RuleGroup name="satsuma-image" groupRelation="or">
      <ImageLoad onmatch="include">
        <ImageLoaded condition="contains">\\AppData\\Local\\Temp\\</ImageLoaded>
        <ImageLoaded condition="contains">\\Windows\\Temp\\</ImageLoaded>
        <ImageLoaded condition="contains">\\Users\\Public\\</ImageLoaded>
      </ImageLoad>
    </RuleGroup>
    <RuleGroup name="satsuma-remote-thread" groupRelation="or">
      <CreateRemoteThread onmatch="exclude" />
    </RuleGroup>
    <RuleGroup name="satsuma-access" groupRelation="or">
      <ProcessAccess onmatch="include">
        <GrantedAccess condition="is">0x1FFFFF</GrantedAccess>
        <GrantedAccess condition="is">0x1F3FFF</GrantedAccess>
        <GrantedAccess condition="is">0x1F0FFF</GrantedAccess>
        <GrantedAccess condition="is">0x143A</GrantedAccess>
        <GrantedAccess condition="is">0x1438</GrantedAccess>
        <GrantedAccess condition="is">0x147A</GrantedAccess>
        <GrantedAccess condition="is">0x0820</GrantedAccess>
        <GrantedAccess condition="is">0x0828</GrantedAccess>
        <GrantedAccess condition="is">0x0038</GrantedAccess>
      </ProcessAccess>
    </RuleGroup>
    <RuleGroup name="satsuma-tampering" groupRelation="or">
      <ProcessTampering onmatch="exclude" />
    </RuleGroup>
  </EventFiltering>
</Sysmon>
"""


def signature_script(path):
    quoted = "'" + str(path).replace("'", "''") + "'"
    return ("$s = Get-AuthenticodeSignature -LiteralPath " + quoted + "; "
            "@{status=[string]$s.Status; subject=[string]$s.SignerCertificate.Subject} | ConvertTo-Json -Compress")


def microsoft_signed(result):
    return result.get('status') == 'Valid' and 'O=Microsoft Corporation' in (result.get('subject') or '')


def install(target_dir, runner=safe_run, fetch=None):
    """Download, verify and install Sysmon; never installs an unverified file. Returns a result dict."""
    target_dir = Path(target_dir)
    fetch = fetch or (lambda url: urllib.request.urlopen(url, timeout=120).read())
    try:
        archive = zipfile.ZipFile(io.BytesIO(fetch(URL)))
        data = archive.read(EXE)
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        return {'ok': False, 'status': 'DOWNLOAD_FAILED', 'error': str(exc)[:300]}
    target_dir.mkdir(parents=True, exist_ok=True)
    exe = target_dir / EXE
    exe.write_bytes(data)
    try:
        signature = json.loads(run_powershell(signature_script(exe), runner) or '{}')
    except (ValueError, RuntimeError, OSError) as exc:   # FirewallError is a RuntimeError; never installs then
        signature = {'status': '', 'subject': '', 'error': str(exc)[:300]}
    if not microsoft_signed(signature):
        exe.unlink()
        return {'ok': False, 'status': 'SIGNATURE_REJECTED', 'signature': signature}
    config = target_dir / 'satsuma-sysmon.xml'
    config.write_text(CONFIG, encoding='utf-8')
    # Installed means the Sysmon64 service exists; "Sysmon64 -c" also succeeds when it is not installed.
    # Kurulu demek Sysmon64 hizmetinin var olmasıdır; "Sysmon64 -c" kurulu değilken de başarılı döner.
    present = runner(['sc.exe', 'query', 'Sysmon64'], capture_output=True, text=True, timeout=60).returncode == 0
    argv = [str(exe), '-accepteula', '-c', str(config)] if present else [str(exe), '-accepteula', '-i', str(config)]
    done = runner(argv, capture_output=True, text=True, timeout=300)
    if done.returncode != 0:
        return {'ok': False, 'status': 'INSTALL_FAILED', 'error': (done.stderr or done.stdout or '')[-300:]}
    channel = runner(['wevtutil.exe', 'gl', CHANNEL], capture_output=True, text=True, timeout=60)
    if channel.returncode != 0:
        return {'ok': False, 'status': 'CHANNEL_MISSING', 'error': (channel.stderr or channel.stdout or '')[-300:]}
    return {'ok': True, 'status': 'UPDATED' if present else 'INSTALLED', 'signature': signature}


def uninstall(target_dir, runner=safe_run):
    exe = Path(target_dir) / EXE
    if not exe.exists():
        return {'ok': True, 'status': 'NOT_INSTALLED'}
    done = runner([str(exe), '-u', 'force'], capture_output=True, text=True, timeout=120)
    return {'ok': done.returncode == 0, 'status': 'REMOVED' if done.returncode == 0 else 'REMOVE_FAILED'}


def parse(xml_text):
    """One Sysmon event as {'id', 'record', field: value}.

    Rendered events never carry a DTD; any input with one is refused before
    parsing, so no entity can be expanded. İşlenmiş olaylarda DTD olmaz; olan
    girdi ayrıştırılmadan reddedilir, hiçbir varlık açılamaz.
    """
    if '<!DOCTYPE' in xml_text or '<!ENTITY' in xml_text:
        raise ValueError('event with a DTD refused')
    root = ET.fromstring(xml_text)
    system = root.find(NS + 'System')
    event = {'id': int(system.findtext(NS + 'EventID')), 'record': int(system.findtext(NS + 'EventRecordID'))}
    for data in root.iter(NS + 'Data'):
        event[data.get('Name')] = data.text
    return event


def pids_to_scan(event):
    """The processes an event points at, for an immediate memory scan."""
    keys = {1: ('ProcessId',), 7: ('ProcessId',), 8: ('TargetProcessId', 'SourceProcessId'),
            10: ('TargetProcessId', 'SourceProcessId'), 25: ('ProcessId',)}.get(event['id'], ())
    found = []
    for key in keys:
        try:
            found.append(int(event.get(key) or 0))
        except ValueError:
            continue
    return [pid for pid in found if pid > 4]


class EventReader:
    """New Sysmon events since the last record read (win32evtlog.EvtQuery)."""

    def __init__(self, evtlog=None):
        if evtlog is None:
            import win32evtlog as evtlog
        self.evtlog, self.last = evtlog, None

    def read(self, limit=2000):
        log = self.evtlog
        if self.last is None:
            query = log.EvtQuery(CHANNEL, log.EvtQueryChannelPath | log.EvtQueryReverseDirection, '*')
            newest = log.EvtNext(query, 1)
            self.last = parse(log.EvtRender(newest[0], log.EvtRenderEventXml))['record'] if newest else 0
            return []
        query = log.EvtQuery(CHANNEL, log.EvtQueryChannelPath,
                             '*[System[EventRecordID > %d]]' % self.last)
        events = []
        while len(events) < limit:
            batch = log.EvtNext(query, 100)
            if not batch:
                break
            for handle in batch:
                event = parse(log.EvtRender(handle, log.EvtRenderEventXml))
                events.append(event)
                self.last = max(self.last, event['record'])
        return events
