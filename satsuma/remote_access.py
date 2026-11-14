"""Remote access that must not accept connections from other machines.

Taken from the yeni-yazim branch (netd/remote_access.py). The user works
with TeamViewer/AnyDesk outbound only; incoming connections must not be
accepted (user decision). Two checks, both read only:

* Listeners: a known remote access server (SSH, VNC, RDP, file sharing,
  RustDesk, MeshAgent, TeamViewer, AnyDesk) listening on an address other
  than loopback is high. A listener whose program runs from /tmp, /home,
  memfd or a deleted file is high too. Other exposed listeners are only
  inventoried. The program is recognised by its executable name; when the
  owner is unknown, by its well-known port.
* AnyDesk settings: TeamViewer and AnyDesk carry incoming sessions inside
  their own outgoing connection, so the firewall cannot tell the two
  directions apart. AnyDesk's options for refusing incoming sessions
  ("Custom client advanced options", support.anydesk.com) are checked in
  /etc/anydesk/system.conf. Nothing is changed: those keys are documented
  for custom clients and not yet confirmed on the stock Linux client, so
  the findings say so. TeamViewer has no documented outgoing-only setting.

Dışarıdan bağlantı kabul etmemesi gereken uzak erişim. yeni-yazim dalından
alındı. Kullanıcı TeamViewer/AnyDesk'i yalnızca dışarıya bağlanarak
kullanır; gelen bağlantı kabul edilmez. İki salt okunur denetim: loopback
dışındaki bir adreste dinleyen bilinen uzak erişim sunucusu (SSH, VNC, RDP,
dosya paylaşımı, RustDesk, MeshAgent, TeamViewer, AnyDesk) ya da /tmp,
/home, memfd veya silinmiş dosyadan çalışan dinleyici yüksek önemdedir;
diğer dinleyiciler yalnızca listelenir. AnyDesk'in gelen oturumu reddetme
ayarları /etc/anydesk/system.conf içinde denetlenir; hiçbir şey
değiştirilmez.
"""
import os
import re

# executable basename -> service
PROGRAMS = {
    'sshd': 'ssh', 'dropbear': 'ssh',
    'x11vnc': 'vnc', 'Xvnc': 'vnc', 'x0vncserver': 'vnc', 'vncserver': 'vnc', 'wayvnc': 'vnc',
    'gnome-remote-desktop-daemon': 'rdp', 'xrdp': 'rdp', 'xrdp-sesman': 'rdp', 'krdpserver': 'rdp',
    'smbd': 'smb', 'nmbd': 'smb',
    'rpcbind': 'nfs', 'rpc.mountd': 'nfs', 'rpc.statd': 'nfs',
    'vsftpd': 'ftp', 'proftpd': 'ftp', 'pure-ftpd': 'ftp',
    'rustdesk': 'rustdesk',
    'meshagent': 'meshagent',
    'teamviewerd': 'teamviewer', 'TeamViewer': 'teamviewer',
    'anydesk': 'anydesk',
}
# Used only when the owning program is unknown (e.g. the kernel NFS server).
PORTS = {22: 'ssh', 21: 'ftp', 3389: 'rdp', 139: 'smb', 445: 'smb', 137: 'smb', 138: 'smb',
         111: 'nfs', 2049: 'nfs', 5938: 'teamviewer', 7070: 'anydesk',
         **{port: 'vnc' for port in range(5900, 6000)},
         **{port: 'rustdesk' for port in range(21115, 21120)}}

ANYDESK_CONFIG = '/etc/anydesk/system.conf'
ANYDESK_BINARY = '/usr/bin/anydesk'
# key -> value that refuses incoming sessions
ANYDESK_REQUIRED = {
    'ad.security.interactive_access': '2',  # never show incoming session requests
    'ad.features.unattended': 'false',      # no unattended (password) access
    'ad.anynet.direct': 'false',            # no direct connections to the listening port
}
# AnyDesk 7+: a non-empty pwd on any permission profile is an unattended access password.
ANYDESK_PROFILE_PASSWORD = re.compile(r'ad\.security\.permission_profiles\.[A-Za-z0-9_]+\.pwd')
UNVERIFIED = 'documented for AnyDesk custom clients; not yet confirmed on the stock Linux client'


def service_of(listener):
    process = listener.get('process') or {}
    exe = (process.get('exe') or '').removesuffix(' (deleted)')
    for name in (os.path.basename(exe), process.get('comm') or ''):
        if name in PROGRAMS:
            return PROGRAMS[name]
    if not exe and not process.get('comm'):
        return PORTS.get(listener.get('port'))
    return None


def listener_findings(listeners):
    findings = []
    for listener in listeners:
        process = listener.get('process') or {}
        service = service_of(listener)
        findings.append({'code': 'remote_access_listener' if service else 'exposed_listener',
                         'severity': 'high' if service or listener.get('suspicious') else 'info',
                         'service': service, 'proto': listener['proto'], 'address': listener['address'],
                         'port': listener['port'], 'exe': process.get('exe'), 'uid': listener.get('uid')})
    return findings


def _read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, encoding='utf-8', errors='replace') as stream:
        return stream.read(256 * 1024)


def anydesk_findings(path=ANYDESK_CONFIG, binary=ANYDESK_BINARY, read=_read, exists=os.path.exists):
    try:
        text = read(path)
    except FileNotFoundError:
        if not exists(binary):
            return []  # AnyDesk is not installed
        return [{'code': 'anydesk_config_missing', 'severity': 'medium', 'path': path, 'note': UNVERIFIED}]
    except OSError as exc:
        return [{'code': 'anydesk_config_unreadable', 'severity': 'info', 'path': path,
                 'error': exc.strerror or str(exc)}]
    values = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if sep:
            values[key.strip()] = value.strip()
    findings = [{'code': 'anydesk_incoming_allowed', 'severity': 'high', 'key': key, 'expected': wanted,
                 'actual': values.get(key), 'note': UNVERIFIED}
                for key, wanted in ANYDESK_REQUIRED.items() if values.get(key) != wanted]
    # The hash itself is never copied into a finding.
    findings += [{'code': 'anydesk_unattended_password', 'severity': 'high', 'key': key, 'note': UNVERIFIED}
                 for key, value in sorted(values.items()) if ANYDESK_PROFILE_PASSWORD.fullmatch(key) and value]
    return findings
