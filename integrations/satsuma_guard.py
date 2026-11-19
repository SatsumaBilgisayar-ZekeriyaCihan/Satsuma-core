#!/usr/bin/env python3
"""Satsuma Suricata+OTX+conntrack guard. Independent, fail-safe nft integration.

Uses an owned nftables table and mirrors real decisions into Core evidence.
A remote source is blocked only on a completed TCP connection, never on a
packet whose source could be forged, and DNS resolvers are never blocked
(audit K2). OTX corroborates only with at least two pulses and positive
reputation (audit K3).

Fixed operator rules (satsuma.peer_watch, satsuma.alert_verify): connections
are read from /proc, each peer is tied to its processes, a no-PTR peer making
a 6th connection during one visit is blocked without waiting for Suricata or OTX, and a
Suricata alert is acted on (and OTX asked) only when a live local process
owns its flow, so a forged packet cannot trigger a block.

OTX connection kill: every established TCP connection to a public peer is
checked against OTX (cached, rate limited). When OTX confirms the peer under
the same two-pulse floor, only that one connection is destroyed and the
result is verified (satsuma.connection_kill). Nothing else is touched.

Satsuma Suricata+OTX+conntrack bekçisi. Bağımsız, hata durumunda güvenli
nft entegrasyonu.

Kendi nftables tablosunu kullanır, gerçek kararları Core kanıtına yansıtır.
Uzak kaynak yalnızca tamamlanmış TCP bağlantısında engellenir, kaynağı
sahtelenebilecek pakette asla; DNS sunucuları hiç engellenmez (denetim K2).
OTX yalnızca en az iki kayıt ve pozitif itibarla destek verir (denetim K3).

OTX bağlantı kesme: genel bir uzak uca kurulu her TCP bağlantısı OTX'e karşı
denetlenir (önbellekli, hız sınırlı). OTX aynı iki kayıt tabanıyla uzak ucu
doğrularsa yalnızca o tek bağlantı yok edilir ve sonuç doğrulanır
(satsuma.connection_kill). Başka hiçbir şeye dokunulmaz.

Değişmez operatör kuralları (satsuma.peer_watch, satsuma.alert_verify):
bağlantılar /proc'tan okunur, her uç süreçlerine bağlanır, bir ziyarette
6. bağlantıyı yapan PTR'siz uç Suricata veya OTX beklemeden engellenir ve
Suricata uyarısı (ve OTX sorgusu) yalnızca akışın sahibi canlı bir yerel süreç
ise işleme alınır; sahte paket engelleme tetikleyemez.
"""
import argparse
import collections
import datetime as dt
import ipaddress
import json
import os
import pathlib
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request

DEFAULT_CONFIG = '/etc/satsuma-core/suricata-otx-guard.json'
DEFAULT = {
    'mode': 'observe',
    'fast_log': '/var/log/suricata/fast.log',
    'eve_json': '/var/log/suricata/eve.json',
    'input': 'auto',
    'start_at_end': True,
    'max_priority': 3,
    'fast_block': True,
    'otx_enabled': True,
    'otx_api_key_file': '/etc/satsuma-core/otx-api.key',
    'otx_min_pulses': 2,
    'otx_min_reputation': 1,
    'otx_match_mode': 'threshold',
    'otx_cache_hours': 24,
    'otx_max_checks_hour': 120,
    'otx_connection_kill': True,
    'otx_lookups_per_poll': 5,
    'peer_poll_seconds': 2,
    'process_stop_max_priority': 1,
    'subnet_enabled': True,
    'subnet_prefix': 24,
    'subnet_threshold': 10,
    'conntrack_poll_seconds': 20,
    'protected_cidrs': [],
    'trusted_cidrs': [],
    'state_dir': '/var/lib/satsuma-core/suricata-otx-guard'
}
FAST_RE = re.compile(r'\[Priority:\s*(\d+)\].*?\{([^}]+)\}\s+(.+?)\s+->\s+(.+?)\s*$')
SRC_DST_RE = re.compile(r'\bsrc=([^\s]+)\s+dst=([^\s]+)')
STOP = False
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def boot_verdict():
    from satsuma.early_guard import read_verdict
    return read_verdict()


def verified_log(path):
    from satsuma.source_guard import open_eve, resolve_writer_uid
    uid = resolve_writer_uid()
    stream = open_eve(path, uid)
    stream.satsuma_writer_uid = uid
    return stream


def _assured_tcp_original(src, dst, sport, dport):
    """True when conntrack holds (src, dst, sport, dport) as the ORIGINAL
    direction of a TCP connection marked [ASSURED].

    ASSURED means the three-way handshake completed. A sender with a forged
    source address never receives the SYN-ACK, so it cannot complete one;
    UDP and unfinished TCP entries, which a single forged packet creates,
    are therefore never accepted.

    conntrack'te (src, dst, sport, dport) bir TCP bağlantısının ORIGINAL
    yönü olarak [ASSURED] işaretiyle duruyorsa doğrudur. ASSURED, üçlü el
    sıkışmasının tamamlandığı anlamına gelir; sahte kaynak adresli gönderici
    SYN-ACK'i hiç almadığı için tamamlayamaz. Tek bir sahte paketin
    oluşturduğu UDP ve yarım TCP kayıtları bu yüzden asla kabul edilmez.
    """
    try:
        source = ipaddress.ip_address(src)
        destination = ipaddress.ip_address(dst)
    except (ValueError, TypeError):
        return False
    if source.version != destination.version:
        return False
    if any(type(p) is not int or not 0 <= p <= 65535 for p in (sport, dport)):
        return False
    src, dst = str(source), str(destination)
    family = 'ipv4' if source.version == 4 else 'ipv6'
    result = command(['conntrack', '-L', '-f', family, '-p', 'tcp',
                      '-s', src, '-d', dst, '--sport', str(sport), '--dport', str(dport)])
    if result.returncode:
        return False
    for line in result.stdout.splitlines():
        if not line.startswith('tcp ') or '[ASSURED]' not in line:
            continue
        original = re.search(r'\bsrc=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)', line)
        if original:
            try:
                values = (str(ipaddress.ip_address(original[1])), str(ipaddress.ip_address(original[2])),
                          int(original[3]), int(original[4]))
            except ValueError:
                continue
            if values == (src, dst, sport, dport):
                return True
    return False


def assured_reply_connection(alert):
    """The alert is a reply on a TCP connection this host opened and completed.

    Used for alerts whose destination is this host: the remote end of a
    connection we initiated (for example a C2 server answering) is a real
    peer, because it completed the handshake with us.

    Alarm, bu bilgisayarın açtığı ve tamamladığı bir TCP bağlantısındaki
    yanıttır. Hedefi bu bilgisayar olan alarmlar için kullanılır: bizim
    başlattığımız bağlantının karşı ucu (örneğin yanıt veren bir C2
    sunucusu) el sıkışmasını bizimle tamamladığı için gerçek bir eştir.
    """
    if alert.get('protocol', '').lower() != 'tcp':
        return False
    return _assured_tcp_original(alert.get('dest_ip'), alert.get('source_ip'),
                                 alert.get('dest_port'), alert.get('source_port'))


def inbound_connection(alert):
    """Require the alert's complete tuple in conntrack's ORIGINAL direction,
    on a completed (ASSURED) TCP connection.

    A reply from a remote relay on a locally initiated connection is not an
    incoming connection, regardless of the application name in its signature.
    UDP is never accepted: one forged UDP packet creates exactly such an
    ORIGINAL entry (audit finding K2).

    Alarmın tam dörtlüsü conntrack'te ORIGINAL yönde ve tamamlanmış (ASSURED)
    bir TCP bağlantısında bulunmalıdır. UDP asla kabul edilmez: tek bir sahte
    UDP paketi tam olarak böyle bir ORIGINAL kayıt oluşturur (denetim K2).
    """
    protocol = alert.get('protocol', '').lower()
    ports = [alert.get('source_port'), alert.get('dest_port')]
    if protocol != 'tcp' or any(type(p) is not int or not 0 <= p <= 65535 for p in ports):
        return False
    return _assured_tcp_original(alert.get('source_ip'), alert.get('dest_ip'), *ports)


def stopped(*_):
    global STOP
    STOP = True


def command(argv, **kwargs):
    return subprocess.run(argv, text=True, capture_output=True, timeout=8, **kwargs)


def get_config(path):
    cfg = dict(DEFAULT)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as fh:
        info=os.fstat(fh.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.geteuid()) or info.st_mode & 0o022 or info.st_nlink!=1:
            raise PermissionError('Unsafe guard configuration')
        raw=fh.read(65537)
        if len(raw)>65536:raise ValueError('Guard configuration exceeds capacity')
        custom=json.loads(raw)
    if not isinstance(custom, dict):
        raise ValueError('Config must be a JSON object')
    extra = set(custom) - set(cfg)
    if extra:
        raise ValueError('Unrecognized config fields: ' + ', '.join(sorted(extra)))
    cfg.update(custom)
    if cfg['mode'] not in ('observe', 'block'):
        raise ValueError('mode must be observe or block')
    if cfg['input'] not in ('auto', 'fast', 'eve'):
        raise ValueError('input must be auto, fast or eve')
    if cfg['otx_match_mode'] not in ('any_pulse', 'threshold'):
        raise ValueError('otx_match_mode must be any_pulse or threshold')
    # Audit K3: anyone can publish a pulse. An old any_pulse setting is read
    # as threshold, and no setting goes below two pulses and reputation one.
    # Denetim K3: eski any_pulse ayarı threshold olarak okunur; hiçbir ayar
    # iki kaydın ve bir itibar puanının altına inmez.
    cfg['otx_match_mode'] = 'threshold'
    for key in ('fast_log', 'eve_json', 'state_dir', 'otx_api_key_file'):
        if not isinstance(cfg[key], str) or not cfg[key].startswith('/'):
            raise ValueError(key + ' must be an absolute path')
    if cfg['state_dir'] != DEFAULT['state_dir']:
        raise ValueError('Guard state directory is fixed beneath the Satsuma data directory')
    for key in ('fast_log','eve_json'):
        source=pathlib.Path(cfg[key])
        if '..' in source.parts or not source.is_relative_to('/var/log'):
            raise ValueError('Guard log sources must stay beneath /var/log')
    secret=pathlib.Path(cfg['otx_api_key_file'])
    if '..' in secret.parts or not secret.is_relative_to('/etc/satsuma-core'):
        raise ValueError('OTX key must stay beneath /etc/satsuma-core')
    for key in ('max_priority', 'otx_min_pulses', 'otx_min_reputation', 'otx_cache_hours', 'otx_max_checks_hour',
                'subnet_prefix', 'subnet_threshold', 'conntrack_poll_seconds', 'otx_lookups_per_poll', 'peer_poll_seconds', 'process_stop_max_priority'):
        if type(cfg[key]) is not int:
            raise ValueError(key + ' must be an integer')
    cfg['otx_min_pulses'] = max(2, cfg['otx_min_pulses'])
    cfg['otx_min_reputation'] = max(1, cfg['otx_min_reputation'])
    if not (0 <= cfg['max_priority'] <= 255 and 8 <= cfg['subnet_prefix'] <= 32 and
            2 <= cfg['subnet_threshold'] <= 1000 and cfg['conntrack_poll_seconds'] >= 5 and
            cfg['otx_max_checks_hour'] >= 0 and cfg['otx_cache_hours'] >= 1 and
            1 <= cfg['otx_lookups_per_poll'] <= 50 and 1 <= cfg['peer_poll_seconds'] <= 60
            and 0 <= cfg['process_stop_max_priority'] <= 3):
        raise ValueError('Invalid threshold/priority/rate setting')
    for key in ('protected_cidrs', 'trusted_cidrs'):
        if not isinstance(cfg[key], list):
            raise ValueError(key + ' must be an array')
        for net in cfg[key]:
            ipaddress.ip_network(net, strict=False)
    for key in ('fast_block', 'otx_enabled', 'start_at_end', 'subnet_enabled', 'otx_connection_kill'):
        if not isinstance(cfg[key], bool):
            raise ValueError(key + ' must be true/false')
    return cfg


def parse_endpoint(token):
    token = token.strip().strip('[]')
    try:
        return ipaddress.ip_address(token)
    except ValueError:
        # IPv4:port or bracketed IPv6:port. Avoid trying to parse arbitrary strings.
        prefix, sep, port = token.rpartition(':')
        if not sep or not port.isdecimal():
            return None
        try:
            return ipaddress.ip_address(prefix.strip('[]'))
        except ValueError:
            return None


def alert_evidence_class(alert):
    """Priority is impact metadata, never attack attribution by itself."""
    token=str(alert.get('rule_id') or '')
    parts=token.split(':')
    try:
        sid=int(parts[1] if len(parts)>=2 else token)
        gid=int(parts[0]) if len(parts)>=2 else int(alert.get('generator_id') or 1)
    except (ValueError,TypeError):sid,gid=None,None
    label=str(alert.get('signature') or '').upper()
    if (sid is not None and 2200000<=sid<2300000) or label.startswith(('SURICATA STREAM','SURICATA TCP','SURICATA IPv4'.upper(),'SURICATA DECODER','SURICATA APP-LAYER')):
        return 'engine_anomaly'
    if sid is None or gid != 1:
        return 'unverified_signature'
    return 'attack_signature_candidate'


def parse_alert(line, source):
    if source == 'fast':
        m = FAST_RE.search(line)
        if not m:
            return None
        protocol = m.group(2).upper()
        def endpoint(token):
            if protocol not in ('TCP', 'UDP'):
                return parse_endpoint(token), None
            address, sep, port = token.strip().rpartition(':')
            if not sep or not port.isdecimal() or not 0 <= int(port) <= 65535:
                return None, None
            try:
                return ipaddress.ip_address(address.strip('[]')), int(port)
            except ValueError:
                return None, None
        src, sport = endpoint(m.group(3))
        dst, dport = endpoint(m.group(4))
        pri = int(m.group(1))
        sid = re.search(r'\[\*\*\]\s+\[(\d+):(\d+):(\d+)\]', line)
        rule_id = ':'.join(sid.groups()) if sid else None
        label = line.split('[**]')[-2].strip() if line.count('[**]') >= 2 else 'Suricata fast.log'
    else:
        try:
            obj = json.loads(line)
            if obj.get('event_type') != 'alert':
                return None
            src, dst = ipaddress.ip_address(obj['src_ip']), ipaddress.ip_address(obj['dest_ip'])
            pri = int(obj['alert'].get('severity', 9))
            protocol = str(obj.get('proto', '')).upper()
            sport, dport = obj.get('src_port'), obj.get('dest_port')
            rule_id = str(obj['alert'].get('signature_id') or '') or None
            label = str(obj['alert'].get('signature', 'Suricata eve.json'))
        except (ValueError, KeyError, TypeError):
            return None
    if src is None or dst is None or src.version != dst.version:
        return None
    return {'source_ip': str(src), 'dest_ip': str(dst), 'source_port': sport, 'dest_port': dport,
            'protocol': protocol, 'rule_id': rule_id, 'priority': pri, 'signature': label[:500], 'input': source,
            'generator_id':int(sid.group(1)) if source=='fast' and sid else obj['alert'].get('gid',1) if source!='fast' else 1}


def parse_conntrack(text):
    """Only inbound TCP connections in ESTABLISHED state count as connected."""
    result = set()
    for line in text.splitlines():
        if not re.match(r'^tcp\s', line) or not re.search(r'\bESTABLISHED\b', line):
            continue
        match = SRC_DST_RE.search(line)
        if match:
            try:
                src = ipaddress.ip_address(match.group(1))
                dst = ipaddress.ip_address(match.group(2))
                if src.version == 4 and dst.version == 4:
                    result.add((str(src), str(dst)))
            except ValueError:
                pass
    return result


def local_ips():
    ips = set()
    try:
        r = command(['ip', '-j', 'address', 'show'])
        if r.returncode == 0:
            for device in json.loads(r.stdout):
                for item in device.get('addr_info', []):
                    ips.add(item.get('local', ''))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        pass
    return ips


class Nft:
    TABLE = 'satsuma_otx_guard'

    def verify_layout(self, include_output=True):
        try:
            entries = json.loads(self.run(['nft', '-j', 'list', 'table', 'inet', self.TABLE]))['nftables']
            chains = {e['chain']['name']: e['chain'] for e in entries if 'chain' in e}
            sets = {e['set']['name']: e['set'] for e in entries if 'set' in e}
            expected_chains = {'input', 'forward', 'output'} if include_output else {'input', 'forward'}
            if set(chains) != expected_chains or set(sets) != {'blocked_v4', 'blocked_v6'}:
                raise ValueError('Unexpected chains or sets')
            for name, family in [('blocked_v4', 'ipv4_addr'), ('blocked_v6', 'ipv6_addr')]:
                if sets[name].get('type') != family or sets[name].get('flags'):
                    raise ValueError('Unexpected address set type/flags')
            for name, chain in chains.items():
                if (chain.get('family'), chain.get('table'), chain.get('type'), chain.get('hook'),
                    chain.get('prio'), chain.get('policy')) != ('inet', self.TABLE, 'filter', name, -150, 'accept'):
                    raise ValueError('Unexpected chain hook/priority/policy')
                actual = []
                for entry in entries:
                    rule = entry.get('rule', {})
                    if rule.get('chain') == name:
                        if rule.get('family') != 'inet' or rule.get('table') != self.TABLE:
                            raise ValueError('Unexpected rule owner')
                        expr = []
                        for term in rule['expr']:
                            if 'counter' in term:
                                expr.append({'counter': None})
                            elif 'match' in term and term['match'].get('left') == {'ct': {'key': 'direction'}}:
                                match = dict(term['match'])
                                match['right'] = {'original': 0, 'reply': 1}.get(match['right'], match['right'])
                                expr.append({'match': match})
                            else:
                                expr.append(term)
                        actual.append(expr)
                expected = []
                if name == 'input':
                    expected.append([{'match': {'op': '==', 'left': {'meta': {'key': 'iifname'}}, 'right': 'lo'}}, {'accept': None}])
                address_field = 'daddr' if name == 'output' else 'saddr'
                for family, target in [('ip', 'blocked_v4'), ('ip6', 'blocked_v6')]:
                    expected.append([
                        {'match': {'op': '==', 'left': {'ct': {'key': 'direction'}}, 'right': 0}},
                        {'match': {'op': '==', 'left': {'payload': {'protocol': family, 'field': address_field}}, 'right': '@'+target}},
                        {'counter': None}, {'drop': None}])
                if actual != expected:
                    raise ValueError('Guard DROP linkage differs from policy')
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError('nft guard layout verification failed: '+str(exc)) from exc

    def run(self, cmd, input_text=None):
        try:
            result = command(cmd, input=input_text)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError('nft command failed: ' + str(exc)) from exc
        if result.returncode:
            raise RuntimeError('nft: ' + (result.stderr or result.stdout).strip()[:500])
        return result.stdout

    def setup(self):
        """Never flush other tables, chains or sets. We own only satsuma_otx_guard."""
        exists = command(['nft', 'list', 'table', 'inet', self.TABLE])
        if exists.returncode:
            script = f'''add table inet {self.TABLE}
add set inet {self.TABLE} blocked_v4 {{ type ipv4_addr; }}
add set inet {self.TABLE} blocked_v6 {{ type ipv6_addr; }}
add chain inet {self.TABLE} input {{ type filter hook input priority -150; policy accept; }}
add chain inet {self.TABLE} forward {{ type filter hook forward priority -150; policy accept; }}
add chain inet {self.TABLE} output {{ type filter hook output priority -150; policy accept; }}
add rule inet {self.TABLE} input iifname "lo" accept
add rule inet {self.TABLE} input ct direction original ip saddr @blocked_v4 counter drop
add rule inet {self.TABLE} input ct direction original ip6 saddr @blocked_v6 counter drop
add rule inet {self.TABLE} forward ct direction original ip saddr @blocked_v4 counter drop
add rule inet {self.TABLE} forward ct direction original ip6 saddr @blocked_v6 counter drop
add rule inet {self.TABLE} output ct direction original ip daddr @blocked_v4 counter drop
add rule inet {self.TABLE} output ct direction original ip6 daddr @blocked_v6 counter drop
'''
            self.run(['nft', '-f', '-'], input_text=script)
        else:
            for set_name in ('blocked_v4', 'blocked_v6'):
                self.run(['nft', 'list', 'set', 'inet', self.TABLE, set_name])
            for chain in ('input', 'forward'):
                self.run(['nft', 'list', 'chain', 'inet', self.TABLE, chain])
            # Migrate only an exactly verified old input/forward table, preserving
            # its existing address sets. Never accept an unknown firewall layout.
            try:
                self.verify_layout()
            except RuntimeError:
                self.verify_layout(include_output=False)
                upgrade = f'''add chain inet {self.TABLE} output {{ type filter hook output priority -150; policy accept; }}
add rule inet {self.TABLE} output ct direction original ip daddr @blocked_v4 counter drop
add rule inet {self.TABLE} output ct direction original ip6 daddr @blocked_v6 counter drop
'''
                self.run(['nft', '-f', '-'], input_text=upgrade)
        self.verify_layout()

    def contains(self, ip):
        addr = ipaddress.ip_address(ip)
        target = 'blocked_v4' if addr.version == 4 else 'blocked_v6'
        try:
            data = json.loads(self.run(['nft', '-j', 'list', 'set', 'inet', self.TABLE, target]))
            sets = [entry['set'] for entry in data['nftables']
                    if isinstance(entry, dict) and 'set' in entry]
            matches = [s for s in sets if s.get('family') == 'inet'
                       and s.get('table') == self.TABLE and s.get('name') == target]
            if len(matches) != 1:
                raise ValueError('Expected owned nft set is missing or ambiguous')
            members = matches[0].get('elem', [])
            if not isinstance(members, list):
                raise ValueError('Invalid nft set elements')
            addresses = set()
            for member in members:
                if isinstance(member, dict):
                    member = member['elem']['val']
                parsed = ipaddress.ip_address(member)
                if parsed.version != addr.version:
                    raise ValueError('Unexpected nft address family')
                addresses.add(str(parsed))
            return str(addr) in addresses
        except (ValueError, KeyError, TypeError) as exc:
            raise RuntimeError('nft readback could not be verified: ' + str(exc)) from exc

    def block(self, ip):
        addr = ipaddress.ip_address(ip)
        target = 'blocked_v4' if addr.version == 4 else 'blocked_v6'
        if not self.contains(str(addr)):
            try:
                self.run(['nft', 'add', 'element', 'inet', self.TABLE, target, '{', str(addr), '}'])
            except RuntimeError:
                # Another writer may have inserted it; only kernel readback counts.
                if not self.contains(str(addr)):
                    raise
        if not self.contains(str(addr)):
            raise RuntimeError('nft block failed kernel readback')

    def unblock(self, ip):
        addr = ipaddress.ip_address(ip)
        target = 'blocked_v4' if addr.version == 4 else 'blocked_v6'
        self.run(['nft', 'delete', 'element', 'inet', self.TABLE, target, '{', str(addr), '}'])
        if self.contains(str(addr)):
            raise RuntimeError('nft unblock failed kernel readback')


class Guard:
    def __init__(self, cfg, *, boot_provider=None, flow_checker=None, opener=None, core_store=None,
                 reply_checker=None, alert_verifier=None):
        os.umask(0o077)  # Keep the state database and evidence logs private.
        self.cfg = cfg
        self.boot_provider = boot_provider or boot_verdict
        if cfg['mode']=='block' and not self.boot_provider().get('response_unlocked'):
            raise RuntimeError('Signed application/boot integrity must pass before guard activation')
        self.flow_checker = flow_checker or inbound_connection
        self.reply_checker = reply_checker or assured_reply_connection
        self.opener = opener or verified_log
        self.core_store = core_store
        self.state = pathlib.Path(cfg['state_dir'])
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.state, 0o700)
        from satsuma.protected_storage import check
        for name in ('guard.sqlite','guard.sqlite-wal','guard.sqlite-shm','events.jsonl'):
            existing=self.state/name
            if existing.exists() or existing.is_symlink():check(existing.lstat())
        self.db = sqlite3.connect(str(self.state / 'guard.sqlite'), timeout=15)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('CREATE TABLE IF NOT EXISTS blocks(ip TEXT PRIMARY KEY, ts TEXT, reason TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS otx_cache(ip TEXT PRIMARY KEY, ts REAL, pulses INTEGER, reputation REAL, verdict TEXT)')
        self.db.execute('CREATE TABLE IF NOT EXISTS offsets(path TEXT PRIMARY KEY, dev INTEGER, inode INTEGER, offset INTEGER)')
        self.db.execute('CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, ts TEXT NOT NULL, event TEXT NOT NULL, body TEXT NOT NULL)')
        self.db.commit()
        event_fd=os.open(self.state/'events.jsonl',os.O_WRONLY|os.O_APPEND|os.O_CREAT|os.O_NOFOLLOW|os.O_NONBLOCK,0o600)
        try:check(os.fstat(event_fd))
        except BaseException:
            os.close(event_fd)
            raise
        self.events=os.fdopen(event_fd,'a',encoding='utf-8')
        self.trusted = [ipaddress.ip_network(x, strict=False) for x in cfg['trusted_cidrs']]
        self.protected = [ipaddress.ip_network(x, strict=False) for x in cfg['protected_cidrs']]
        self.own_ips = local_ips()
        self.nft = Nft()
        self.previous_peers = None
        self.recent_peers = {}  # first-seen peer IPs inside a rolling five-minute window
        self.otx_requests = collections.deque()
        from satsuma.peer_watch import PeerWatch, PtrResolver
        from satsuma.alert_verify import verify_alert
        self.peers = PeerWatch(PtrResolver(lambda: sorted(self.resolvers())), self.eligible, self.support_ips)
        self.alert_verifier = alert_verifier or (
            lambda alert: verify_alert(alert, watch=self.peers, store=self.core_store))
        self.watch_logged = {}
        self.api_key = None
        if cfg['otx_enabled']:
            try:
                with open(cfg['otx_api_key_file'], encoding='utf-8') as f:
                    self.api_key = f.read().strip()
            except FileNotFoundError:
                pass
            if not self.api_key:
                self.write('otx_disabled', note='OTX API key is missing/empty; checks disabled')
        if cfg['mode'] == 'observe':
            if shutil.which('nft'):
                old = command(['nft', 'list', 'table', 'inet', Nft.TABLE])
                if old.returncode == 0:
                    self.write('warning', detail='Previous nft table still active; to fully disable blocking: nft delete table inet satsuma_otx_guard')
        if cfg['mode'] == 'block':
            if not self.boot_provider().get('response_unlocked'):
                raise RuntimeError('Signed application/boot integrity must pass before guard activation')
            self.nft.setup()
            for (ip,) in self.db.execute('SELECT ip FROM blocks'):
                self.nft.block(ip)
        self.write('startup', mode=cfg['mode'], fast_block=cfg['fast_block'], subnet_enabled=cfg['subnet_enabled'])

    def write(self, event, **fields):
        payload = {'ts': dt.datetime.now(dt.timezone.utc).isoformat(), 'event': event, **fields}
        outcomes={'suricata_alert':'DETECTED','block':'BLOCKED','would_block':'OBSERVE_ONLY',
                  'ACTION_FAILED':'FAILED','ACTION_UNSUPPORTED':
                    'UNVERIFIED' if 'direction_unverified' in str(fields.get('reason','')) else 'OBSERVE_ONLY'}
        if event in outcomes:
            payload['response_outcome']=outcomes[event]
            payload['evidence_scope']='nft_set_and_rule_readback' if event=='block' else 'decision_only'
        if event == 'otx_connection_kill':
            payload['response_outcome']='BLOCKED' if fields.get('terminated') else 'FAILED'
            payload['evidence_scope']='socket_destroy_and_second_lookup'
        if self.core_store is not None and event == 'otx_connection_kill':
            self.core_store.add('actions', {**payload, 'timestamp': time.time(), 'source': 'suricata_guard',
                'action': 'network.connection_kill', 'executed': bool(fields.get('terminated')),
                'status': 'connection_terminated' if fields.get('terminated') else 'connection_kill_failed'})
        if self.core_store is not None and event in ('otx_check','otx_confirmed'):
            self.core_store.add('otx', {**payload, 'timestamp':time.time(), 'source':'suricata_guard',
                'reason':'otx_confirmed' if event=='otx_confirmed' else 'OTX gösterge sorgusu', 'traffic_drop_verified':False})
        if self.core_store is not None and event in ('block', 'would_block', 'ACTION_FAILED', 'ACTION_UNSUPPORTED', 'suricata_alert'):
            record = {**payload, 'timestamp': time.time(), 'source': 'suricata_guard',
                      'action': 'suricata.detected' if event == 'suricata_alert' else 'suricata.network_block',
                      'status': 'set_membership_confirmed' if event == 'block' else
                                'observe_only' if event == 'would_block' else event,
                      'traffic_drop_verified': False,
                      'executed': event == 'block', 'drop_rule_linked': event == 'block',
                      'detection_id': fields.get('detection_id')}
            self.core_store.add('events' if event == 'suricata_alert' else 'actions', record)
        line = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
        self.db.execute('INSERT INTO events(ts,event,body) VALUES(?,?,?)', (payload['ts'], event, line))
        self.db.commit()
        self.events.write(line + '\n')
        self.events.flush()
        if event in ('block', 'would_block', 'startup', 'warning', 'otx_confirmed', 'otx_connection_kill',
                     'process_stop'):
            print(line, flush=True)

    def heartbeat(self, status='RUNNING', **fields):
        if self.core_store is not None:
            if self.cfg['mode']=='block' and not self.boot_provider().get('response_unlocked'):
                status='LOCKED'
            self.core_store.set('suricata_guard_health', {'status':status,'updated_at':time.time(),
                'mode':self.cfg['mode'],'otx_configured_enabled':self.cfg.get('otx_enabled',False),
                'otx_key_available':bool(self.api_key),'direction':'inbound_and_outbound_original','traffic_drop_verified':False,**fields})

    def protected_dest(self, addr):
        ip = ipaddress.ip_address(addr)
        # Private destinations and locally assigned public IPs count as protected.
        return ip.is_private or str(ip) in self.own_ips or any(ip in n for n in self.protected if ip.version == n.version)

    def resolvers(self):
        """DNS servers this host depends on: the Core DNS policy and resolv.conf.

        Blocking one cuts this host off, so neither direction may target them.
        Bu bilgisayarın dayandığı DNS sunucuları; engellenirlerse bilgisayar
        ağdan kopar, bu yüzden iki yönde de hedef olamazlar.
        """
        found = set()
        if self.core_store is not None:
            dns = self.core_store.get('dns_policy', {}) or {}
            found.update(dns.get('expected_dns_servers', []) or [])
            if dns.get('upstream'):
                found.add(dns['upstream'])
        try:
            with open('/etc/resolv.conf', encoding='ascii', errors='replace') as stream:
                for line in stream.read(65536).splitlines():
                    fields = line.split()
                    if len(fields) >= 2 and fields[0] == 'nameserver':
                        found.add(fields[1].split('%', 1)[0])
        except OSError:
            pass
        normalized = set()
        for value in found:
            try:
                normalized.add(str(ipaddress.ip_address(value)))
            except ValueError:
                pass
        return normalized

    def eligible(self, src, dst):
        srcip = ipaddress.ip_address(src)
        if (not srcip.is_global or srcip.is_multicast or srcip.is_loopback
                or srcip.is_unspecified or src in self.own_ips):
            return False
        if self.operator_allowed(src):
            return False
        if str(srcip) in self.resolvers():
            return False
        if any(srcip in n for n in self.trusted if n.version == srcip.version):
            return False
        return self.protected_dest(dst)

    def operator_allowed(self, ip):
        """The owner's allow entry (address or range, 2.2.50) covering ``ip``, or None."""
        if self.core_store is None:
            return None
        from satsuma.net_allow import allowed
        return allowed(self.core_store, ip)

    def release_allowed(self):
        """Lift this guard's blocks that an allowed address or range now covers (2.2.50)."""
        released = []
        if self.core_store is None:
            return released
        for (ip,) in self.db.execute('SELECT ip FROM blocks').fetchall():
            covering = self.operator_allowed(ip)
            if not covering:
                continue
            try:
                if self.nft.contains(ip):
                    self.nft.unblock(ip)
            except RuntimeError as exc:
                self.write('warning', component='allow_release', ip=ip, detail=str(exc)[:200])
                continue
            self.db.execute('DELETE FROM blocks WHERE ip=?', (ip,))
            self.db.commit()
            self.write('UNBLOCKED', ip=ip, reason='operator_allowlisted', allowed_by=covering)
            released.append(ip)
        return released

    def block(self, ip, reason, **fields):
        ip = str(ipaddress.ip_address(ip))
        if self.core_store is not None:
            runtime=self.core_store.get('integrity_runtime',{}) or {}
            if runtime.get('status') not in (None,'HEALTHY'):
                self.write('ACTION_UNSUPPORTED',ip=ip,reason='integrity_observe_only',**fields)
                return {'status':'integrity_observe_only','ip':ip}
            covering = self.operator_allowed(ip)
            if covering:
                self.write('ACTION_UNSUPPORTED',ip=ip,reason='operator_allowlisted',allowed_by=covering,**fields)
                return {'status':'operator_allowlisted','ip':ip,'allowed_by':covering}
        persisted = bool(self.db.execute('SELECT 1 FROM blocks WHERE ip=?', (ip,)).fetchone())
        if self.cfg['mode'] == 'block':
            if not self.boot_provider().get('response_unlocked'):
                self.write('ACTION_FAILED', ip=ip, reason=reason, detail='Boot/application integrity is not healthy', **fields)
                return {'status':'integrity_observe_only','ip':ip}
            try:
                self.nft.verify_layout()
                self.nft.block(ip)
            except RuntimeError as exc:
                self.write('ACTION_FAILED', ip=ip, reason=reason, detail=str(exc), **fields)
                return {'status':'failed','ip':ip,'error':str(exc)}
            self.db.execute('INSERT OR IGNORE INTO blocks VALUES(?,?,?)', (ip, dt.datetime.now(dt.timezone.utc).isoformat(), reason))
            self.db.commit()
            self.write('block', ip=ip, reason=reason, restored=persisted, **fields)
            return {'status':'set_membership_confirmed','ip':ip,'persisted':True,'drop_rule_linked':True,
                    'scope':'incoming_and_outgoing_original','traffic_drop_verified':False}
        else:
            self.write('would_block', ip=ip, reason=reason, **fields)
            return {'status':'observe_only','ip':ip,'executed':False}

    def otx_confirms(self, pulses, reputation):
        # Audit K3: never one pulse. load_config enforces the same floors.
        return (pulses >= max(2, self.cfg['otx_min_pulses'])
                and reputation >= max(1, self.cfg['otx_min_reputation']))

    def otx_check(self, ip):
        if not self.api_key:
            return False
        now = time.time()
        cached = self.db.execute('SELECT ts, pulses, reputation, verdict FROM otx_cache WHERE ip=?', (ip,)).fetchone()
        if cached and now - cached[0] < self.cfg['otx_cache_hours'] * 3600:
            # Re-evaluate cached evidence under the current thresholds.
            return self.otx_confirms(cached[1], cached[2])
        while self.otx_requests and now - self.otx_requests[0] > 3600:
            self.otx_requests.popleft()
        if len(self.otx_requests) >= self.cfg['otx_max_checks_hour']:
            return False
        self.otx_requests.append(now)
        ip_obj = ipaddress.ip_address(ip)
        family = 'IPv4' if ip_obj.version == 4 else 'IPv6'
        url = f'https://otx.alienvault.com/api/v1/indicators/{family}/{ip}/general'
        req = urllib.request.Request(url, headers={'X-OTX-API-KEY': self.api_key, 'User-Agent': 'Satsuma-Guard/1.0'})
        try:
            with urllib.request.urlopen(req, timeout=4) as response:
                obj = json.load(response)
            pulses = int(obj.get('pulse_info', {}).get('count') or 0)
            reputation = float(obj.get('reputation') or 0)
            ok = self.otx_confirms(pulses, reputation)
            verdict = 'confirmed' if ok else 'not_confirmed'
            self.db.execute('INSERT OR REPLACE INTO otx_cache VALUES(?,?,?,?,?)', (ip, now, pulses, reputation, verdict))
            self.db.commit()
            self.write('otx_check', ip=ip, pulse_count=pulses, reputation=reputation, verdict=verdict)
            return ok
        except (urllib.error.URLError, ValueError, TypeError, TimeoutError, OSError) as exc:
            self.write('warning', component='otx', ip=ip, detail=str(exc)[:200])
            return False

    def egress_eligible(self, src, dst):
        """Select a remote IP only when an alert originated from this host."""
        if src not in self.own_ips:
            return False
        try:
            peer = ipaddress.ip_address(dst)
        except (ValueError, TypeError):
            return False
        if not peer.is_global or dst in self.own_ips:
            return False
        if any(peer in net for net in self.trusted if net.version == peer.version):
            return False
        if self.core_store is not None:
            if self.operator_allowed(dst):
                return False
            dns = self.core_store.get('dns_policy', {}) or {}
            resolvers = set(dns.get('expected_dns_servers', []) or [])
            upstream = dns.get('upstream')
            if upstream:
                resolvers.add(upstream)
            if dst in resolvers:
                return False
        return True

    def on_alert(self, alert):
        # One actionable Suricata signature is sufficient; OTX does not need
        # to corroborate it. The configured severity policy still applies.
        if not 1 <= alert['priority'] <= self.cfg['max_priority']:
            return
        src, dst = alert['source_ip'], alert['dest_ip']
        target = None
        direction = None
        if self.egress_eligible(src, dst):
            target, direction = dst, 'outbound_original'
        elif dst in self.own_ips and self.eligible(src, dst):
            # Audit K2: the source of a packet arriving here can be forged, so
            # it is blocked only when it belongs to a completed TCP connection,
            # either opened by the remote end or (a C2 server answering) by
            # this host. Anything unverified is recorded, never blocked.
            # Denetim K2: buraya gelen paketin kaynağı sahtelenebilir; yalnızca
            # tamamlanmış bir TCP bağlantısına aitse engellenir.
            try:
                verified = self.flow_checker(alert) or self.reply_checker(alert)
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                self.write('ACTION_UNSUPPORTED', ip=src, reason='connection_direction_unverified',
                           detail=str(exc), rule_id=alert.get('rule_id'))
                return
            if not verified:
                self.write('ACTION_UNSUPPORTED', ip=src, reason='connection_not_verified',
                           rule_id=alert.get('rule_id'))
                return
            target, direction = src, 'remote_to_local'
        elif self.eligible(src, dst):
            # For forwarded LAN destinations, preserve original conntrack
            # validation so a spoofed reply cannot ban an unrelated IP.
            try:
                incoming = self.flow_checker(alert)
            except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
                self.write('ACTION_UNSUPPORTED', ip=src, reason='connection_direction_unverified',
                           detail=str(exc), rule_id=alert.get('rule_id'))
                return
            if not incoming:
                self.write('ACTION_UNSUPPORTED', ip=src, reason='outbound_or_connection_direction_unverified',
                           rule_id=alert.get('rule_id'))
                return
            target, direction = src, 'inbound_forward_original'
        if target is None:
            return
        import uuid
        alert = {**alert, 'detection_id': uuid.uuid4().hex}
        self.write('suricata_alert', **alert)
        evidence_class=alert_evidence_class(alert)
        if evidence_class != 'attack_signature_candidate':
            self.write('would_block', ip=target, reason='engine_anomaly_requires_independent_attack_evidence' if evidence_class=='engine_anomaly' else 'unverified_signature_requires_review',
                       evidence_class=evidence_class, otx_role='reputation_not_attack_proof',
                       signature=alert.get('signature'),rule_id=alert.get('rule_id'),
                       detection_id=alert['detection_id'])
            return
        verification = None
        if direction in ('outbound_original', 'remote_to_local'):
            # A forged packet cannot open a socket here: act only when a live
            # local process owns the flow (and only then ask OTX).
            verification = self.verify_flow(alert)
            if verification is not None and verification['verdict'] != 'verified_live_process':
                self.write('would_block', ip=target, reason='alert_not_backed_by_live_process',
                           verification=verification, signature=alert.get('signature'),
                           rule_id=alert.get('rule_id'), detection_id=alert['detection_id'])
                return
        extra = {'verification': verification} if verification is not None else {}
        blocked = False
        if self.cfg['fast_block']:
            outcome = self.block(target, 'suricata_priority_' + str(alert['priority']), signature=alert['signature'],
                                 rule_id=alert.get('rule_id'), direction=direction,
                                 priority=alert['priority'], detection_id=alert['detection_id'], **extra)
            blocked = blocked or (outcome or {}).get('status') == 'set_membership_confirmed'
        if self.cfg['otx_enabled'] and self.otx_check(target):
            self.write('otx_confirmed', ip=target, source='suricata')
            outcome = self.block(target, 'otx_confirmed', pulse_policy=self.cfg['otx_match_mode'],
                                 direction=direction, detection_id=alert['detection_id'], **extra)
            blocked = blocked or (outcome or {}).get('status') == 'set_membership_confirmed'
        if verification is not None and verification.get('verdict') == 'verified_live_process':
            if blocked:
                self.cut_flow(alert)
            self.stop_process(alert, verification)
        elif not self.cfg['fast_block']:
            self.write('would_block', ip=target, reason='automatic_block_not_authorized',
                       detection_id=alert['detection_id'])

    def established_peers(self):
        """Public remote address -> [(local ip, local port, remote port)] for established TCP."""
        from satsuma.procnet import read_all
        peers = {}
        for sock in read_all():
            if sock['proto'] != 'tcp' or sock['state'] != '01':
                continue
            local, remote = sock['local'], sock['remote']
            host = getattr(remote[0], 'ipv4_mapped', None) or remote[0]
            near = getattr(local[0], 'ipv4_mapped', None) or local[0]
            peers.setdefault(str(host), []).append((str(near), local[1], remote[1]))
        return peers

    def check_otx_connections(self, peers=None, killer=None):
        """Destroy established connections to peers OTX confirms as malicious."""
        if not (self.cfg['otx_connection_kill'] and self.cfg['otx_enabled'] and self.api_key):
            return []
        if killer is None:
            from satsuma.connection_kill import kill_connection as killer
        peers = self.established_peers() if peers is None else peers
        if self.core_store is not None:
            runtime = self.core_store.get('integrity_runtime', {}) or {}
            if runtime.get('status') not in (None, 'HEALTHY'):
                return []
        results = []
        budget = self.cfg['otx_lookups_per_poll']
        horizon = time.time() - self.cfg['otx_cache_hours'] * 3600
        for ip, connections in sorted(peers.items()):
            try:
                if not connections or not self.eligible(ip, connections[0][0]):
                    continue
            except ValueError:
                continue
            cached = self.db.execute('SELECT 1 FROM otx_cache WHERE ip=? AND ts>?', (ip, horizon)).fetchone()
            if not cached:
                if budget <= 0:
                    continue  # the hourly OTX budget is spread over later polls
                budget -= 1
            if not self.otx_check(ip):
                continue
            for local_ip, local_port, remote_port in connections:
                if self.cfg['mode'] != 'block' or not self.boot_provider().get('response_unlocked'):
                    self.write('would_block', ip=ip, reason='otx_connection_observe_only',
                               local_port=local_port, remote_port=remote_port)
                    continue
                report = killer(local_ip, local_port, ip, remote_port, 'tcp')
                results.append(report)
                self.write('otx_connection_kill', ip=ip, local_port=local_port, remote_port=remote_port,
                           terminated=report.get('terminated') is True, verified=report.get('verified') is True,
                           reason=report.get('reason'))
        return results

    def support_ips(self):
        """Addresses recently resolved from a remote-support domain (TeamViewer, AnyDesk)."""
        if self.core_store is None:
            return set()
        try:
            from satsuma.otx import remote_support_ips
            return remote_support_ips(self.core_store)
        except Exception:
            return set()

    def check_peers(self):
        """Fixed rule: a no-PTR peer making a 6th connection in one visit is blocked now."""
        from satsuma.peer_watch import THRESHOLD
        decisions = self.peers.poll()
        for item in decisions:
            fields = {'rule': item['rule'], 'ptr': item['ptr'], 'threshold': item['threshold'],
                      'connections_in_visit': item['connections_in_visit'],
                      'processes': [{k: p.get(k) for k in ('pid', 'exe', 'parent_exe')} for p in item['processes']],
                      'memory_verification': item['memory_verification']}
            outcome = self.block(item['ip'], 'no_ptr_connection_flood', **fields)
            if outcome.get('status') == 'set_membership_confirmed':
                from satsuma.connection_kill import kill_connection
                for local_ip, local_port, remote_port in item['connections']:
                    report = kill_connection(local_ip, local_port, item['ip'], remote_port, 'tcp')
                    self.write('otx_connection_kill', ip=item['ip'], local_port=local_port, remote_port=remote_port,
                               terminated=report.get('terminated') is True, verified=report.get('verified') is True,
                               reason=report.get('reason') or 'no_ptr_connection_flood')
        watching = self.peers.watchlist()
        if watching != self.watch_logged:
            self.watch_logged = dict(watching)
            if self.core_store is not None:
                self.core_store.set('ptr_watchlist', {'timestamp': time.time(), 'peers': watching,
                                                      'threshold': THRESHOLD})
        return decisions

    def verify_flow(self, alert):
        """Verification summary for an alert, or None when no verifier is configured."""
        verifier = getattr(self, 'alert_verifier', None)
        if verifier is None:
            return None
        report = verifier(alert)
        return {'verdict': report['verdict'], 'dns_backed': report.get('dns_backed', False),
                'dns_domains': report.get('dns_domains', []),
                'initiated_locally': report.get('initiated_locally', False),
                'local_port': report.get('local_port'),
                'processes': [{k: p.get(k) for k in ('pid', 'exe', 'parent_exe', 'starttime')}
                              for p in report.get('processes', [])]}

    def stop_process(self, alert, verification, process_response=None):
        """Stop the one local program that started a flow behind a top-priority attack alert.

        Only for a verified live process that started the connection itself;
        a program that serves a connection is never stopped for what a remote
        peer sends it. The decision goes through AutoActionEngine, so the
        authorization gate, the protected-program exemptions (Satsuma,
        TeamViewer, AnyDesk, system services), the integrity lock and privd
        all apply.
        """
        limit = self.cfg['process_stop_max_priority']
        if (self.core_store is None or self.cfg['mode'] != 'block' or not 1 <= alert['priority'] <= limit
                or verification is None or verification.get('verdict') != 'verified_live_process'
                or verification.get('initiated_locally') is not True
                or len(verification.get('processes', [])) != 1):
            return None
        process = verification['processes'][0]
        if type(process.get('starttime')) is not int or not process.get('exe'):
            return None
        from satsuma.auto_action import AutoActionEngine
        config = self.process_config()
        finding = {'finding_id': 'guard-' + str(alert.get('detection_id')), 'rule_id': 'SATSUMA-GUARD-NET-001',
                   'type': 'suricata_attack_signature_from_live_local_process', 'severity': 'high',
                   'confidence': 'medium', 'classification': 'suspicious',
                   'summary': 'Suricata attack signature on a connection started by a live local program: '
                              + str(alert.get('signature'))[:200],
                   'event': {'pid': process['pid'], 'starttime': process['starttime'], 'exe': process['exe'],
                             'timestamp': time.time(), 'source': 'suricata',
                             'signature': alert.get('signature'), 'signature_id': alert.get('rule_id'),
                             'remote_ip': alert.get('dest_ip') if alert.get('source_ip') in self.own_ips
                             else alert.get('source_ip')}}
        engine = AutoActionEngine(self.core_store, config, response=process_response)
        outcome = (engine.process(finding) or {}).get('process_response') or {}
        self.write('process_stop', pid=process['pid'], exe=process['exe'], status=outcome.get('status'),
                   signal_sent=outcome.get('signal_sent') is True, exit_verified=outcome.get('exit_verified') is True,
                   reasons=outcome.get('reasons'), detection_id=alert.get('detection_id'),
                   rule_id=alert.get('rule_id'))
        return outcome

    def process_config(self):
        from satsuma.config import load_with_policy
        return load_with_policy()[0]

    def cut_flow(self, alert, killer=None):
        """Destroy the one connection behind a verified alert; the address block alone leaves it open."""
        if killer is None:
            from satsuma.connection_kill import kill_connection as killer
        report = killer(alert['source_ip'], alert.get('source_port'), alert['dest_ip'], alert.get('dest_port'), 'tcp')
        self.write('otx_connection_kill', ip=alert['dest_ip'] if alert['source_ip'] in self.own_ips else alert['source_ip'],
                   local_port=alert.get('source_port'), remote_port=alert.get('dest_port'),
                   terminated=report.get('terminated') is True, verified=report.get('verified') is True,
                   reason=report.get('reason') or 'verified_suricata_alert')
        return report

    def check_connections(self):
        if not self.cfg['subnet_enabled']:
            return
        if not shutil.which('conntrack'):
            self.write('warning', component='conntrack', detail='conntrack executable missing; subnet detection unavailable')
            return
        try:
            r = command(['conntrack', '-L', '-f', 'ipv4'])
        except (subprocess.TimeoutExpired, OSError) as exc:
            self.write('warning', component='conntrack', detail=str(exc)[:200])
            return
        if r.returncode:
            self.write('warning', component='conntrack', detail=r.stderr[:200])
            return
        peers = set()
        for src, dst in parse_conntrack(r.stdout):
            if self.eligible(src, dst):
                peers.add(src)
        now = time.time()
        # Count sequential distinct IPs, even when their connections have
        # already closed. Each observation expires after five minutes.
        self.recent_peers = {ip: seen for ip, seen in self.recent_peers.items()
                             if 0 <= now - seen < 300}
        if self.previous_peers is None:
            self.previous_peers = peers
            self.recent_peers.update({ip: now for ip in peers})
            self.write('subnet_baseline', active_peers=len(peers))
            return
        newcomers = peers - self.previous_peers
        self.previous_peers = peers
        for peer in newcomers:
            self.recent_peers[peer] = now
        subnet_members = collections.defaultdict(set)
        for peer in self.recent_peers:
            subnet = str(ipaddress.ip_network(f'{peer}/{self.cfg["subnet_prefix"]}', strict=False))
            subnet_members[subnet].add(peer)
        for peer in sorted(newcomers):
            subnet = str(ipaddress.ip_network(f'{peer}/{self.cfg["subnet_prefix"]}', strict=False))
            count = len(subnet_members[subnet])
            if count >= self.cfg['subnet_threshold']:
                # The distinct-peer condition alone triggers; block the
                # newcomer, not every peer or the whole CIDR network.
                self.block(peer, 'subnet_threshold', subnet=subnet, active_distinct=count,
                           window_seconds=300)

    def source(self):
        opt = self.cfg['input']
        if opt == 'fast':
            return self.cfg['fast_log'], 'fast'
        if opt == 'eve':
            return self.cfg['eve_json'], 'eve'
        fast = pathlib.Path(self.cfg['fast_log'])
        eve = pathlib.Path(self.cfg['eve_json'])
        if fast.is_file():
            return str(fast), 'fast'
        return str(eve), 'eve'

    def follow(self, once=False):
        fp = None
        open_path = None
        inode = None
        offset = 0
        initial_open = True
        skipping = False
        next_conn = time.monotonic()
        next_peer = time.monotonic()
        next_checkpoint = time.monotonic() + 2
        while not STOP:
            path, source = self.source()
            try:
                stat = os.stat(path)
            except FileNotFoundError:
                self.heartbeat('DEGRADED', error='Suricata input file missing')
                if not once:
                    time.sleep(2)
                    continue
                self.write('warning', detail=f'Input file not found: {path}')
                break
            key = (stat.st_dev, stat.st_ino)
            if fp is None or open_path != path or inode != key or stat.st_size < offset:
                if fp:
                    fp.close()
                fp = self.opener(path)
                opened = os.fstat(fp.fileno())
                key = (opened.st_dev, opened.st_ino)
                open_path, inode = path, key
                saved = self.db.execute('SELECT dev, inode, offset FROM offsets WHERE path=?', (path,)).fetchone()
                if saved and (saved[0], saved[1]) == key and saved[2] <= opened.st_size:
                    offset = saved[2]
                elif self.cfg['start_at_end'] and not once and initial_open and not saved:
                    fp.seek(0, os.SEEK_END)
                    offset = fp.tell()
                else:
                    offset = 0
                fp.seek(offset)
                initial_open = False
                skipping = False
                self.write('input_open', file=path, start_offset=offset, parser=source)
            if hasattr(fp, 'satsuma_writer_uid'):
                from satsuma.source_guard import validate_stat
                validate_stat(os.fstat(fp.fileno()), fp.satsuma_writer_uid)
            line_start = fp.tell()
            line = fp.readline(65537)
            if line:
                if skipping or len(line) > 65536:
                    skipping = not line.endswith(b'\n')
                    offset = fp.tell()
                    self.write('warning', detail='Oversized Suricata log line discarded')
                    continue
                if not line.endswith(b'\n'):
                    fp.seek(line_start)
                    offset = line_start
                    if once:
                        break
                    time.sleep(0.5)
                    continue
                offset = fp.tell()
                alert = parse_alert(line.decode('utf-8', errors='replace'), source)
                if alert:
                    self.on_alert(alert)
            else:
                if once:
                    break
                time.sleep(0.5)
            now = time.monotonic()
            if now >= next_peer:
                try:
                    self.release_allowed()
                    self.check_peers()
                except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
                    self.write('warning', component='peer_watch', detail=str(exc)[:200])
                next_peer = now + self.cfg['peer_poll_seconds']
            if now >= next_conn:
                self.check_connections()
                try:
                    self.check_otx_connections()
                except (OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
                    self.write('warning', component='otx_connection_kill', detail=str(exc)[:200])
                next_conn = now + self.cfg['conntrack_poll_seconds']
            if now >= next_checkpoint:
                self.heartbeat()
                self.db.execute('INSERT OR REPLACE INTO offsets VALUES(?,?,?,?)', (path, key[0], key[1], offset))
                self.db.commit()
                next_checkpoint = now + 2
        if fp:
            self.db.execute('INSERT OR REPLACE INTO offsets VALUES(?,?,?,?)', (open_path, inode[0], inode[1], offset))
            self.db.commit()
            fp.close()
        self.events.close()
        self.db.close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', default=DEFAULT_CONFIG)
    sub = p.add_subparsers(dest='action', required=True)
    for name in ('run', 'once', 'check', 'status'):
        sub.add_parser(name)
    up = sub.add_parser('unblock')
    up.add_argument('ip')
    args = p.parse_args()
    cfg = get_config(args.config)
    if args.action == 'check':
        path = cfg['fast_log'] if cfg['input'] == 'fast' or (cfg['input'] == 'auto' and os.path.isfile(cfg['fast_log'])) else cfg['eve_json']
        report = {'valid_config': True, 'mode': cfg['mode'], 'input_found': os.path.isfile(path),
                  'input_file': path, 'nft_found': bool(shutil.which('nft')),
                  'conntrack_found': bool(shutil.which('conntrack')),
                  'otx_key_found': os.path.isfile(cfg['otx_api_key_file'])}
        print(json.dumps(report, indent=2))
        # A missing conntrack tool degrades forwarded/subnet decisions, but
        # must not disable direct host Suricata response.
        if not report['input_found'] or (cfg['mode']=='block' and not report['nft_found']):
            raise RuntimeError('Suricata response prerequisites unavailable')
        with verified_log(path):
            pass
        return
    if args.action == 'status':
        dbpath = pathlib.Path(cfg['state_dir']) / 'guard.sqlite'
        if not dbpath.exists():
            print('No state database yet')
            return
        db = sqlite3.connect(f'file:{dbpath}?mode=ro', uri=True)
        print('Configured mode:', cfg['mode'])
        print('Blocks in state DB:', db.execute('SELECT count(*) FROM blocks').fetchone()[0])
        print('Recent blocks:')
        for row in db.execute('SELECT ip, ts, reason FROM blocks ORDER BY ts DESC LIMIT 25'):
            print(' | '.join(row))
        db.close()
        return
    if args.action == 'unblock':
        ip = str(ipaddress.ip_address(args.ip))
        # Unblock even if config was switched back to observe mode;
        # old nft rules may still be active until explicitly removed.
        try:
            Nft().unblock(ip)
        except RuntimeError as exc:
            if 'No such file' not in str(exc) and 'No such table' not in str(exc):
                raise
        dbpath = pathlib.Path(cfg['state_dir']) / 'guard.sqlite'
        if dbpath.exists():
            db = sqlite3.connect(str(dbpath))
            db.execute('DELETE FROM blocks WHERE ip=?', (ip,))
            db.commit()
            db.close()
        print('Unblocked / removed from persistence:', ip)
        return
    if os.geteuid() != 0:
        raise SystemExit('run/once requires root to read Suricata files and conntrack')
    signal.signal(signal.SIGINT, stopped)
    signal.signal(signal.SIGTERM, stopped)
    from satsuma.self_guard import verify
    from satsuma.store import Store
    from satsuma.protected_storage import open_directory
    verify()
    directory = open_directory(pathlib.Path(cfg['state_dir']))
    os.close(directory)
    store = Store()
    try:
        guard = Guard(cfg, core_store=store)
        guard.follow(once=args.action == 'once')
    finally:
        store.close()


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, RuntimeError, sqlite3.Error) as err:
        print('ERROR:', err, file=sys.stderr)
        sys.exit(1)
