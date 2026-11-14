"""Verify that an alert comes from a live local process, not from a forged packet.

An outsider can forge packets and make Suricata raise alerts, but cannot open
a socket inside this machine. An alert is therefore acted on only when its
flow belongs to a process that is really running: the flow is found in the
PeerWatch window or read from /proc right now, a process holds its socket, and
that process's memory can be read (satsuma.peer_watch.verify_live). Satsuma's
own DNS records (kind 'dns') are added as context: which domain this host
asked for that address. An address with no DNS record is reported, because a
program that connects to a bare address is worth a second look.

Verdicts: verified_live_process, flow_without_live_process,
unverified_possible_forgery. Only the first lets the caller act.

initiated_locally says whether the local program started the connection (its
local port is not one this host listens on). A program that merely serves a
connection must never be stopped because of what a remote peer sends it, or
an attacker could kill local services with a crafted payload.

Uyarının sahte paketten değil, canlı bir yerel süreçten geldiğini doğrular.

Dışarıdaki biri paket sahteleyip Suricata'ya uyarı ürettirebilir, ama bu
makinenin içinde soket açamaz. Bu yüzden uyarı yalnızca akışı gerçekten çalışan
bir sürece aitse işleme alınır: akış PeerWatch penceresinde bulunur ya da şu an
/proc'tan okunur, soketini bir süreç tutar ve o sürecin belleği okunabilir
(satsuma.peer_watch.verify_live). Satsuma'nın kendi DNS kayıtları ('dns' türü)
bağlam olarak eklenir: bu makine o adres için hangi alan adını sordu. DNS kaydı
olmayan adres bildirilir; çıplak adrese bağlanan program ikinci bir bakışı hak
eder.

Kararlar: verified_live_process, flow_without_live_process,
unverified_possible_forgery. Yalnızca ilki çağırana işlem yapma izni verir.

initiated_locally, bağlantıyı yerel programın başlatıp başlatmadığını söyler
(yerel portu bu makinenin dinlediği bir port değildir). Bağlantıyı yalnızca
sunan bir program, uzak ucun ona gönderdiği şey yüzünden asla durdurulmamalıdır;
yoksa saldırgan hazırlanmış bir yükle yerel servisleri öldürtebilirdi.
"""
import json

from . import peer_watch


def dns_names_for(store, ip, limit=2000):
    """Domains Satsuma's DNS records resolved to this address."""
    names = set()
    if store is None:
        return names
    try:
        rows = store.db.execute("SELECT body FROM records WHERE kind='dns' ORDER BY id DESC LIMIT ?",
                                (limit,)).fetchall()
    except Exception:
        return names
    for (body,) in rows:
        try:
            item = json.loads(body)
        except (ValueError, TypeError):
            continue
        if isinstance(item, dict) and ip in [str(v) for v in item.get('ips') or []]:
            name = str(item.get('query') or '').rstrip('.').lower()
            if name:
                names.add(name)
    return names


def _live_flow(src_ip, src_port, dst_ip, dst_port, proc):
    """The flow read from /proc right now: (process identities, local port), or None if absent."""
    wanted = {(str(src_ip), int(src_port), str(dst_ip), int(dst_port)),
              (str(dst_ip), int(dst_port), str(src_ip), int(src_port))}
    for item in peer_watch.read_connections(proc, public_only=False):
        if (item['local'], item['local_port'], item['remote'], item['remote_port']) in wanted:
            holders = peer_watch.holders_for({item['inode']}, proc).get(item['inode'], set())
            return [peer_watch.process_identity(pid, proc) for pid in sorted(holders)], item['local_port']
    return None


def verify_alert(alert, watch=None, store=None, proc='/proc', verifier=peer_watch.verify_live):
    """Verdict, the processes behind the flow and the domains DNS recorded for the peer."""
    src, dst = alert.get('source_ip'), alert.get('dest_ip')
    sport, dport = alert.get('source_port'), alert.get('dest_port')
    report = {'verdict': 'unverified_possible_forgery', 'processes': [], 'memory_verification': [],
              'dns_domains': [], 'dns_backed': False, 'flow_seen': False,
              'local_port': None, 'initiated_locally': False}
    try:
        found = watch.flow_local(src, sport, dst, dport) if watch is not None else None
        if not found or not found[0]:
            live = _live_flow(src, sport, dst, dport, proc)
            found = live if live is not None else found
        listening = peer_watch.listening_ports(proc)
    except (OSError, ValueError, TypeError):
        return report
    if found is None:
        return report
    identities, local_port = found
    report['local_port'] = local_port
    report['initiated_locally'] = (str(alert.get('protocol', 'TCP')).upper() == 'TCP'
                                   and local_port is not None and local_port not in listening)
    report['flow_seen'] = True
    report['processes'] = identities
    report['memory_verification'] = [verifier(p['pid']) for p in identities]
    report['verdict'] = ('verified_live_process'
                         if any(v.get('live') for v in report['memory_verification'])
                         else 'flow_without_live_process')
    peers = {str(src), str(dst)}
    domains = set()
    for peer in peers:
        domains |= dns_names_for(store, peer)
    report['dns_domains'] = sorted(domains)
    report['dns_backed'] = bool(domains)
    return report
