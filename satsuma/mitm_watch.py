"""Man-in-the-middle watch: DNS, routes, network profiles, kernel settings, remote access.

Runs every minute as root (satsuma-mitm-watch.timer), and once more in
every security scan and in satsuma-admin tam-kontrol. The checks come from
the yeni-yazim branch (user decision 2026-10-26):

- dns_watch: resolv.conf, the servers in use, and the DNS filter's
  upstream against the pinned servers (OpenDNS by default);
- route_watch: routes and policy rules that redirect loopback or DNS
  traffic, and a changed default route;
- nm_profiles: NetworkManager profiles with a VPN, proxy, static route
  or DNS servers of their own; a profile added since the last check;
- kernel_net: route_localnet, rp_filter, source routing, ICMP redirects.
  A changed value is written back at once and reported;
- remote_access: remote access servers (SSH, VNC, RDP, TeamViewer,
  AnyDesk...) accepting connections from other machines, listeners run
  from /tmp, /home or memfd, and AnyDesk's incoming-session settings.

Everything else is reported, never changed: a finding is written to the
host findings (SATSUMA-MITM-*) and marked CLEARED when the condition is
gone. Events (a changed upstream, default route or kernel setting) stay.
Info-level results (every profile, every exposed listener) are kept in
the state for the dashboard only. While a Satsuma WireGuard profile
(satsuma.wireguard) is active, its own policy rule (fwmark table) is
expected, and its NetworkManager profile is never reported as added.

Ortadaki adam izleyicisi: DNS, rotalar, ağ profilleri, çekirdek ayarları,
uzak erişim. Her dakika root olarak çalışır (satsuma-mitm-watch.timer);
ayrıca her güvenlik taramasında ve tam-kontrol komutunda. Denetimler
yeni-yazim dalından alındı. Değişen çekirdek ayarı hemen geri yazılır ve
bildirilir; geri kalan her şey yalnızca bildirilir, değiştirilmez. Bulgu
ana makine bulgularına (SATSUMA-MITM-*) yazılır, durum düzelince CLEARED
olarak işaretlenir; olaylar (değişen üst sunucu, varsayılan rota, çekirdek
ayarı) kalır. Bilgi düzeyindeki sonuçlar yalnızca durum kaydında tutulur.
Bir Satsuma WireGuard profili (satsuma.wireguard) etkinken kendi politika
kuralı (fwmark tablosu) beklenen durumdur; NetworkManager profili de "yeni
profil eklendi" olarak bildirilmez.
"""
import hashlib
import json
import os
import time

from . import dns_watch, kernel_net, nm_profiles, procnet, remote_access, route_watch

INFO = 'info'
EVENTS = {'dns_upstream_changed', 'default_route_changed', 'kernel_setting_changed', 'network_profile_added'}
TEXT = {
    'resolv_conf_unexpected_link': ('resolv.conf beklenmeyen bir dosyaya bağlanmış',
                                    'DNS ayarı başka bir dosyadan okunuyor. Siz yapmadıysanız inceleyin.'),
    'resolv_conf_missing': ('resolv.conf okunamıyor', 'Ad çözümleme çalışmayabilir; NetworkManager durumunu inceleyin.'),
    'resolv_conf_writable': ('resolv.conf dosyasına root dışında yazılabiliyor',
                             'Bir program DNS sunucusunu değiştirebilir. Düzeltmek için: sudo chown root:root /etc/resolv.conf'
                             ' && sudo chmod 644 /etc/resolv.conf'),
    'resolv_conf_immutable': ('resolv.conf kilitli (chattr +i)', 'Yeni ağın DNS ayarı uygulanamaz.'),
    'dns_config_invalid': ('DNS sabitleme dosyası geçersiz', '/etc/satsuma-core/dns-pinned.json dosyasını inceleyin.'),
    'dns_upstream_invalid': ('DNS filtresinin üst sunucusu geçersiz', 'Panelden DNS filtresinin üst sunucusunu yeniden seçin.'),
    'dns_upstream_not_pinned': ('DNS filtresi sabitlenmemiş bir sunucuya soruyor',
                                'Panelden DNS filtresinin üst sunucusunu sabitlenen sunuculardan biri yapın.'),
    'dns_server_not_from_networkmanager': ('NetworkManager\'ın bilmediği DNS sunucusu',
                                           'Sunucu resolv.conf dosyasına elle ya da bir programla yazılmış. '
                                           'Siz yazmadıysanız ortadaki adam saldırısı olabilir.'),
    'dns_upstream_changed': ('DNS filtresinin üst sunucusu değişti',
                             'Bu değişikliği siz yapmadıysanız DNS ayarınız ele geçirilmiş olabilir.'),
    'loopback_route_off_lo': ('Loopback trafiği gerçek bir arayüze yönlendirilmiş',
                              'Yerel servisler dışarıdan erişilebilir olabilir. Siz eklemediyseniz rotayı inceleyin: ip route show table all'),
    'local_route_for_foreign_address': ('Başka bir sunucunun adresi bu makineye yönlendirilmiş',
                                        'O sunucuya giden bağlantılar burada dinleyen bir programa gider. '
                                        'Siz eklemediyseniz saldırı belirtisidir: ip route show table local'),
    'dns_resolver_route': ('DNS sunucusuna özel rota var',
                           'DNS sorguları başka bir ağ geçidine gidiyor. Siz eklemediyseniz ortadaki adam saldırısı olabilir.'),
    'dns_resolver_blocked': ('DNS sunucusu rota ile engellenmiş', 'Bilgi.'),
    'extra_policy_rule': ('Fazladan yönlendirme kuralı (ip rule)',
                          'Trafik başka bir tabloya gönderiliyor. VPN kullanmıyorsanız inceleyin: ip rule show'),
    'default_route_changed': ('Varsayılan rota değişti',
                              'İnternete çıkış başka bir ağ geçidinden yapılıyor. Ağ değiştirmediyseniz inceleyin.'),
    'network_profile_tunnel': ('Ağ profili: VPN / tünel',
                               'Trafik bu tünelden geçebilir. Siz kurmadıysanız NetworkManager\'dan silin.'),
    'network_profile_proxy': ('Ağ profili: proxy tanımlı',
                              'Trafik bir proxy\'den geçiyor. Siz tanımlamadıysanız NetworkManager ayarından kaldırın.'),
    'network_profile_routes': ('Ağ profili: sabit rota tanımlı',
                               'Siz tanımlamadıysanız NetworkManager ayarından kaldırın.'),
    'network_profile_added': ('Yeni ağ profili eklendi', 'Siz eklemediyseniz inceleyin: nmcli connection show'),
    'kernel_setting_changed': ('Çekirdek ağ ayarı değiştirilmiş',
                               'Satsuma değeri güvenli olana geri yazdı. Siz değiştirmediyseniz bir program ağ korumasını gevşetmeye çalıştı.'),
    'remote_access_listener': ('Uzak erişim sunucusu dışarıdan bağlantı kabul ediyor',
                               'Bu bilgisayara dışarıdan bağlanılmamalı. Programın gelen bağlantı ayarını kapatın '
                               '(SSH için: sudo satsuma-admin ssh sunucu-kapat).'),
    'exposed_listener': ('Şüpheli konumdan çalışan program dışarıyı dinliyor',
                         'Program /tmp, /home, bellek ya da silinmiş bir dosyadan çalışıyor. Tanımıyorsanız karantinaya alın.'),
    'anydesk_config_missing': ('AnyDesk gelen oturum ayarı bulunamadı',
                               'AnyDesk ayarlarından gelen oturumları ve gözetimsiz erişimi kapatın.'),
    'anydesk_incoming_allowed': ('AnyDesk gelen oturumlara izin veriyor olabilir',
                                 'AnyDesk ayarlarından gelen oturum isteklerini ve gözetimsiz erişimi kapatın.'),
    'anydesk_unattended_password': ('AnyDesk gözetimsiz erişim parolası tanımlı',
                                    'Bu parola ile dışarıdan izinsiz bağlanılabilir. AnyDesk ayarlarından kaldırın.'),
}
SEVERITY_CLASS = {'critical': 'likely', 'high': 'suspicious', 'medium': 'indicator', 'low': 'indicator'}


def _subject(item):
    keep = {k: v for k, v in item.items() if k not in ('severity', 'note')}
    return hashlib.sha256(json.dumps(keep, sort_keys=True, default=str).encode()).hexdigest()[:20]


def _summary(item):
    parts = []
    for key in ('server', 'before', 'after', 'target', 'profile', 'family', 'routes', 'key', 'actual', 'expected',
                'service', 'address', 'port', 'exe', 'method', 'route', 'rule', 'resolvers', 'error'):
        if item.get(key) not in (None, '', [], {}):
            parts.append(f'{key}: {json.dumps(item[key], ensure_ascii=False, default=str)[:200]}')
    return ' · '.join(parts)[:600]


def collect(core_state, previous, runner=None, as_root=None, dns=dns_watch.findings, kernel=kernel_net,
            listeners=procnet.exposed_listeners, anydesk=remote_access.anydesk_findings,
            profiles=nm_profiles.read_profiles, snapshot=route_watch.snapshot, own=route_watch.local_addresses):
    """All checks once; returns (findings, state). previous: the last state."""
    import subprocess
    runner = runner or subprocess.run
    as_root = os.geteuid() == 0 if as_root is None else as_root
    found, unavailable = [], []
    upstream = (core_state.get('dns_policy') or {}).get('upstream')
    try:
        pinned = dns_watch.pinned_servers()
    except (OSError, ValueError):
        pinned = frozenset()  # reported by the DNS check
    found += dns(upstream=upstream, previous_upstream=previous.get('upstream'))
    resolvers = set(pinned)
    try:
        if upstream:
            import ipaddress
            resolvers.add(ipaddress.ip_address(upstream))
    except ValueError:
        pass
    snap = snapshot(runner)
    unavailable += snap.get('unavailable', [])
    addresses = own(runner)
    if addresses is None:
        unavailable.append('ip address show')
    else:
        expected_tables = set(core_state.get('wireguard_tables') or ())
        found += [f for f in route_watch.inspect(snap, addresses, resolvers)
                  if not (f['code'] == 'extra_policy_rule' and str((f.get('rule') or {}).get('table')) in expected_tables)]
    defaults = route_watch._default_routes(snap)
    if previous.get('default_routes') is not None and previous['default_routes'] != defaults and snap['routes']:
        found.append({'code': 'default_route_changed', 'severity': 'medium',
                      'before': previous['default_routes'], 'after': defaults})
    profile_list = profiles(runner)
    inventory = []
    if profile_list is None:
        unavailable.append('nmcli connection show')
    else:
        for profile in profile_list:
            # Port 53 goes to the DNS filter: a profile's own DNS servers are
            # not judged against the pinned set; routes over them still are.
            found += nm_profiles.audit(profile, frozenset(), set(route_watch.PUBLIC_RESOLVERS) | set(pinned))
        inventory = sorted({(p.get('connection.uuid') or '', p.get('connection.id') or '', p.get('connection.type') or '')
                            for p in profile_list})
        known = {row[0] for row in previous.get('profiles', [])}
        if previous.get('profiles') is not None:
            own = set(core_state.get('wireguard_profiles') or ())
            for uuid, name, kind in inventory:
                if uuid not in known and not (kind == 'wireguard' and name in own):
                    found.append({'code': 'network_profile_added', 'severity': 'medium', 'profile': name,
                                  'uuid': uuid, 'type': kind})
    drift = kernel.drift()
    restored = kernel.restore() if as_root and drift else {'restored': [], 'failed': drift}
    first = not previous
    if not first:
        for item in drift:
            done = any(r['key'] == item['key'] for r in restored['restored'])
            found.append({'code': 'kernel_setting_changed', 'severity': 'high', **item,
                          'restored': done})
    exposed = listeners()
    for item in remote_access.listener_findings(exposed):
        found.append(item)
    found += anydesk()
    state = {'updated_at': time.time(), 'upstream': upstream, 'pinned': sorted(str(a) for a in pinned),
             'default_routes': defaults if snap['routes'] else previous.get('default_routes'),
             'profiles': [list(row) for row in inventory] if profile_list is not None else previous.get('profiles'),
             'listeners': [{k: l[k] for k in ('proto', 'address', 'port')} | {'exe': (l['process'] or {}).get('exe')}
                           for l in exposed][:200],
             'kernel': {'drift': len(drift), 'restored': len(restored['restored']), 'failed': restored['failed'][:20],
                        'first_apply': first and bool(drift)},
             'unavailable': unavailable}
    return found, state


def record(store, found, now=None):
    """Write findings to the host store; clear the ones that are gone."""
    now = now or time.time()
    current = set()
    for item in found:
        if item.get('severity') == INFO:
            continue
        code = item['code']
        ident = f'SATSUMA-MITM-{code.upper()}:{_subject(item)}'
        current.add(ident)
        title, advice = TEXT.get(code, (code, ''))
        if code == 'kernel_setting_changed' and not item.get('restored'):
            advice = 'Değer geri yazılamadı: ' + str(item.get('error') or 'yetki yok') + '. sudo satsuma-admin tam-kontrol çalıştırın.'
        body = {'finding_id': ident, 'rule_id': 'SATSUMA-MITM-' + code.upper(), 'timestamp': now,
                'severity': item['severity'], 'classification': SEVERITY_CLASS.get(item['severity'], 'indicator'),
                'source': 'mitm_watch', 'title': title, 'summary': _summary(item), 'advice': advice,
                'item': item, 'status': 'REVIEW'}
        row = store.db.execute('SELECT body FROM findings WHERE finding_id=?', (ident,)).fetchone()
        if row is None:
            store.db.execute('INSERT INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                             (ident, now, json.dumps(body, ensure_ascii=False, default=str)))
        elif json.loads(row[0]).get('status') == 'CLEARED':
            store.db.execute('UPDATE findings SET last_seen=?, body=? WHERE finding_id=?',
                             (now, json.dumps({**body, 'reopened': True}, ensure_ascii=False, default=str), ident))
        else:
            store.db.execute('UPDATE findings SET last_seen=? WHERE finding_id=?', (now, ident))
    for ident, body in store.db.execute("SELECT finding_id, body FROM findings WHERE finding_id LIKE 'SATSUMA-MITM-%'").fetchall():
        data = json.loads(body)
        code = (data.get('item') or {}).get('code')
        if ident not in current and code not in EVENTS and data.get('status') != 'CLEARED':
            data.update(status='CLEARED', cleared='Son denetimde bu durum yok.')
            store.db.execute('UPDATE findings SET body=? WHERE finding_id=?', (json.dumps(data, ensure_ascii=False), ident))
    store.db.commit()
    return current


def run(host, core, **kwargs):
    """One check: findings into the host store, state under 'mitm_watch'."""
    previous = host.get('mitm_watch', {}) or {}
    core_state = {'dns_policy': core.get('dns_policy', {}) or {}}
    try:
        from . import wireguard
        profiles = core.get(wireguard.STATE_KEY, {}) or {}
        core_state['wireguard_profiles'] = sorted(profiles)
        if profiles:
            if wireguard.active_managed(core, kwargs.get('runner') or __import__('subprocess').run):
                # The policy rule of an active Satsuma profile is expected, not interception.
                core_state['wireguard_tables'] = [str(wireguard.FWMARK)]
    except Exception as exc:
        try:
            core.add('errors', {'component': 'wireguard_sync', 'error': str(exc)[:200], 'timestamp': time.time()})
        except Exception:
            pass
    found, state = collect(core_state, previous, **kwargs)
    active = record(host, found)
    state['active'] = len(active)
    state['counts'] = {sev: sum(1 for f in found if f.get('severity') == sev)
                       for sev in ('critical', 'high', 'medium')}
    host.set('mitm_watch', state)
    return state


def main():
    from .host_store import HostStore
    from .store import Store
    host, core = HostStore(), Store()
    try:
        state = run(host, core)
    finally:
        host.close()
        core.close()
    print(json.dumps({k: state[k] for k in ('counts', 'active', 'unavailable')}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
