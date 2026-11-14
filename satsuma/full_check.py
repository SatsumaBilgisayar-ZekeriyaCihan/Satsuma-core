"""Full check: is every Satsuma function on and running? Fix what is off.

Run by ``satsuma-admin tam-kontrol`` (and by release/<version>/yama.sh after
an upgrade). With ``fix`` it first switches back on every dashboard toggle
that is off (automatic blocking, automatic network blocking, OTX lookups and
blocking, subnet protection), lifts an operator pause and enrolls the modem
when exactly one is visible. Then it reports each item as TAMAM or SORUN
with the reason, so nothing is left silently off. Since 2.2.30 it also
downloads missing Suricata rules, reports OpenSnitch, the kernel module
lock and package signatures, and turns dnf's gpgcheck on where it is off.
Since 2.2.36 it also reports the DNS filter and, with ``fix``, switches it back
on through the same steps as the operator command (OpenSnitch rule, list
refresh, real DNS probe, redirect table); a failure restores the previous
policy and is reported with its reason.

Tam kontrol: Satsuma'nın her işlevi açık ve çalışıyor mu? Kapalı olanı aç.

``satsuma-admin tam-kontrol`` ile (ve yükseltmeden sonra
release/<sürüm>/yama.sh ile) çalışır. ``fix`` ile önce panelde kapalı olan
her anahtarı (otomatik engelleme, otomatik ağ engeli, OTX sorgu ve engeli,
subnet koruması) yeniden açar, operatör duraklatmasını kaldırır ve tek modem
görünüyorsa modemi kaydeder. Sonra her maddeyi sebebiyle TAMAM ya da SORUN
olarak bildirir; hiçbir şey sessizce kapalı kalmaz. 2.2.30'dan beri eksik
Suricata kurallarını indirir; OpenSnitch'i, çekirdek modül kilidini ve paket
imzalarını bildirir, kapalı dnf gpgcheck'i açar. 2.2.36'dan beri DNS filtresini
de bildirir; ``fix`` ile operatör komutuyla aynı adımlarla (OpenSnitch kuralı,
liste yenileme, gerçek DNS sınaması, yönlendirme tablosu) yeniden açar; hata
önceki politikayı geri yükler ve sebebiyle bildirilir.
"""
import json
import subprocess
from pathlib import Path
import time

SERVICES = ('satsuma-core.service', 'satsuma-teams.service', 'satsuma-core-otx.service',
            'satsuma-core-subnet.service', 'satsuma-core-audit.service', 'satsuma-core-finding.service',
            'satsuma-app-control.service', 'satsuma-operator.service', 'satsuma-reader.service',
            'satsuma-network-identity.service', 'satsuma-memory-hardening.service',
            'satsuma-core-dns.service', 'satsuma-suricata-ips.service',
            'satsuma-core-security-scan.timer', 'satsuma-privd.service')


def switch_on(store):
    """Turn every dashboard toggle back on; return what was changed."""
    changed = []
    def ensure(key, values):
        current = store.get(key, {}) or {}
        if any(current.get(k) != v for k, v in values.items()):
            store.set(key, {**current, **values})
            changed.append(key)
    from .enforcement import POLICY_KEY
    ensure(POLICY_KEY, {'enabled': True, 'source': 'full_check'})
    ensure('auto_action_policy', {'network_enabled': True, 'early_guard_required': False})
    ensure('operator_otx_policy', {'enabled': True, 'blocker_mode': True})
    ensure('subnet_protection_policy', {'enabled': True})
    # Pausing was removed (2.2.16); clear a value left by an older version.
    # Duraklatma kaldırıldı (2.2.16); eski sürümden kalan değer temizlenir.
    if store.get('operator_pause', False):
        store.set('operator_pause', False)
        changed.append('operator_pause')
    return changed


def _row(name, ok, detail):
    return {'name': name, 'ok': bool(ok), 'detail': detail}


def _usable_upstream(value):
    import ipaddress
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        return None
    return None if address.is_loopback or address.is_unspecified or address.is_multicast else str(address)


def dns_filter_row(store, fix=True, runner=subprocess.run, rule=None, refresh=None, probe=None, apply=None, ready=None):
    """The DNS filter row; with ``fix`` a filter that is off is switched back on.

    The same steps as the operator's dns_filter command, in the same order:
    rule, list refresh, real DNS probe, redirect table, readiness record. Any
    failure restores the previous policy and is reported with its reason.
    DNS filtresi satırı; ``fix`` ile kapalı filtre yeniden açılır. Adımlar
    operatörün dns_filter komutuyla aynı ve aynı sırada: kural, liste yenileme,
    gerçek DNS sınaması, yönlendirme tablosu, hazır olma kaydı. Her hata önceki
    politikayı geri yükler ve sebebiyle bildirilir.
    """
    name = 'DNS filtresi'
    policy = store.get('dns_policy', {}) or {}
    if policy.get('enabled') is True:
        health = store.get('dns_filter_health', {}) or {}
        if health.get('ok') and health.get('status') == 'ACTIVE':
            return _row(name, True, 'Etkin: yönlendirme çalışıyor')
        return _row(name, False, 'Etkin ama sağlıklı değil: ' + str(health.get('error') or health.get('status') or 'durum yok')[:200])
    if not fix:
        return _row(name, False, 'Kapalı: zararlı alan adı engellemesi etkin değil; sudo satsuma-admin tam-kontrol açar')
    from .dnsmasq_control import OPENDNS
    from .network_modes import NetworkModes, DNS_TABLE
    if rule is None:
        from .opensnitch import ensure_dns_rule as rule
    if refresh is None:
        from .dnsmasq_control import refresh
    if probe is None:
        from .dnsmasq_control import probe
    if apply is None:
        apply = lambda table, on: NetworkModes(store, runner).apply(table, on)
    if ready is None:
        from .dnsmasq_control import record_readiness as ready
    previous = dict(policy)
    upstream = _usable_upstream(policy.get('upstream')) or OPENDNS[0]
    store.set('dns_policy', {**policy, 'enabled': True, 'upstream': upstream})
    try:
        rule()
        refresh(store)
        probe()
        apply(DNS_TABLE, True)
        ready(store)
    except Exception as exc:
        store.set('dns_policy', previous)
        return _row(name, False, 'Kapalıydı, açılamadı: ' + str(exc)[:200])
    return _row(name, True, 'Kapalıydı, açıldı (üst sunucu ' + upstream + ')')


def check(store, runner=subprocess.run, config_loader=None, modem=None, ipv6=None, keys=None, fix=True, sudo=None, protection=None,
          binary=None, ssh=None, python=None, media=None, systemd=None, boot=None,
          mitm=None, browser=None, aide=None, dns_filter=None):
    rows = []
    if fix:
        changed = switch_on(store)
        rows.append(_row('Panel anahtarları', True,
                         'Kapalı bulunup açılan: ' + ', '.join(changed) if changed else 'Hepsi zaten açıktı'))
    from .full_protection import FULL_PROTECTION
    try:
        if config_loader is None:
            from .config import load_with_policy
            config_loader = load_with_policy
        config = config_loader()[0]
        off = [key for key in FULL_PROTECTION if config.get(key) is not True]
        rows.append(_row('Tam koruma ayarları', not off, 'Kapalı: ' + ', '.join(off) if off else 'Hepsi açık'))
    except Exception as exc:
        rows.append(_row('Tam koruma ayarları', False, 'Ayar okunamadı: ' + str(exc)[:200]))
    from .enforcement import policy as enforcement_policy
    rows.append(_row('Otomatik engelleme', enforcement_policy(store).get('enabled'), 'Panel anahtarı'))
    rows.append(_row('Otomatik ağ engeli', (store.get('auto_action_policy', {}) or {}).get('network_enabled') is not False, 'Panel anahtarı'))
    otx = store.get('operator_otx_policy', {}) or {}
    rows.append(_row('OTX sorgu ve engeli', otx.get('enabled') is not False and otx.get('blocker_mode') is not False, 'Panel anahtarı'))
    rows.append(browser() if browser else browser_row())
    rows.append(aide() if aide else aide_row(store))
    from .self_health import subnet_check
    subnet = subnet_check(store.get('subnet_protection_policy', None), store.get('subnet_health', {}))
    rows.append(_row('Alt ağ engelleyici', subnet['ok'], subnet['message'] + ' (OTX anahtarı gerekmez)'))
    for unit in SERVICES:
        try:
            state = runner(['/usr/bin/systemctl', 'is-active', unit], capture_output=True, text=True, timeout=10).stdout.strip()
        except (OSError, subprocess.SubprocessError) as exc:
            state = 'okunamadı: ' + str(exc)[:100]
        rows.append(_row('Servis ' + unit, state == 'active', state or 'bilinmiyor'))
    if dns_filter is None:
        # Real host steps; injected runners (tests) skip them unless given.
        dns_filter = (lambda: dns_filter_row(store, fix, runner)) if runner is subprocess.run else (lambda: None)
    dns_row = dns_filter()
    if dns_row:
        rows.append(dns_row)
    try:
        table = runner(['/usr/sbin/nft', '-j', 'list', 'table', 'inet', 'satsuma_core'],
                       capture_output=True, text=True, timeout=10)
        from .network_control import validate_layout
        ok = table.returncode == 0 and validate_layout(json.loads(table.stdout))
        rows.append(_row('Güvenlik duvarı (satsuma_core)', ok, 'Kurallar yerinde; IPv6 ilk kuralda düşürülüyor, lo yalnızca DNS ve TeamViewer için açık' if ok
                         else 'Tablo yok ya da kurallar beklenen düzende değil'))
    except Exception as exc:
        rows.append(_row('Güvenlik duvarı (satsuma_core)', False, str(exc)[:200]))
    if ipv6 is None:
        from .ipv6_off import status as ipv6
    state = ipv6()
    rows.append(_row('IPv6 kapalı', state['ipv6_off'], 'Açık kalan: ' + ', '.join(state['enabled_on']) if state['enabled_on'] else 'Bütün arayüzlerde kapalı'))
    rows.append(modem() if modem else modem_row())
    rows.append(binary() if binary else binary_row())
    rows.append(ssh() if ssh else ssh_row())
    rows.append(mitm() if mitm else mitm_row())
    rows.append(python() if python else python_row())
    rows.append(media() if media else media_row())
    rows.append(systemd() if systemd else systemd_row())
    rows.append(boot() if boot else boot_row())
    if sudo is None:
        from .sudo_nopasswd import grants as sudo
    found = sudo()
    rows.append(_row('Parolasız sudo', not found, 'Tanımlı değil' if not found else
                     'NOPASSWD: ' + '; '.join(f"{g['file']}:{g['line']} {g['text']}" for g in found)
                     + '. Siz eklemediyseniz: sudo visudo -f <dosya>'))
    if keys is None:
        keys = key_rows
    rows.extend(keys())
    if protection is None:
        # Real host checks; injected runners (tests) skip them unless given.
        protection = (lambda: protection_rows(runner, fix)) if runner is subprocess.run else (lambda: [])
    rows.extend(protection())
    return rows


def missing_tools(exists=None):
    """Packages whose program is missing; unhide may be installed as ``unhide`` or ``unhide-linux``.

    Programı bulunmayan paketler; unhide ``unhide`` ya da ``unhide-linux`` adıyla kurulmuş olabilir.
    """
    import os
    exists = exists or os.path.exists
    needed = (('dbus-tools', ('/usr/bin/dbus-monitor',)),
              ('unhide', ('/usr/sbin/unhide', '/usr/sbin/unhide-linux')),
              ('unhide', ('/usr/sbin/unhide-tcp',)),
              ('rkhunter', ('/usr/bin/rkhunter',)),
              ('suricata-update', ('/usr/bin/suricata-update',)))
    return sorted({package for package, paths in needed if not any(exists(path) for path in paths)})


def protection_rows(runner=subprocess.run, fix=True):
    """Suricata configuration and rules, OpenSnitch, module lock, package signatures (2.2.30)."""
    rows = []
    import os
    missing = missing_tools()
    rows.append(_row('Gerekli araçlar', not missing, 'Hepsi kurulu (dbus-monitor, unhide, rkhunter, suricata-update)' if not missing
                     else 'Eksik: ' + ', '.join(missing) + ' · sudo dnf install ' + ' '.join(missing)))
    from . import suricata_config
    note = ''
    if not suricata_config.rules_present() and fix:
        try:
            if suricata_config.update_rules(runner):
                runner(['/usr/bin/systemctl', 'restart', 'satsuma-suricata-ips.service'], capture_output=True, text=True, timeout=120)
                note = ' · kurallar şimdi indirildi, IPS yeniden başlatıldı'
        except Exception as exc:
            note = ' · ' + str(exc)[:200]
    generated = suricata_config.GENERATED
    made = generated.is_file() and 'HOME_NET' in generated.read_text(errors='replace')
    rows.append(_row('Suricata yapılandırması ve kuralları', suricata_config.rules_present() and made,
                     ('Satsuma yapılandırması ' + ('üretildi' if made else 'yok (IPS yeniden başlatılınca üretilir)')
                      + ' · kurallar ' + ('var' if suricata_config.rules_present() else 'yok: sudo suricata-update')) + note))
    from . import opensnitch
    snitch = opensnitch.status()
    rows.append(_row('Uygulama izinleri (OpenSnitch)', snitch['running'],
                     'OpenSnitch çalışıyor; Satsuma kuralları: ' + (', '.join(snitch['satsuma_rules']) or 'yok') if snitch['running']
                     else 'OpenSnitch kurulu ama çalışmıyor: sudo systemctl enable --now opensnitch; şimdilik Satsuma App Control devrede' if snitch['installed']
                     else 'OpenSnitch kurulu değil (github.com/evilsocket/opensnitch/releases); şimdilik Satsuma App Control devrede'))
    try:
        locked = Path('/proc/sys/kernel/modules_disabled').read_text().strip() == '1'
    except OSError:
        locked = False
    try:
        timer = runner(['/usr/bin/systemctl', 'is-enabled', 'satsuma-module-lock.timer'], capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        timer = 'bilinmiyor'
    # A lock scheduled for the next boot is not a problem (user: no false "sorun").
    rows.append(_row('Çekirdek modül kilidi', locked or timer == 'enabled',
                     'Kilitli: yeniden başlatmaya kadar yeni modül yüklenemez' if locked
                     else 'Kurulumdan sonraki ilk açılışta, açılıştan 3 dakika sonra kilitlenecek' if timer == 'enabled'
                     else 'Kilitli değil ve zamanlayıcı kapalı (' + timer + '): sudo systemctl enable satsuma-module-lock.timer'))
    from . import package_signatures
    audit = package_signatures.audit(runner, fix=fix)
    parts = []
    if audit['fixed_files']:
        parts.append('gpgcheck açıldı: ' + ', '.join(audit['fixed_files']))
    if audit['weak_repositories']:
        parts.append('imza denetimi kapalı depo: ' + ', '.join(s for _, s in audit['weak_repositories']))
    if audit['unsigned']:
        parts.append('imzasız kurulu paket ' + str(len(audit['unsigned'])) + ': ' + ', '.join(audit['unsigned'][:8]))
    if audit['error']:
        parts.append(audit['error'])
    rows.append(_row('Paket imzaları', audit['ok'], '; '.join(parts) or 'dnf ve bütün depolar imza denetliyor; kurulu paketlerin hepsi imzalı'))
    return rows


def modem_row():
    from . import modem_identity
    try:
        data = modem_identity.inventory()
        policy = modem_identity.load()
        if policy is None:
            enrolled = modem_identity.approve_automatic(data=data)
            if enrolled['status'] != 'AUTOMATICALLY_ENROLLED':
                return _row('Modem', False, ' '.join(enrolled['reasons']) +
                            ' Elle kaydetmek için: sudo satsuma-admin modem --mac <modem-etiketindeki-MAC>')
            policy = modem_identity.load()
        result = modem_identity.compare(policy, data)
        modem = policy['modem']
        text = f"{modem['gateway']} · {modem['interface']} · MAC {modem['gateway_mac']}"
        if result['status'] == 'MATCHED_USER_APPROVAL':
            return _row('Modem', True, 'Tanındı: ' + text)
        from .network_identity import classify_change
        kind, severity, title, advice = classify_change(result)
        # Anything but a full match fails the product's health check too, so
        # it is never reported as TAMAM here.
        extra = (' Etiketteki MAC kayıtlıyla aynıysa yeniden kaydetmek için: sudo satsuma-admin modem'
                 if kind == 'ROUTES_CHANGED' else '')
        return _row('Modem', False, title + ' (kayıtlı: ' + text + '). ' + advice + extra)
    except Exception as exc:
        return _row('Modem', False, 'Modem okunamadı: ' + str(exc)[:200])


def binary_row():
    """Last system program audit (satsuma.binary_audit), from the scan store."""
    name = 'Sistem programları (/usr/bin, /usr/sbin)'
    try:
        from .host_store import HostStore
        host = HostStore()
        try:
            state = host.get('binary_audit', {}) or {}
        finally:
            host.close()
    except Exception as exc:
        return _row(name, False, 'Okunamadı: ' + str(exc)[:200])
    if not state.get('updated_at'):
        return _row(name, False, 'Henüz denetlenmedi: sudo systemctl start satsuma-core-security-scan-now.service')
    if state.get('error'):
        return _row(name, False, state['error'])
    counts = state.get('counts') or {}
    bad = counts.get('modified', 0) + counts.get('unowned', 0)
    text = (f"değiştirilmiş {counts.get('modified', 0)}, paketsiz {counts.get('unowned', 0)}, "
            f"/usr/local'da paket dışı {counts.get('local', 0)}, "
            f"saldırı aracı {counts.get('attack_tool', 0)}, karantinaya alınan {len(state.get('quarantined') or [])}")
    if state.get('virustotal') == 'no_key':
        text += ' · VirusTotal anahtarı yok'
    return _row(name, not bad, text)


def python_row():
    """Last Python script audit (satsuma.python_audit), from the scan store."""
    name = 'Python betikleri'
    try:
        from .host_store import HostStore
        host = HostStore()
        try:
            state = host.get('python_audit', {}) or {}
        finally:
            host.close()
    except Exception as exc:
        return _row(name, False, 'Okunamadı: ' + str(exc)[:200])
    if not state.get('updated_at'):
        return _row(name, False, 'Henüz denetlenmedi: sudo systemctl start satsuma-core-security-scan-now.service')
    modified, high, medium = (state.get(k) or [] for k in ('modified', 'high', 'medium'))
    text = (f"değişmiş paketli dosya {len(modified)}, yüksek puanlı betik {len(high)}, orta puanlı {len(medium)}"
            + (': ' + ', '.join((modified + high)[:5]) if modified or high else ''))
    return _row(name, not modified and not high, text)


def media_row():
    """Last media audit (satsuma.media_audit), from the scan store."""
    name = 'Man, SVG, PNG ve font dosyaları'
    try:
        from .host_store import HostStore
        host = HostStore()
        try:
            state = host.get('media_audit', {}) or {}
        finally:
            host.close()
    except Exception as exc:
        return _row(name, False, 'Okunamadı: ' + str(exc)[:200])
    if not state.get('updated_at'):
        return _row(name, False, 'Henüz denetlenmedi: sudo systemctl start satsuma-core-security-scan-now.service')
    high, other = state.get('high') or [], state.get('other') or []
    return _row(name, not high, f"yüksek önemli {len(high)}, diğer {len(other)}"
                + (': ' + ', '.join(high[:5]) if high else ''))


def systemd_row():
    """Last systemd audit (satsuma.systemd_audit), from the scan store."""
    name = 'systemd birimleri'
    try:
        from .host_store import HostStore
        host = HostStore()
        try:
            state = host.get('systemd_audit', {}) or {}
        finally:
            host.close()
    except Exception as exc:
        return _row(name, False, 'Okunamadı: ' + str(exc)[:200])
    if not state.get('updated_at'):
        return _row(name, False, 'Henüz denetlenmedi: sudo systemctl start satsuma-core-security-scan-now.service')
    bad = (state.get('modified') or []) + (state.get('new_units') or []) + (state.get('flagged_units') or [])
    failed = ((state.get('timing') or {}).get('failed')) or []
    text = (f"değişmiş paket dosyası {len(state.get('modified') or [])}, yeni birim {len(state.get('new_units') or [])}, "
            f"şüpheli birim {len(state.get('flagged_units') or [])}, başarısız servis {len(failed)}"
            + (': ' + ', '.join(sorted(set(bad))[:5]) if bad else ''))
    return _row(name, not bad, text)


def boot_row():
    """Problems of the current boot (satsuma.boot_correlator)."""
    name = 'Açılış sorunları'
    try:
        from .host_store import HostStore
        host = HostStore()
        try:
            state = host.get('boot_correlation', {}) or {}
        finally:
            host.close()
    except Exception as exc:
        return _row(name, False, 'Okunamadı: ' + str(exc)[:200])
    if not state.get('boot_id'):
        return _row(name, False, 'Bu açılış henüz eşlenmedi (açılıştan 5 dakika sonra ya da elle taramada)')
    serious = [p for p in state.get('problems') or [] if p.get('severity') in ('high', 'critical')]
    text = f"sorun {len(state.get('problems') or [])}, yüksek {len(serious)}, bağlantısız uyarı {state.get('unrelated_warnings', 0)}"
    if serious:
        text += ': ' + ' | '.join(p['sentence'] for p in serious[:3])
    return _row(name, not serious, text)


def ssh_row():
    """Last SSH audit (satsuma.ssh_keys), from the scan store."""
    try:
        from .host_store import HostStore
        host = HostStore()
        try:
            state = host.get('ssh_keys', {}) or {}
        finally:
            host.close()
    except Exception as exc:
        return _row('SSH anahtarları', False, 'Okunamadı: ' + str(exc)[:200])
    if not state.get('updated_at'):
        return _row('SSH anahtarları', False, 'Henüz denetlenmedi: sudo systemctl start satsuma-core-security-scan-now.service')
    sshd = state.get('sshd') or {}
    problems = []
    if state.get('pending'):
        problems.append(f"bilginiz dahilinde olduğu onaylanmamış anahtar {len(state['pending'])} "
                        "(sudo satsuma-admin ssh liste)")
    if state.get('new_keys'):
        problems.append(f"son denetimden beri eklenen {len(state['new_keys'])}")
    if state.get('permissions'):
        problems.append('başkalarının yazabildiği SSH dosyası')
    if sshd.get('is-active') == 'active' or sshd.get('is-enabled') == 'enabled':
        problems.append('SSH sunucusu açık (sudo satsuma-admin ssh sunucu-kapat)')
    text = (f"yetkili anahtar {state.get('authorized_count', 0)}, parolasız özel anahtar "
            f"{len(state.get('unencrypted_private') or [])}, ~/.ssh dışında {len(state.get('stray_private') or [])}")
    return _row('SSH anahtarları', not problems, ('; '.join(problems) + ' · ' if problems else '') + text)


def mitm_row():
    """Last man-in-the-middle watch (satsuma.mitm_watch), from the scan store."""
    name = 'Ortadaki adam izleyicisi (DNS, rota, profil, çekirdek, uzak erişim)'
    try:
        from .host_store import HostStore
        host = HostStore()
        try:
            state = host.get('mitm_watch', {}) or {}
        finally:
            host.close()
    except Exception as exc:
        return _row(name, False, 'Okunamadı: ' + str(exc)[:200])
    if not state.get('updated_at'):
        return _row(name, False, 'Henüz çalışmadı: sudo systemctl start satsuma-mitm-watch.service')
    if time.time() - state['updated_at'] > 600:
        return _row(name, False, 'Son denetim 10 dakikadan eski: sudo systemctl status satsuma-mitm-watch.timer')
    counts = state.get('counts') or {}
    kernel = state.get('kernel') or {}
    problems = [f"{label} {counts[key]}" for key, label in (('critical', 'kritik'), ('high', 'yüksek'), ('medium', 'orta'))
                if counts.get(key)]
    if kernel.get('failed'):
        problems.append(f"geri yazılamayan çekirdek ayarı {len(kernel['failed'])}")
    text = (f"DNS üst sunucusu {state.get('upstream') or 'yok'}"
            + (', sabitlenen: ' + ', '.join(state['pinned']) if state.get('pinned') else ', sabitleme yok')
            + f"; dışarıyı dinleyen {len(state.get('listeners') or [])}")
    if state.get('unavailable'):
        text += '; okunamayan: ' + ', '.join(state['unavailable'])
    return _row(name, not problems, ('Bulgu: ' + ', '.join(problems) + ' · ' if problems else '') + text)


def aide_row(store):
    """The AIDE guard's last comparison with the snapshot. AIDE bekçisinin son karşılaştırması."""
    from .aide_guard import status_text
    row = store.get('aide_changes', None)
    return _row('AIDE bekçisi', bool(row) and row.get('status') == 'CLEAN', status_text(row))


def browser_row():
    """Browser policies from satsuma-omni V62 are in place. V62 tarayıcı politikaları yerinde mi."""
    from .browser_policy import status
    state = status()
    missing = [path for path, ok in state['files'].items() if not ok]
    return _row('Tarayıcı politikaları', state['ok'], 'Firefox, Chrome, Chromium kilitli' if state['ok'] else
                'Eksik ya da değişmiş: ' + ', '.join(missing) + ' · sudo satsuma-kur')


def key_rows():
    rows = []
    try:
        from .otx import load_config
        rows.append(_row('OTX anahtarı', bool(load_config().get('api_key')),
                         'Var' if load_config().get('api_key') else
                         'Yok: OTX sorguları çalışmıyor; ağ koruması OTX olmadan sürer · sudo satsuma-admin set-otx-key'))
    except Exception as exc:
        rows.append(_row('OTX anahtarı', False, str(exc)[:200]))
    from .binary_audit import _vt_key
    rows.append(_row('VirusTotal anahtarı', bool(_vt_key()),
                     'Var' if _vt_key() else 'Yok: /etc/satsuma-core/virustotal.key (root, 0640); sistem programları yalnızca özetle sorulur'))
    from .deepseek_client import is_available
    from .definitions import status as definition_status
    counts = definition_status()
    rows.append(_row('MITRE/CISA tanımları', bool(counts.get('techniques')) and bool(counts.get('kev')),
                     'MITRE teknik ' + str(counts.get('techniques') or 0) + ', CISA KEV ' + str(counts.get('kev') or 0)
                     + ' (/var/lib/satsuma-core/tanim)'))
    rows.append(_row('DeepSeek anahtarı', is_available(),
                     'Var' if is_available() else 'Yok: /etc/satsuma-core/deepseek.key (root:root 0600; yalnız yetkili arka uç)'))
    return rows


def report(rows):
    lines = []
    for row in rows:
        lines.append(('[TAMAM] ' if row['ok'] else '[SORUN] ') + row['name'] + ': ' + row['detail'])
    bad = sum(1 for row in rows if not row['ok'])
    lines.append('Sonuç: ' + ('her şey açık ve çalışıyor.' if not bad else f'{bad} maddede sorun var; yukarıdaki [SORUN] satırlarına bakın.'))
    return '\n'.join(lines)
