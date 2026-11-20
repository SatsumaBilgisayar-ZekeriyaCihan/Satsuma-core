#!/bin/sh
# Satsuma 2.2.64 saha denetimi (yalnızca okuma; hiçbir şey değiştirmez). sudo ile. Çıktı: /root/satsuma-264-kontrol.txt
out=/root/satsuma-264-kontrol.txt
ok(){ printf '  [TAMAM] %s\n' "$*"; }; no(){ printf '  [SORUN] %s\n' "$*"; }
{
echo "== 1. Sürüm ve rpm-ostree"
v=$(rpm -q satsuma-core); [ "$v" = "satsuma-core-2.2.64-1.fc44.x86_64" ] && ok "$v" || no "$v"
rpm-ostree status 2>/dev/null | grep -q "State: idle" && ok "rpm-ostree boşta" || no "rpm-ostree meşgul: $(rpm-ostree status | grep -i 'State\|Transaction' | head -2 | tr '\n' ' ')"
t=$(rpm-ostree status -v 2>/dev/null | grep -m1 -i InitramfsEtc); [ -n "$t" ] && echo "  [BİLGİ] ilk açılış görüntüsü takibi: $t" || echo "  [BİLGİ] initramfs takibi yok"
ls /boot/ostree/initramfs-overlays/ 2>/dev/null | sed 's/^/  [BİLGİ] overlay: /'

echo; echo "== 2. Servisler"
f=$(systemctl list-units 'satsuma-*' --state=failed --no-legend --plain | awk '{print $1}'); [ -z "$f" ] && ok "başarısız Satsuma birimi yok" || no "başarısız: $f"
for u in satsuma-privd satsuma-teams satsuma-core satsuma-reader satsuma-operator satsuma-core-dns satsuma-core-otx clamd@scan; do
  s=$(systemctl is-active $u.service); [ "$s" = active ] && ok "$u: active" || no "$u: $s"; done
grep -q 'ConditionKernelCommandLine=!satsuma.off' /usr/lib/systemd/system/satsuma-teams.service && ok "satsuma.off anahtarı birimlerde" || no "satsuma.off anahtarı yok"

echo; echo "== 3. Panel"
[ "$(systemctl show satsuma-reader -p User --value)" = root ] && ok "okuyucu root" || no "okuyucu kullanıcısı: $(systemctl show satsuma-reader -p User --value)"
[ -d /run/satsuma ] && ok "/run/satsuma var ($(stat -c '%a %U:%G' /run/satsuma))" || no "/run/satsuma yok"
[ -S /run/satsuma/operator.sock ] && ok "operatör soketi var" || no "operatör soketi yok"
cd /opt/satsuma-core 2>/dev/null && python3 -c '
from satsuma.dashboard_api_client import ReaderClient
r=ReaderClient(timeout=10).call("health")
print("  [TAMAM] okuyucu yanıt verdi:",str(r)[:150]) if r is not None else print("  [SORUN] okuyucu boş yanıt")' 2>&1 | sed 's/^Traceback.*/  [SORUN] okuyucu hatası:/' | tail -3
cd /

echo; echo "== 4. Sahibin çıkış yolu (kurulu kodla, komut çalıştırmadan)"
cd /opt/satsuma-core && python3 - <<'PY' 2>&1
from satsuma.smart_rules import SmartRuleEngine
from satsuma import enforcement
e=SmartRuleEngine();e.strict_mode=True
for c in ['rpm-ostree uninstall satsuma-core','rpm-ostree rollback','rpm-ostree reset','rpm-ostree override reset --all',
          'rpm-ostree uninstall satsuma-core --install ./satsuma-core-2.2.65-1.fc44.x86_64.rpm','rpm-ostree cancel']:
    stops=[f['rule_id'] for f in e.match({'source':'sys_proc','action':'exec','cmd':c,'exe':'/usr/bin/rpm-ostree','uid':0,'pid':5000,'ppid':4000}) if enforcement.eligible(f)]
    print('  [TAMAM]' if not stops else '  [SORUN]',c,'-> durdurulmaz' if not stops else '-> DURDURULUR '+str(stops))
for c in ['/usr/bin/s-nail -s test root','/usr/sbin/avahi-daemon -s']:
    stops=[f['rule_id'] for f in e.match({'source':'sys_proc','action':'exec','cmd':c,'exe':c.split()[0],'uid':0,'pid':5000,'ppid':4000}) if enforcement.eligible(f)]
    print('  [TAMAM]' if stops else '  [SORUN]',c,'-> durdurulur '+str(stops) if stops else '-> durdurulmuyor')
PY
cd /

echo; echo "== 5. Politika ve en sıkı mod"
satsuma-admin politika durum 2>&1 | sed 's/^/  /'
satsuma-admin en-siki-mod durum 2>&1 | head -3 | sed 's/^/  /'

echo; echo "== 6. Yasaklar"
for u in avahi-daemon.service avahi-daemon.socket brltty.service ipp-usb.service gssproxy.service systemd-resolved.service vmtoolsd.service; do
  s=$(systemctl is-enabled $u 2>&1); case "$s" in masked*) ok "$u maskeli";; *) no "$u: $s";; esac; done
[ -x /etc/cron.daily/rkhunter ] && no "rkhunter posta cron'u çalıştırılabilir" || ok "rkhunter posta cron'u kapalı"
b=$(rpm -q firefox systemd-resolved avahi gssproxy brltty ipp-usb python3-cups ibus-panel python3-ibus python3-langtable s-nail 2>/dev/null | grep -v 'not installed\|kurulu değil'); [ -z "$b" ] && ok "yasaklı paketlerin hiçbiri kurulu değil" || no "kurulu yasaklı paket: $b"
grep -q 'langpack-tr@firefox.mozilla.org' /etc/firefox/policies/policies.json 2>/dev/null && ok "Firefox dil eklentisi politikada engelli" || no "Firefox politikasında dil eklentisi engeli yok (politika yeniden uygulanmadı)"

echo; echo "== 7. DNS"
for n in dns.google doh.opendns.com mozilla.cloudflare-dns.com; do r=$(getent ahostsv4 $n | head -1 | awk '{print $1}'); [ "$r" = 0.0.0.0 ] && ok "$n engelli" || no "$n -> ${r:-çözülmedi}"; done
getent ahostsv4 use-application-dns.net >/dev/null 2>&1 && no "Firefox denetim adı çözülüyor (DoH açık kalabilir)" || ok "use-application-dns.net yok (Firefox DoH kapanır)"
r=$(getent ahostsv4 fedoraproject.org | head -1 | awk '{print $1}'); [ -n "$r" ] && [ "$r" != 0.0.0.0 ] && ok "fedoraproject.org -> $r" || no "fedoraproject.org engelli/çözülmüyor"
grep -c '^address=/' /etc/satsuma-core/dns/blocked.conf | sed 's/^/  [BİLGİ] engel satırı: /'

echo; echo "== 8. Modüller"
[ "$(cat /proc/sys/kernel/modules_disabled)" = 1 ] && ok "modül kilidi kapalı" || no "modül kilidi açık (açılıştan 2 dk geçti mi?)"
[ -f /etc/modprobe.d/satsuma-module-allowlist.conf ] && echo "  [BİLGİ] izin listesi: $(grep -c '^install' /etc/modprobe.d/satsuma-module-allowlist.conf) modül engelli" || echo "  [BİLGİ] izin listesi henüz yok (öğrenme açılışı)"
for m in bridge tun kvm_amd; do grep -q "^$m " /proc/modules && ok "$m yüklü" || no "$m yüklü değil"; done

echo; echo "== 9. Bu açılıştaki önemli bulgular"
cd /opt/satsuma-core && python3 - <<'PY' 2>&1
import sqlite3,json,time,re
boot=time.time()-float(open('/proc/uptime').read().split()[0])
db=sqlite3.connect('file:/var/lib/satsuma-core/core.db?mode=ro',uri=True)
want=re.compile(r'SATSUMA-(GAP-0(23|36|47|75|76|77)|FILELESS-002|PRIVD-001|POLICY-SIG-00\d|HEALTH-RESTART-001|OFF-001|BANNED-PKG-001)')
cnt={}
for (b,) in db.execute("SELECT body FROM records WHERE created>? AND kind IN ('findings','events') ",(boot,)):
    for m in set(want.findall(b)):
        k='SATSUMA-'+m[0];cnt[k]=cnt.get(k,0)+1
print('  [BİLGİ]',cnt or 'bu açılışta bu bulgulardan hiçbiri yok')
acts={}
for (b,) in db.execute("SELECT body FROM records WHERE created>? AND kind='actions'",(boot,)):
    s=json.loads(b).get('status');acts[s]=acts.get(s,0)+1
print('  [BİLGİ] kararlar:',dict(sorted(acts.items(),key=lambda x:-x[1])[:8]))
PY
} > "$out" 2>&1
echo "Tamam: $out"
