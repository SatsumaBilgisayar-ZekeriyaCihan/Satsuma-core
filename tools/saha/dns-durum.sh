#!/bin/sh
# Satsuma: DNS filtresi tanısı (yalnızca okuma). sudo ile. Çıktı: /root/satsuma-dns.txt
out=/root/satsuma-dns.txt
{
rpm -q satsuma-core
echo "== Birimler"
for u in satsuma-dns-netns satsuma-core-dns satsuma-core-dns-refresh satsuma-core-dns-refresh.timer satsuma-network satsuma-network-modes satsuma-core-otx satsuma-reader satsuma-self-health; do
  printf '%-34s %s\n' "$u" "$(systemctl show $u -p ActiveState -p SubState -p Result -p ExecMainStatus --value | tr '\n' ' ')"; done
echo; echo "== Hatalar (bu açılış)"
journalctl -b --no-pager -p warning -u satsuma-dns-netns -u satsuma-core-dns -u satsuma-core-dns-refresh -u satsuma-network -u satsuma-network-modes -u satsuma-core-otx 2>&1 | tail -40
echo; echo "== SELinux reddi (DNS/ağ)"
ausearch -m AVC -ts boot 2>/dev/null | grep -iE "dnsmasq|satsuma|nft|ip " | tail -10 || echo "ausearch yok"
echo; echo "== Ad alanı ve dinleme"
ls -l /run/netns/ 2>&1; ip netns exec satsuma-dns ss -lunp 2>&1 | head -5
echo; echo "== DNS yönlendirme kuralları"
nft list ruleset 2>/dev/null | grep -nE "dport 53|udp dport domain|tcp dport domain|dnat|redirect" | head -15
echo; echo "== Çözümleyici"; resolvectl status 2>/dev/null | head -15; cat /etc/resolv.conf | grep -v '^#'
echo; echo "== Deneme"
b=$(sed -n 's,^address=/\(.*\)/#$,\1,p' /etc/satsuma-core/dns/blocked.conf 2>/dev/null | head -1)
echo "engelli listedeki ilk ad: $b ($(grep -c '^address=/' /etc/satsuma-core/dns/blocked.conf 2>/dev/null) satır)"
for n in "$b" fedoraproject.org; do [ -n "$n" ] && echo "$n -> $(getent ahostsv4 "$n" 2>&1 | head -1)"; done
echo; echo "== Satsuma'nın son durdurmaları ve kararları (DNS ile ilgili)"
python3 - <<'PY' 2>&1
import sqlite3,time
db=sqlite3.connect('file:/var/lib/satsuma-core/core.db?mode=ro',uri=True)
q="SELECT created,kind,substr(body,1,260) FROM records WHERE created>? AND (body LIKE '%dnsmasq%' OR body LIKE '%dns_netns%' OR body LIKE '%satsuma-dns%' OR body LIKE '%POLICY-SIG%' OR body LIKE '%privd_unavailable%') ORDER BY id DESC LIMIT 15"
for c,k,b in db.execute(q,(time.time()-3*3600,)):print(time.strftime('%H:%M:%S',time.localtime(float(c))),k,b)
PY
echo; echo "== Politika ve sağlık"; satsuma-admin politika durum 2>&1; cat /var/lib/satsuma-core/self-health/status.json 2>/dev/null | python3 -c 'import json,sys;d=json.load(sys.stdin);c=d.get("checks",{});print(d.get("status"));print(json.dumps({k:c[k] for k in c if "dns" in k},ensure_ascii=False)[:800])' 2>&1
} > "$out" 2>&1
echo "Tamam: $out"
