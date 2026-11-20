#!/bin/sh
# Satsuma: DNS filtresi tanısı 2 (yalnızca okuma). sudo ile. Çıktı: /root/satsuma-dns2.txt
out=/root/satsuma-dns2.txt
{
echo "== Engel listeleri"
for f in blocked.conf added.hosts dnsmasq.conf; do p=/etc/satsuma-core/dns/$f; echo "$f: $(wc -l < $p 2>/dev/null) satır, $(stat -c '%y' $p 2>/dev/null)"; done
grep -c . /etc/satsuma-core/dns/added.hosts 2>/dev/null; head -3 /etc/satsuma-core/dns/added.hosts 2>/dev/null
python3 - <<'PY' 2>&1
import sqlite3,json,time
db=sqlite3.connect('file:/var/lib/satsuma-core/core.db?mode=ro',uri=True)
def state(k):
    for t in ('state',):
        try:
            r=db.execute(f"SELECT body FROM {t} WHERE key=?",(k,)).fetchone()
            if r:return json.loads(r[0])
        except Exception:pass
    return None
now=time.time()
d=state('dns_blocked_domains') or {}
print('dns_blocked_domains toplam:',len(d),' süresi dolmamış:',sum(1 for v in d.values() if isinstance(v,dict) and v.get('expires_at',0)>now))
for k in ('dns_policy','dns_filter_health','dns_custom_lists','otx_health','dns_filter_hot_added_at','dns_filter_restarted_at'):
    v=state(k);print(k,':',json.dumps(v,ensure_ascii=False)[:400])
print()
print('== GAP-047 / GAP-023 ayrıntı (bu açılış)')
for c,b in db.execute("SELECT created,body FROM records WHERE kind IN ('findings','events') AND created>? AND (body LIKE '%GAP-047%' OR body LIKE '%GAP-023%') ORDER BY id DESC LIMIT 6",(now-6*3600,)):
    j=json.loads(b);f=(j.get('metadata') or {}).get('finding') or j
    e=f.get('event') or {}
    print(time.strftime('%H:%M:%S',time.localtime(float(c))),f.get('rule_id'),'| cmd:',str(e.get('cmd') or e.get('command'))[:200],'| exe:',e.get('exe'),'| pid:',e.get('pid'),'| path:',e.get('file_path') or e.get('path'),'| ppid:',e.get('ppid'))
print()
print('== Bu açılıştaki durdurmalar')
for c,b in db.execute("SELECT created,body FROM records WHERE kind='actions' AND created>? ORDER BY id DESC LIMIT 400",(now-6*3600,)):
    j=json.loads(b)
    if str(j.get('status','')).startswith(('process_','terminated','stopped','killed')) or 'stop' in str(j.get('action','')):
        print(time.strftime('%H:%M:%S',time.localtime(float(c))),j.get('status'),j.get('action'),str(j.get('cmd') or j.get('command') or j.get('reason'))[:160])
PY
echo; echo "== Tarayıcı DoH denemesi (engellenmeli)"
for n in dns.google mozilla.cloudflare-dns.com doh.opendns.com; do echo "$n -> $(getent ahostsv4 $n 2>&1 | head -1)"; done
} > "$out" 2>&1
echo "Tamam: $out"
