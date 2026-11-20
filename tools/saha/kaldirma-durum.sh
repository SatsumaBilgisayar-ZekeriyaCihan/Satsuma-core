#!/bin/sh
# Satsuma: kaldırmayı neyin engellediği (yalnızca okuma). sudo ile. Çıktı: /root/satsuma-kaldirma.txt
out=/root/satsuma-kaldirma.txt
{
echo "== Açılışlar"; journalctl --list-boots --no-pager | tail -6
echo; echo "== Dağıtımlar"; rpm-ostree status 2>&1 | grep -E "^[ ●]|Version|LayeredPackages|LocalPackages|RemovedBasePackages|InitramfsEtc" | head -30
echo; echo "== Satsuma kayıtları: rpm-ostree / satsuma-core / en sıkı mod (son 24 saat)"
python3 - <<'PY' 2>&1
import sqlite3,json,time
db=sqlite3.connect('file:/var/lib/satsuma-core/core.db?mode=ro',uri=True)
now=time.time()
q=("SELECT created,kind,body FROM records WHERE created>? AND (body LIKE '%rpm-ostree%' OR body LIKE '%satsuma-core%' "
   "OR body LIKE '%GAP-036%' OR body LIKE '%GAP-075%' OR body LIKE '%strict%' OR body LIKE '%en-siki%' OR body LIKE '%readonly%') "
   "ORDER BY id LIMIT 4000")
seen=set()
for c,k,b in db.execute(q,(now-24*3600,)):
    try:j=json.loads(b)
    except Exception:continue
    f=(j.get('metadata') or {}).get('finding') or j.get('finding') or j
    e=f.get('event') if isinstance(f.get('event'),dict) else {}
    rule=f.get('rule_id') or j.get('rule_id') or j.get('action') or ''
    cmd=str(e.get('cmd') or j.get('cmd') or j.get('command') or '')[:150]
    st=j.get('status') or j.get('decision') or (j.get('event') or {}).get('outcome') if isinstance(j.get('event'),dict) else j.get('status')
    key=(int(float(c))//5,rule,cmd,str(st))
    if key in seen:continue
    seen.add(key)
    print(time.strftime('%d %H:%M:%S',time.localtime(float(c))),k,rule,'|',st,'|',cmd,'|',str(j.get('error') or j.get('reason') or '')[:120])
PY
echo; echo "== Satsuma servis hataları (2.2.63 açılışları)"
for b in $(journalctl --list-boots --no-pager | awk 'NR>1{print $1}' | tail -4); do echo "--- açılış $b"; journalctl -b $b --no-pager -p err -u 'satsuma-*' 2>/dev/null | tail -8; done
} > "$out" 2>&1
echo "Tamam: $out"
