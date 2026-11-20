#!/bin/sh
# Satsuma: langtable / Firefox dil eklentisi / ibus karantina kararları (yalnızca okuma). sudo ile.
out=/root/satsuma-karantina.txt
{
echo "== Karantinadaki dosyalar (eşleşenler)"
for d in /var/lib/satsuma-core/scan-quarantine /var/lib/satsuma-core/quarantine-pending; do
  grep -lisE 'langtable|langpack|ibus|firefox' $d/*.json 2>/dev/null | while read f; do echo "--- $f"; python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));print({k:d.get(k) for k in ("original_path","source","reason","signature","rule_id","quarantined_at","sha256")})' "$f"; done
done
echo; echo "== Satsuma kararları (son 3 gün)"
python3 - <<'PY' 2>&1
import sqlite3,json,time
db=sqlite3.connect('file:/var/lib/satsuma-core/core.db?mode=ro',uri=True)
seen=set()
for c,k,b in db.execute("SELECT created,kind,body FROM records WHERE created>? AND (body LIKE '%langtable%' OR body LIKE '%langpack%' OR body LIKE '%ibus%') ORDER BY id LIMIT 3000",(time.time()-3*86400,)):
    try:j=json.loads(b)
    except Exception:continue
    f=(j.get('metadata') or {}).get('finding') or j.get('finding') or j
    e=f.get('event') if isinstance(f.get('event'),dict) else {}
    rule=f.get('rule_id') or j.get('rule_id') or j.get('action') or j.get('engine') or ''
    path=e.get('file_path') or e.get('path') or j.get('path') or j.get('original_path') or j.get('target') or ''
    what=str(e.get('cmd') or j.get('signature') or j.get('reason') or j.get('title') or '')[:140]
    st=j.get('status') or j.get('decision') or ''
    key=(rule,str(path),str(st),what)
    if key in seen:continue
    seen.add(key)
    print(time.strftime('%d %H:%M',time.localtime(float(c))),k,rule,'|',st,'|',path,'|',what)
PY
} > "$out" 2>&1
echo "Tamam: $out"
