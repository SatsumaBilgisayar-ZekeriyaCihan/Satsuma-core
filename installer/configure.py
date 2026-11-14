import sys,json,os
from pathlib import Path
sys.path.insert(0,'/opt/satsuma-core')
from satsuma.config import DEFAULT
from satsuma.policy import from_legacy,validate
p=Path('/etc/satsuma-core/policy.json')
if p.exists():policy=validate(json.loads(p.read_text()))
else:policy=from_legacy(DEFAULT)
w=policy['workers'];w['response']['enabled']=True
w['response']['nft']={'family':'inet','table':'satsuma_core','ipv4_set':'blocked_ips','ipv6_set':'blocked_ips_v6'}
w['response']['destructive']={'enabled':True,'allowed_actions':['network_isolate','process_kill','file_quarantine','user_disable'],'sudo_autoblock_enabled':True}
w['otx']={**w.get('otx',{}),'enabled':True,'blocker_mode':True}
print('Tam koruma: bütün yanıtlar ve engellemeler açık.')
# Detect actual sensors; never create fake EVE/audit logs and call them healthy.
for name,key in [('suricata_collector','eve_path'),('audit','log_path')]:
 path=Path(w[name][key]);w[name]['enabled']=path.exists()
 if name=='suricata_collector':w[name]['writer_uid']='managed_suricata'
 if not path.exists():print('SENSOR MISSING:',name,path)
policy['revision']+=1;validate(policy)
p.write_text(json.dumps(policy,indent=2));p.chmod(0o644)
(Path('/etc/satsuma-core')/'config.json').write_text(json.dumps({**DEFAULT,'nft_table':'satsuma_core'},indent=2))
os.chmod('/etc/satsuma-core/config.json',0o644)
