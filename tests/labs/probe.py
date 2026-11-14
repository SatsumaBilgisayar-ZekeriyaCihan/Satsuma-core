"""Read-only use of RPM code in a disposable network namespace; no host rules."""
import json, os, re, socket, struct, subprocess as sp, sys, time, threading
from pathlib import Path
sys.path.insert(0,'/rpm/usr/lib/satsuma-core/payload')
from satsuma.network_control import render_ruleset
from satsuma.network_modes import dns_script
from satsuma.app_firewall import nft_script
from satsuma.dnsmasq_control import _probe_once
OUT=Path('/out'); OUT.mkdir(exist_ok=True)
processes=[]
def run(args,**kwargs):
 result=sp.run(args,text=True,capture_output=True,**kwargs)
 if result.returncode: print(args, result.stderr,flush=True);result.check_returncode()
 return result
def start(args,name):
 stream=(OUT/name).open('w');p=sp.Popen(args,stdout=stream,stderr=sp.STDOUT);processes.append(p);return p
def nft(text):
 run(['nft','-f','-'],input=text)
def query(host,port,name='example.com',kind=1,transport='udp'):
 qname=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0' if name else b'\0'
 packet=struct.pack('!6H',12345,0x100,1,0,0,0)+qname+struct.pack('!HH',kind,1)
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM if transport=='tcp' else socket.SOCK_DGRAM) as s:
  s.settimeout(2);s.connect((host,port));s.sendall(struct.pack('!H',len(packet))+packet if transport=='tcp' else packet)
  data=s.recv(65535)
  if transport=='tcp':
   expected=int.from_bytes(data[:2],'big');data=data[2:]
   while len(data)<expected:data+=s.recv(expected-len(data))
  return {'bytes':len(data),'header':struct.unpack('!6H',data[:12]),'peer':s.getpeername(),'client':s.getsockname(),'transport':transport}
def attempt(label,fn):
 stamp=time.time()
 try:result={'ok':True,'result':fn()}
 except Exception as exc:result={'ok':False,'error':type(exc).__name__+': '+str(exc)}
 result.update(started_at=stamp,finished_at=time.time())
 print(label,json.dumps(result),flush=True);results[label]=result
results={}
try:
 if not Path('/.dockerenv').exists() or len(json.loads(run(['ip','-j','link','show']).stdout))!=1:
  raise RuntimeError('Requires a fresh Docker --network none namespace')
 run(['ip','link','set','lo','up'])
 run(['ip','link','add','dummy0','type','veth','peer','name','peer0'])
 run(['ip','addr','add','192.0.2.10/24','dev','dummy0'])
 run(['ip','link','set','dummy0','up'])
 run(['ip','link','set','peer0','up'])
 run(['ip','route','add','default','dev','dummy0'])
 run(['useradd','--system','--no-create-home','satsuma-dns'])
 # Fixture: deterministic synthetic authority for the direct root-NS readiness probe.
 def authority():
  with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
   s.bind(('127.0.0.2',5353))
   while True:
    packet,addr=s.recvfrom(65535)
    s.sendto(packet[:2]+struct.pack('!5H',0x8180,1,0,0,0)+packet[12:],addr)
 threading.Thread(target=authority,daemon=True).start()
 (OUT/'dns.conf').write_text('port=53053\nlisten-address=127.0.0.1\nbind-interfaces\nno-resolv\nno-hosts\ncache-size=0\nserver=127.0.0.2#5353\naddress=/example.com/93.184.216.34\naddress=/otx.alienvault.com/192.0.2.20\n')
 dns_process=start(['dnsmasq','--keep-in-foreground','--user=satsuma-dns','--conf-file=/out/dns.conf','--pid-file=','--log-queries','--log-facility=-'],'dnsmasq.log')
 time.sleep(.3)
 (OUT/'fixture.rules').write_text('drop udp any any -> any 53053 (msg:"LAB intentional DNS denial"; content:"|07|blocked|07|example|03|com|00|"; sid:9999991; rev:1;)\n' + 'drop tcp any any -> any 53053 (msg:"LAB intentional TCP DNS denial"; flow:stateless; pkt_data; content:"|07|blocked|07|example|03|com|00|"; sid:9999992; rev:1;)\n')
 suri=start(['suricata','--init-errors-fatal','-c','/etc/suricata/suricata.yaml','--runmode','workers','-q','100','-S','/out/fixture.rules','-l','/out','--set','stream.inline=yes','--set','stream.bypass=no','--set','nfq.mode=accept','--set','nfq.fail-open=no'],'suricata-console.log')
 for _ in range(100):
  if suri.poll() is not None:raise RuntimeError('Suricata exited; see console log')
  if Path('/proc/net/netfilter/nfnetlink_queue').exists() and '100' in Path('/proc/net/netfilter/nfnetlink_queue').read_text():break
  time.sleep(.1)
 else:raise RuntimeError('No NFQUEUE 100 listener')
 ports={'tcp':(53,443),'udp':(53,)}
 core=render_ruleset(ports=ports);nat=dns_script()
 (OUT/'production-core.nft').write_text(core);(OUT/'production-nat.nft').write_text(nat)
 nft(core);nft(nat)
 nft('table inet lab_trace {\n chain out { type filter hook output priority -301; meta nftrace set 1; }\n chain in { type filter hook input priority -301; meta nftrace set 1; }\n}\n')
 start(['nft','monitor','trace'],'trace.log')
 attempt('direct_A',lambda:query('127.0.0.1',53053))
 attempt('direct_readiness_function',_probe_once)
 attempt('redirected_A',lambda:query('208.67.220.220',53))
 import importlib.util
 spec=importlib.util.spec_from_file_location('review_dns_readiness','/code/satsuma/dns_readiness.py')
 wire=importlib.util.module_from_spec(spec);spec.loader.exec_module(wire)
 for transport in ('udp','tcp'):
  attempt('current_direct_'+transport,lambda t=transport:wire.query('127.0.0.1',53053,transport=t))
  attempt('current_redirected_'+transport,lambda t=transport:wire.query('208.67.220.220',53,transport=t))
 (OUT/'system-resolv.conf').write_text('nameserver 208.67.220.220\n')
 attempt('current_system_ready',lambda:wire.probe_system(resolv_path=OUT/'system-resolv.conf'))
 for transport in ('udp','tcp'):
  attempt('suricata_drop_'+transport,lambda t=transport:query('208.67.220.220',53,'blocked.example.com',transport=t))
 # Deliberately broken system path in this disposable namespace only.
 nft('table inet lab_failure {\n chain out { type filter hook output priority 5; ct direction original ct original proto-dst 53 ip daddr 127.0.0.1 drop; }\n}\n')
 attempt('fixture_failure_direct',lambda:wire.query('127.0.0.1',53053))
 attempt('fixture_failure_system',lambda:wire.probe_system(timeout=1,resolv_path=OUT/'system-resolv.conf'))
 nft('delete table inet lab_failure')
 dns_process.terminate();dns_process.wait(timeout=5)
 attempt('dnsmasq_absent_existing_redirect',lambda:wire.query('208.67.220.220',53,timeout=.5))
 results['existing_redirect_retained']=json.loads(run(['nft','-j','list','table','inet','satsuma_dns']).stdout)
 # Fresh-install scenario is a separate owned-table state in the same private lab.
 nft('delete table inet satsuma_dns')
 attempt('dnsmasq_absent_no_redirect',lambda:wire.query('127.0.0.1',53053,timeout=.5))
 attempt('system_without_new_redirect',lambda:wire.query('208.67.220.220',53,timeout=.5))
 results['fresh_install_tables']=json.loads(run(['nft','-j','list','tables']).stdout)
 (OUT/'conntrack.txt').write_text(run(['conntrack','-L']).stdout)
 (OUT/'rules-after.txt').write_text(run(['nft','-a','list','ruleset']).stdout)
 (OUT/'queues.txt').write_text(Path('/proc/net/netfilter/nfnetlink_queue').read_text())
 (OUT/'versions.txt').write_text(run(['suricata','-V']).stdout+run(['nft','--version']).stdout+run(['uname','-r']).stdout)
finally:
 (OUT/'results.json').write_text(json.dumps(results,indent=2))
 for p in processes:
  if p.poll() is None:p.terminate()
 for p in processes:
  try:p.wait(timeout=10)
  except sp.TimeoutExpired:p.kill();p.wait()

# Successful answers and explicit engine verdicts are separate evidence.
verdicts=re.search(r'Verdict: Accepted (\d+), Dropped (\d+)',(OUT/'suricata-console.log').read_text())
assert verdicts and int(verdicts[1])>0 and int(verdicts[2])>0
for name in ('current_direct_udp','current_direct_tcp','current_redirected_udp','current_redirected_tcp','current_system_ready','fixture_failure_direct'):
 assert results[name]['ok'],name
for name in ('suricata_drop_udp','suricata_drop_tcp','fixture_failure_system','dnsmasq_absent_existing_redirect','dnsmasq_absent_no_redirect','system_without_new_redirect'):
 assert not results[name]['ok'],name
assert any(e.get('table',{}).get('name')=='satsuma_dns' for e in results['existing_redirect_retained']['nftables'])
assert not any(e.get('table',{}).get('name')=='satsuma_dns' for e in results['fresh_install_tables']['nftables'])
trace=(OUT/'trace.log').read_text().splitlines();protocols={}
for line in trace:
 if 'ip protocol udp' in line:protocols[line.split()[2]]='udp'
 if 'ip protocol tcp' in line:protocols[line.split()[2]]='tcp'
for protocol in ('udp','tcp'):
 (OUT/(protocol+'-trace.log')).write_text('\n'.join(line for line in trace if protocols.get(line.split()[2])==protocol)+'\n')
(OUT/'validation.json').write_text(json.dumps({'passed':True,'accepted':int(verdicts[1]),'dropped':int(verdicts[2]),'namespace':'private --network none','field_timeout_cause':'UNVERIFIED'},indent=2))
