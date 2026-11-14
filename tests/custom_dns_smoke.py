"""Prove a user-added hosts feed reaches a real DNS answer in an isolated netns."""
import json,os,socket,struct,subprocess,tempfile,time
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).parents[1]))
from satsuma import custom_dns_lists as c
from satsuma.dnsmasq_control import render

if os.readlink('/proc/self/ns/net')==os.readlink('/proc/1/ns/net'):raise RuntimeError('Refusing host namespace')
subprocess.run(['/usr/sbin/ip','link','set','lo','up'],check=True)
class Store:
    def __init__(self):self.data={}
    def get(self,key,default=None):return self.data.get(key,default)
    def set(self,key,value):self.data[key]=value
    def add(self,*args):pass
store=Store();store.set('dns_policy',{'upstream':'192.0.2.1','enabled':True})
c.change(store,'https://feed.example/hosts','update',lambda:{'status':'configured'},fetcher=lambda url:b'0.0.0.0 malware-block.example\n')
with tempfile.TemporaryDirectory() as directory:
    config=Path(directory)/'dnsmasq.conf'
    config.write_text('port=10553\nlisten-address=127.0.0.1\nbind-interfaces\nno-resolv\nno-hosts\n'+render(store.get('dns_policy'),c.blocked_domains(store),[]))
    with tempfile.TemporaryFile() as output:
        process=subprocess.Popen(['/usr/sbin/dnsmasq','--no-daemon','--user=root','--group=root','--conf-file='+str(config)],stdout=output,stderr=output)
        try:
            query=struct.pack('!6H',1234,0x100,1,0,0,0)+b'\x0dmalware-block\x07example\0'+struct.pack('!HH',1,1)
            deadline=time.monotonic()+5;reply=None
            while time.monotonic()<deadline:
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as connection:
                    connection.settimeout(.3);connection.sendto(query,('127.0.0.1',10553))
                    try:reply=connection.recv(4096);break
                    except socket.timeout:pass
            assert reply and len(reply)>=12,'No DNS response'
            ident,flags,questions,answers,*_=struct.unpack('!6H',reply[:12])
            assert ident==1234 and ((flags&15)==3 or ((flags&15)==0 and answers>0 and reply[-4:]==b'\0'*4)),'Custom domain not blocked'
            print(json.dumps({'custom_feed_to_dns_answer':'PASS','scope':'isolated_dnsmasq_hosts_feed','rcode':flags&15,'answers':answers}))
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
