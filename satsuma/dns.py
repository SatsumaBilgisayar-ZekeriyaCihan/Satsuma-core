"""DNSMonitorWorker: EVE v2/v3 records, bounded context and explicit policy actions."""
import ipaddress
import time
from collections import OrderedDict, deque


def domain(value):
    if not isinstance(value,str) or not value or len(value)>253: raise ValueError('invalid DNS name')
    value=value.rstrip('.').lower()
    if any(ord(c)<33 or ord(c)==127 for c in value): raise ValueError('control/space in DNS name')
    return value


def questions(dns):
    result=[]
    candidates=dns.get('queries') or dns.get('query') or []
    if isinstance(candidates,dict): candidates=[candidates]
    if isinstance(candidates,str): candidates=[{'rrname':candidates,'rrtype':dns.get('rrtype')}]
    if dns.get('rrname'): candidates=[{'rrname':dns['rrname'],'rrtype':dns.get('rrtype')}]+candidates
    if not isinstance(candidates,list): raise ValueError('invalid DNS questions')
    for q in candidates[:128]:
        if not isinstance(q,dict): continue
        name=q.get('rrname') or q.get('name')
        if name:
            item=(domain(name),str(q.get('rrtype','UNKNOWN'))[:16])
            if item not in result:result.append(item)
    return result


class DNSMonitorWorker:
    name='dns_monitor_worker'
    def __init__(self,store,config,clock=time.monotonic):
        self.store,self.config,self.clock=store,config,clock
        self.answers=OrderedDict(); self.flows=OrderedDict();self.failures=OrderedDict()
        self.count=0;self.missing_names=0
        self.requests=0;self.responses=0;self.anomalies=0
        self.nxdomain=0;self.query_name_missing=0;self.domains=set()

    def process(self,event,raw_id):
        dns=event.get('dns')
        if not isinstance(dns,dict): return []
        now=self.clock();src=str(ipaddress.ip_address(event['src_ip']));dst=str(ipaddress.ip_address(event['dest_ip']))
        typ=dns.get('type','unknown')
        response=typ in ('answer','response') or (event.get('src_port')==53 and event.get('dest_port')!=53)
        client,resolver=(dst,src) if response else (src,dst)
        qs=questions(dns)
        flow=(str(event.get('flow_id')),str(event.get('tx_id',dns.get('tx_id'))),str(dns.get('id')),client,resolver)
        if not qs and response:
            previous=self.flows.get(flow)
            if previous and now-previous[0]<120:qs=previous[1]
        if qs and not response:
            self.flows[flow]=(now,qs);self.flows.move_to_end(flow)
        while len(self.flows)>4096:self.flows.popitem(last=False)
        while self.flows and now-next(iter(self.flows.values()))[0]>120:self.flows.popitem(last=False)
        if not qs:self.missing_names+=1;qs=[(None,'UNKNOWN')]
        answers=dns.get('answers',[])
        if not isinstance(answers,list):raise ValueError('invalid DNS answers')
        clean=[]
        for answer in answers[:256]:
            if not isinstance(answer,dict):continue
            rrtype=str(answer.get('rrtype',''))[:16]
            data=str(answer.get('rdata',''))[:4096]
            if rrtype in ('A','AAAA'):data=str(ipaddress.ip_address(data))
            ttl=answer.get('ttl')
            clean.append({'name':answer.get('rrname'),'type':rrtype,'data':data,
                          'ttl':ttl if type(ttl) is int and ttl>=0 else None})
        # Some EVE configurations emit grouped answers instead of detailed answers.
        grouped=dns.get('grouped',{})
        if not clean and isinstance(grouped,dict):
            for typ2,values in grouped.items():
                if typ2 not in ('A','AAAA') or not isinstance(values,list):continue
                for value in values[:128]:clean.append({'name':None,'type':typ2,'data':str(ipaddress.ip_address(value)),'ttl':None})
        result=[]
        for name,rrtype in qs:
            flags=[];changes={};rcode=dns.get('rcode')
            if not name:flags.append('QUERY_NAME_MISSING')
            if name and max(map(len,name.split('.')))>50: flags.append('LONG_LABEL_REVIEW')
            expected=self.config.get('expected_dns_servers',[])
            if expected and resolver not in expected:flags.append('UNEXPECTED_RESOLVER')
            if response and rcode=='NXDOMAIN':
                bucket=self.failures.setdefault(client,deque(maxlen=1000));bucket.append(now);self.failures.move_to_end(client)
                while bucket and now-bucket[0]>60:bucket.popleft()
                if len(bucket)>=20:flags.append('NXDOMAIN_BURST_REVIEW')
            while len(self.failures)>1024:self.failures.popitem(last=False)
            ips=sorted({x['data'] for x in clean if x['type'] in ('A','AAAA')})
            ttls=sorted({x['ttl'] for x in clean if x['ttl'] is not None})
            key=(client,resolver,name,rrtype)
            if name and response and ips:
                previous=self.answers.get(key)
                if previous and now-previous['seen']<3600:
                    if ips!=previous['ips']:flags.append('ANSWER_CHANGED');changes['previous_ips']=previous['ips']
                    if ttls and previous['ttls'] and ttls!=previous['ttls']:flags.append('TTL_CHANGED')
                    if all(ipaddress.ip_address(x).is_global for x in previous['ips']) and any(not ipaddress.ip_address(x).is_global for x in ips):flags.append('PUBLIC_TO_NONPUBLIC_REVIEW')
                self.answers[key]={'ips':ips,'ttls':ttls,'seen':now};self.answers.move_to_end(key)
            while len(self.answers)>4096:self.answers.popitem(last=False)
            while self.answers and now-next(iter(self.answers.values()))['seen']>3600:self.answers.popitem(last=False)
            watch=name in self.config.get('watch_domains',[])
            if watch:flags.append('WATCHED_DOMAIN')
            record={'timestamp':event.get('timestamp'),'flow_id':event.get('flow_id'),'tx_id':event.get('tx_id',dns.get('tx_id')),
                    'raw_id':raw_id,'client':client,'resolver':resolver,'src_ip':src,'dest_ip':dst,
                    'transport':event.get('proto'),'query':name,'rrtype':rrtype,'type':'response' if response else 'request',
                    'rcode':rcode,'answers':clean,'ips':ips,'flags':flags,'changes':changes,
                    'process':None,'process_status':'not_collected','watched':watch,'verdict':'review' if flags else 'observed'}
            self.store.add('dns',record);self.count+=1
            if response:self.responses+=1
            else:self.requests+=1
            if name:self.domains.add(name)
            if flags:self.anomalies+=1
            if str(rcode).upper()=='NXDOMAIN':self.nxdomain+=1
            if 'QUERY_NAME_MISSING' in flags:self.query_name_missing+=1
            result.append(record)
        return result
