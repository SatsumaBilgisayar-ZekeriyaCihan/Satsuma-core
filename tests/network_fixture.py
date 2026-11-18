"""Independent nft JSON fixture for the installed strict policy."""
import json

def table_json():
    out=[{'table':{'family':'inet','name':'satsuma_core','comment':'Satsuma Core managed'}}]
    for suffix,typ in [('', 'ipv4_addr'),('_v6','ipv6_addr')]:
        out.append({'set':{'name':'blocked_ips'+suffix,'type':typ}})
    def match(left,right):return {'match':{'op':'in' if left=={'ct':{'key':'state'}} else '==','left':left,'right':right}}
    for chain in ('input','output','forward'):
        out.append({'chain':{'name':chain,'type':'filter','hook':chain,'prio':0,'policy':'drop'}})
        # 2.2.9: IPv6 is dropped first in every chain (as nft -j prints it).
        expressions=[[match({'meta':{'key':'nfproto'}},'ipv6'),{'counter':{'packets':0,'bytes':0}},{'drop':None}]]
        if chain!='forward':
            # 2.2.13: loopback closed except replies and the listed local services.
            key='iifname' if chain=='input' else 'oifname'
            lo=match({'meta':{'key':key}},'lo')
            expressions.append([lo,match({'ct':{'key':'state'}},['established','related']),{'accept':None}])
            expressions.append([lo,match({'payload':{'protocol':'tcp','field':'dport'}},{'set':[53,5939]}),{'accept':None}])
            expressions.append([lo,match({'payload':{'protocol':'udp','field':'dport'}},53),{'accept':None}])
            expressions.append([lo,{'counter':{'packets':0,'bytes':0}},{'drop':None}])
        expressions.append([match({'ct':{'key':'state'}},'invalid'),{'drop':None}])
        directions=['saddr','daddr'] if chain=='forward' else ['saddr' if chain=='input' else 'daddr']
        for direction in directions:
            for protocol,setname in [('ip','blocked_ips'),('ip6','blocked_ips_v6')]:
                expressions.append([match({'payload':{'protocol':protocol,'field':direction}},'@'+setname),{'counter':{'packets':0,'bytes':0}},{'drop':None}])
        # 2.2.38: no dnsmasq redirect; DNS goes straight to the pinned resolver.
        # 2.2.41 (owner: no channel may bypass Suricata): DHCP 67, NTP 123,
        # TeamViewer 5938 and AnyDesk 6568 are queued with the profile ports;
        # from 2.2.16 to 2.2.40 they were accepted outside the queue.
        for protocol,ports in [('tcp',{'set':[53,443,5938,6568]}),('udp',{'set':[53,67,123,5938]})]:
            if chain=='output':
                expressions.append([match({'payload':{'protocol':protocol,'field':'dport'}},ports),{'counter':{}},{'queue':{'num':100}}])
            elif chain=='input':
                expressions.append([match({'ct':{'key':'state'}},'established'),match({'ct':{'key':'direction'}},'reply'),match({'payload':{'protocol':protocol,'field':'sport'}},ports),{'counter':{}},{'queue':{'num':100}}])
        if chain=='forward':
            # 2.2.44: the DNS filter in its own namespace is the only forwarded
            # traffic: to OpenDNS port 53 and its replies, through queue 100.
            upstreams={'set':['208.67.222.222','208.67.220.220']}
            for protocol in ('tcp','udp'):
                expressions.append([match({'meta':{'key':'iifname'}},'satsuma-dns0'),match({'payload':{'protocol':'ip','field':'saddr'}},'169.254.53.2'),
                                    match({'payload':{'protocol':'ip','field':'daddr'}},upstreams),match({'payload':{'protocol':protocol,'field':'dport'}},53),
                                    {'counter':{'packets':0,'bytes':0}},{'queue':{'num':100}}])
            for protocol in ('tcp','udp'):
                expressions.append([match({'meta':{'key':'oifname'}},'satsuma-dns0'),match({'payload':{'protocol':'ip','field':'daddr'}},'169.254.53.2'),
                                    match({'ct':{'key':'state'}},'established'),match({'ct':{'key':'direction'}},'reply'),
                                    match({'payload':{'protocol':'ip','field':'saddr'}},upstreams),match({'payload':{'protocol':protocol,'field':'sport'}},53),
                                    {'counter':{'packets':0,'bytes':0}},{'queue':{'num':100}}])
        out.extend({'rule':{'chain':chain,'expr':expr}} for expr in expressions)
    return json.dumps({'nftables':out})
