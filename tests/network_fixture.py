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
        # 2.2.16: DHCP, NTP and remote support accepted outside the queue.
        for protocol,ports in [('tcp',{'set':[5938,6568]}),('udp',{'set':[67,123,5938]})]:
            if chain=='output':
                expressions.append([match({'payload':{'protocol':protocol,'field':'dport'}},ports),{'counter':{}},{'accept':None}])
            elif chain=='input':
                expressions.append([match({'ct':{'key':'state'}},'established'),match({'ct':{'key':'direction'}},'reply'),match({'payload':{'protocol':protocol,'field':'sport'}},ports),{'counter':{}},{'accept':None}])
        # 2.2.38: no dnsmasq redirect; DNS goes straight to the pinned resolver.
        for protocol,ports in [('tcp',{'set':[53,443]}),('udp',53)]:
            if chain=='output':
                expressions.append([match({'payload':{'protocol':protocol,'field':'dport'}},ports),{'counter':{}},{'queue':{'num':100}}])
            elif chain=='input':
                expressions.append([match({'ct':{'key':'state'}},'established'),match({'ct':{'key':'direction'}},'reply'),match({'payload':{'protocol':protocol,'field':'sport'}},ports),{'counter':{}},{'queue':{'num':100}}])
        out.extend({'rule':{'chain':chain,'expr':expr}} for expr in expressions)
    return json.dumps({'nftables':out})
