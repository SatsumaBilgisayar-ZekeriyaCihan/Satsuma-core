#!/usr/bin/env python3
"""Live UDP DROP proof in a disposable network namespace only."""
import json
import socket
import subprocess


def run(argv,input=None):
    return subprocess.run(argv,input=input,text=True,capture_output=True,timeout=5,check=True).stdout


def probe(parent_netns=None):
    # This child MUST be launched with unshare --net; never modify the host namespace.
    import os
    import re
    # The parent captures its own namespace before unshare. Reading PID 1's
    # namespace requires ptrace permissions on some Fedora installations;
    # those permissions are deliberately absent from the health service.
    if parent_netns is None or not re.fullmatch(r'net:\[\d+\]',parent_netns):
        raise RuntimeError('Missing original network namespace identity')
    if os.readlink('/proc/self/ns/net')==parent_netns:
        raise RuntimeError('Refusing packet test in original network namespace')
    run(['/usr/sbin/ip','link','set','lo','up'])
    results=[]
    for family,address,nftproto in [(socket.AF_INET,'127.0.0.1','ip'),(socket.AF_INET6,'::1','ip6')]:
        with socket.socket(family,socket.SOCK_DGRAM) as receiver,socket.socket(family,socket.SOCK_DGRAM) as sender:
            receiver.bind((address,0));receiver.settimeout(.4)
            destination=(address,receiver.getsockname()[1])
            sender.sendto(b'baseline',destination)
            assert receiver.recv(64)==b'baseline','Baseline delivery failed'
            script='add table inet satsuma_health_probe\nadd chain inet satsuma_health_probe input { type filter hook input priority -200; policy accept; }\nadd rule inet satsuma_health_probe input '+nftproto+' saddr '+address+' udp dport '+str(destination[1])+' counter drop\n'
            run(['/usr/sbin/nft','-f','-'],script)
            try:
                sender.sendto(b'must_drop',destination)
                try:receiver.recv(64)
                except socket.timeout:pass
                else:raise AssertionError('DROP rule did not stop the test packet')
                rules=json.loads(run(['/usr/sbin/nft','-j','list','table','inet','satsuma_health_probe']))['nftables']
                counters=[term['counter']['packets'] for item in rules if 'rule' in item for term in item['rule']['expr'] if 'counter' in term]
                assert counters and sum(counters)>0,'DROP counter did not confirm packet arrival'
            finally:run(['/usr/sbin/nft','delete','table','inet','satsuma_health_probe'])
            sender.sendto(b'restored',destination)
            assert receiver.recv(64)==b'restored','Delivery after removal failed'
            results.append({'family':nftproto,'baseline':True,'drop_counter_verified':True,'delivery_restored':True})
    return {'scope':'isolated_namespace_udp_ipv4_ipv6_only','packet_drop_verified':True,'results':results,'vendor_sessions_tested':False}


if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument('--parent-netns',required=True)
    print(json.dumps(probe(parser.parse_args().parent_netns)))
