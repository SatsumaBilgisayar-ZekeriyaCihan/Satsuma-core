#!/usr/bin/env python3
import sys,os,pwd,json,subprocess
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
def main():
    if os.geteuid()!=0:raise SystemExit('sudo satsuma-admin <status|pause|resume|unblock IP|allow IP|unallow IP>')
    args=sys.argv[1:]
    if not args:args=['status']
    user=pwd.getpwnam('satsuma-core')
    # Run state changes as the service owner; preserve database ownership.
    from satsuma.network_control import run,TABLE
    import ipaddress
    if args[0] in ('unblock','allow'):
        ip=str(ipaddress.ip_address(args[1]));name='blocked_ips_v6' if ':' in ip else 'blocked_ips'
        r=run(['delete','element','inet',TABLE,name,'{',ip,'}'])
        if run(['get','element','inet',TABLE,name,'{',ip,'}']).returncode==0:raise SystemExit('Engel kaldirilamadi: '+r.stderr)
    os.setgroups([]);os.setgid(user.pw_gid);os.setuid(user.pw_uid);os.umask(0o077)
    from satsuma.store import Store
    store=Store()
    try:
        action=args[0]
        if action in ('unblock','allow','unallow'):
            ip=str(ipaddress.ip_address(args[1]));blocks=store.get('persistent_blocks',{});blocks.pop(ip,None);store.set('persistent_blocks',blocks)
            allow=set(store.get('operator_allow_ips',[]))
            if action in ('allow','unblock'):allow.add(ip)
            else:allow.discard(ip)
            store.set('operator_allow_ips',sorted(allow))
        elif action!='status':raise SystemExit('Unknown command')
        print(json.dumps({'allow_ips':store.get('operator_allow_ips',[]),
                          'blocks':store.get('persistent_blocks',{}),'health':store.get('health',{}),'brain':store.get('brain.health',{})},indent=2))
    finally:store.close()
if __name__=='__main__':main()
