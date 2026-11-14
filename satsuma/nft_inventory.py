"""Read-only kernel-set inventory; never runs mutation, flush or setup commands."""
import ipaddress
import json
import subprocess
import time

OWNED={'satsuma_core':{'blocked_ips','blocked_ips_v6'},'satsuma_otx_guard':{'blocked_v4','blocked_v6'}}


def parse_owned_sets(data):
    sets=[];union=set();unparsed=0
    for entry in data.get('nftables',[]):
        item=entry.get('set') or {}
        if item.get('family')!='inet' or item.get('name') not in OWNED.get(item.get('table'),set()):continue
        addresses=set()
        for elem in item.get('elem') or []:
            value=elem.get('elem',{}).get('val') if isinstance(elem,dict) and 'elem' in elem else elem
            try:addresses.add(str(ipaddress.ip_address(value)))
            except (ValueError,TypeError):unparsed+=1
        union|=addresses
        sets.append({'family':'inet','table':item['table'],'set':item['name'],'element_count':len(addresses)})
    return {'data_state':'PARTIAL' if unparsed else 'OK','sets':sets,'unique_ip_count':len(union) if not unparsed else None,'known_unique_ip_count':len(union),
            'unparsed_elements':unparsed,'scope':'current Satsuma-owned kernel IP sets; union deduplicated across tables',
            'traffic_drop_verified':False,'observed_at':time.time()}


def snapshot(runner=None):
    try:
        result=(runner or subprocess.run)(['/usr/sbin/nft','-j','list','ruleset'],capture_output=True,text=True,timeout=3)
        if result.returncode or len(result.stdout)>4*1024*1024:raise ValueError()
        return parse_owned_sets(json.loads(result.stdout))
    except (OSError,ValueError,TypeError,subprocess.TimeoutExpired):
        return {'data_state':'UNKNOWN','unique_ip_count':None,'sets':[],
                'error':'kernel_set_inventory_unavailable','traffic_drop_verified':False}
