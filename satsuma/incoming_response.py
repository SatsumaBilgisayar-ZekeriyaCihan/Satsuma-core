"""Automatic IP responses affect ORIGINAL incoming traffic only.

Manual bidirectional isolation remains a separate, authenticated operator action.
A remote peer name or reply packet does not establish incoming initiation.
"""
import ipaddress
import os
from pathlib import Path
import re
import sqlite3
from .sqlite_closing import ClosingConnection
import time


def incoming_peer(ip):
    from integrations.satsuma_guard import command, local_ips
    address=ipaddress.ip_address(ip)
    result=command(['conntrack','-L','-f','ipv4' if address.version==4 else 'ipv6','-s',str(address)])
    if result.returncode:
        raise RuntimeError('Conntrack direction unavailable: '+result.stderr[:200])
    own=local_ips()
    if str(address) in own:return False
    for line in result.stdout.splitlines():
        if not line.startswith(('tcp ','udp ')):continue
        match=re.search(r'\bsrc=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)',line)
        if match and str(ipaddress.ip_address(match[1]))==str(address) and str(ipaddress.ip_address(match[2])) in own:
            return True
    return False


def block(worker,ip,reason,raw_id=None):
    from integrations.satsuma_guard import Guard, DEFAULT_CONFIG, get_config
    from .protected_storage import open_directory
    if not incoming_peer(ip):
        result={'status':'outbound_or_direction_unverified','ip':ip,'executed':False}
        worker.store.add('actions',{'timestamp':time.time(),'action':'incoming_block','reason':reason,**result})
        return result
    cfg=get_config(DEFAULT_CONFIG)
    if cfg['mode']!='block':return {'status':'observe_only','ip':ip,'executed':False}
    cfg={**cfg,'otx_enabled':False,'subnet_enabled':False}
    os.close(open_directory(Path(cfg['state_dir'])))
    service=Guard(cfg,core_store=worker.store)
    try:
        return service.block(ip,reason,raw_id=raw_id,direction='inbound_original')
    finally:
        service.events.close();service.db.close()


def unblock_existing(worker,ip):
    from integrations.satsuma_guard import Nft, DEFAULT
    from .protected_storage import check
    path=Path(DEFAULT['state_dir'])/'guard.sqlite'
    if not path.exists():return
    check(path.lstat());check(path.parent.lstat(),True)
    with sqlite3.connect('file:'+str(path)+'?mode=rw',uri=True,timeout=5,factory=ClosingConnection) as db:
        if not db.execute('SELECT 1 FROM blocks WHERE ip=?',(ip,)).fetchone():return
        nft=Nft();nft.verify_layout();nft.unblock(ip)
        db.execute('DELETE FROM blocks WHERE ip=?',(ip,));db.commit()
    worker.store.add('actions',{'timestamp':time.time(),'action':'incoming_unblock','ip':ip,
                                'status':'set_absence_confirmed','scope':'incoming_original_only'})
