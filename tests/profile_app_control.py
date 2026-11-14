"""Local CPU profile, NOT an NFQUEUE/Fedora throughput acceptance test.

Uses real Linux socket inventories and process identities. Sends no traffic and
does not bind an NFQUEUE, alter firewall rules, or start services.
"""
import argparse
import cProfile
import io
import json
import os
from pathlib import Path
import pstats
import socket
import struct
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import psutil
from satsuma.app_firewall import Decisions,SocketOwners,identity,parse_packet


def packet(port):
    raw=bytearray(28);raw[0]=0x45;raw[2:4]=(28).to_bytes(2,'big');raw[9]=17
    raw[12:16]=socket.inet_aton('127.0.0.1');raw[16:20]=socket.inet_aton('127.0.0.1')
    raw[20:24]=struct.pack('!HH',port,9)
    return bytes(raw)


def scenario(socket_count,batch_size,packet_count):
    sockets=[]
    try:
        for _ in range(socket_count):
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sockets.append(s);s.bind(('127.0.0.1',0));s.connect(('127.0.0.1',9))
        packets=[packet(s.getsockname()[1]) for s in sockets]
        engine=Decisions();engine.rules[identity(os.getpid())['key']]='allow'
        stages={'inventory_seconds':0.,'index_seconds':0.,'identity_decision_seconds':0.}
        batch_times=[];inventory_count=0;decisions=0
        started=time.perf_counter();cpu=time.process_time()
        for offset in range(0,packet_count,batch_size):
            begin=time.perf_counter()
            entries=psutil.net_connections(kind='inet');after_scan=time.perf_counter()
            owners=SocketOwners(entries);after_index=time.perf_counter();inventory_count+=1
            for n in range(offset,min(offset+batch_size,packet_count)):
                flow=parse_packet(packets[n%len(packets)])
                assert engine.decide(owners.resolve(flow),flow)
                decisions+=1
            end=time.perf_counter()
            stages['inventory_seconds']+=after_scan-begin
            stages['index_seconds']+=after_index-after_scan
            stages['identity_decision_seconds']+=end-after_index
            batch_times.append(end-begin)
        elapsed=time.perf_counter()-started;cpu_elapsed=time.process_time()-cpu
        ordered=sorted(batch_times)
        return {'socket_count':socket_count,'batch_size':batch_size,'decisions':decisions,
            'inventories':inventory_count,'wall_seconds':elapsed,'cpu_seconds':cpu_elapsed,
            'batch_processing_ms_p50':ordered[len(ordered)//2]*1000,
            'batch_processing_ms_p95':ordered[min(len(ordered)-1,int(len(ordered)*.95))]*1000,
            'mean_processing_ms_per_packet':elapsed/decisions*1000,**stages}
    finally:
        for s in sockets:s.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--packets',type=int,default=64)
    args=parser.parse_args()
    if not 1<=args.packets<=4096:parser.error('packets must be 1..4096')
    profile=cProfile.Profile();profile.enable()
    cases=[scenario(n,b,args.packets) for n in (1,64,512) for b in (1,8,32)]
    profile.disable();stream=io.StringIO()
    pstats.Stats(profile,stream=stream).strip_dirs().sort_stats('cumulative').print_stats(25)
    report={'scope':'Local socket/process CPU profile; no packets queued or sent',
        'native_fedora_verified':False,'throughput_verified':False,
        'kernel_queue_wait_measured':False,'kernel_drops_measured':False,
        'cases':cases,'profile_top':stream.getvalue()}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    args.out.write_text(json.dumps(report,indent=2))
    print(json.dumps({'cases':len(cases),'report':str(args.out)}))


if __name__=='__main__':main()
