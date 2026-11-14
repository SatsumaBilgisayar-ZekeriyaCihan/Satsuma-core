#!/usr/bin/env python3
"""Read-only bounded browser RAM snapshot: identities, mappings and hashes only.

Salt okunur sınırlı tarayıcı RAM incelemesi: kimlik, eşleme ve yalnız özetler.
No raw dumps, credentials, script source, process signals or system changes.
Ham döküm, kimlik bilgisi, betik içeriği, sinyal veya sistem değişikliği yoktur.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import uuid

PROC=Path('/proc')
MAP_LIMIT=1024*1024
TOTAL_BYTES=8*1024*1024
PROCESS_BYTES=512*1024
MAX_PROCESSES=32
MAX_REGIONS=64
MAX_THREADS=32
FAMILIES={'firefox':'firefox','firefox-bin':'firefox','chrome':'chromium','chromium':'chromium',
          'chromium-browser':'chromium','opera':'opera/chromium','brave':'chromium',
          'brave-browser':'chromium','msedge':'chromium'}


def bounded_text(path,limit):
    with path.open('rb') as stream:data=stream.read(limit+1)
    if len(data)>limit:raise ValueError('metadata_limit_exceeded')
    return data.decode('utf-8',errors='replace')


def identity(directory):
    fields=bounded_text(directory/'stat',4096).rsplit(')',1)[1].split()
    return {'pid':int(directory.name),'starttime':int(fields[19]),'ppid':int(fields[1]),
            'exe':os.readlink(directory/'exe')}


def browser_identity(directory,deadline):
    original=identity(directory);current=directory;seen=set();witnesses=[]
    for _ in range(6):
        if time.monotonic()>=deadline:raise TimeoutError('discovery_deadline')
        value=identity(current)
        if value['pid'] in seen:break
        seen.add(value['pid']);witnesses.append((current,value))
        family=FAMILIES.get(Path(value['exe']).name)
        if family:
            if any(identity(path)!=witness for path,witness in witnesses):
                raise ValueError('ancestry_changed')
            if identity(directory)!=original:raise ValueError('process_identity_changed')
            return original,{'family_hint':family,'witness_pid':value['pid'],
                             'origin_verified':False,'method':'executable_name_and_bounded_ancestry'}
        if value['ppid']<=1:break
        current=directory.parent/str(value['ppid'])
    return None,None


def thread_hints(directory,deadline):
    result={'sampled_threads':0,'worker_name_hints':0,'complete':False,'js_worker_verified':False}
    try:
        with os.scandir(directory/'task') as entries:
            for index,entry in enumerate(entries):
                if index>=MAX_THREADS or time.monotonic()>=deadline:break
                if not entry.name.isdigit():continue
                try:name=bounded_text(Path(entry.path)/'comm',256).lower()
                except OSError:continue
                result['sampled_threads']+=1
                if any(t in name for t in ('dom worker','web worker','js helper','dedicatedwork','serviceworker','sharedworker')):
                    result['worker_name_hints']+=1
            else:result['complete']=True
    except OSError:result['error']='thread_metadata_unavailable'
    return result


def scan(directory,who,attribution,budget,deadline):
    result={'identity':who,'browser':attribution,'status':'UNVERIFIED','bytes_read':0,
            'valid_snapshot_read_bytes':0,'candidate_bytes':0,'candidate_regions':0,
            'memory_access_denied':False,'regions':[],'raw_memory_persisted':False,
            'trusted_reference_verified_bytes':0,'malicious_code_verified':False,
            'coverage':'BOUNDED_PARTIAL','intervention_executed':False}
    try:
        if identity(directory)!=who:raise ValueError('process_identity_changed')
        maps=bounded_text(directory/'maps',MAP_LIMIT);regions=[]
        for line in maps.splitlines():
            fields=line.split(None,5)
            if len(fields)<5:raise ValueError('invalid_maps')
            if 'x' not in fields[1]:continue
            start,end=(int(v,16) for v in fields[0].split('-'))
            if end<=start:raise ValueError('invalid_mapping_range')
            path=fields[5] if len(fields)>5 else ''
            kind='memfd' if 'memfd:' in path else 'deleted' if path.endswith(' (deleted)') else 'file' if path.startswith('/') else 'anonymous_or_kernel'
            regions.append((start,end,int(fields[2],16),fields[1],kind))
            result['candidate_bytes']+=end-start
        result['candidate_regions']=len(regions)
        # Only fixed class labels are retained, never arbitrary mapping names.
        result['threads']=thread_hints(directory,deadline)
        with (directory/'mem').open('rb',buffering=0) as memory:
            for start,end,offset,permissions,kind in regions[:MAX_REGIONS]:
                if result['bytes_read']>=budget or time.monotonic()>=deadline:break
                row={'address':hex(start),'mapped_bytes':end-start,'file_offset':offset,
                     'permissions':permissions,'class':kind,'bytes_read':0,'status':'UNREAD'}
                if start>=2**63:
                    row['status']='KERNEL_METADATA_ONLY';result['regions'].append(row);continue
                size=min(end-start,budget-result['bytes_read'])
                try:
                    data=os.pread(memory.fileno(),size,start)
                    row['bytes_read']=len(data);result['bytes_read']+=len(data)
                    row['status']='OBSERVED_UNVERIFIED' if len(data)==size else 'SHORT_READ'
                    if data:row['sample_sha256']=hashlib.sha256(data).hexdigest()
                    del data
                except PermissionError:row['status']='ACCESS_DENIED'
                except OSError:row['status']='UNREADABLE'
                result['regions'].append(row)
        if identity(directory)!=who:raise ValueError('process_identity_changed')
        if bounded_text(directory/'maps',MAP_LIMIT)!=maps:raise ValueError('mapping_changed')
        result['status']='OBSERVED_UNVERIFIED' if result['bytes_read'] else 'NO_MEMORY_READ'
        result['valid_snapshot_read_bytes']=result['bytes_read']
    except PermissionError:
        result.update(status='ACCESS_DENIED',memory_access_denied=True,reason='existing_permissions_denied_read')
    except (OSError,ValueError,IndexError) as exc:
        result.update(status='INVALIDATED',reason=type(exc).__name__+': '+str(exc)[:120])
    if result['status'] not in ('OBSERVED_UNVERIFIED','NO_MEMORY_READ'):
        result['valid_snapshot_read_bytes']=0
        for row in result['regions']:row.pop('sample_sha256',None);row['status']='INVALIDATED'
    return result


def read_setting(path):
    try:return bounded_text(Path(path),64).strip()
    except OSError:return 'UNAVAILABLE'


def collect(proc=PROC):
    started=time.time();deadline=time.monotonic()+10
    result={'schema_version':1,'started_at':started,'scope':'bounded browser executable RAM; not all RAM or JavaScript source',
            'raw_memory_persisted':False,'malware_verdict':'NOT_DETERMINED','clean_result_claimed':False,
            'trusted_reference_provider_configured':False,'system_changes':False,'signals_sent':False,
            'ptrace_scope':read_setting('/proc/sys/kernel/yama/ptrace_scope'),
            'selinux_enforce':read_setting('/sys/fs/selinux/enforce'),
            'boot_id':read_setting('/proc/sys/kernel/random/boot_id'),
            'limits':{'total_bytes':TOTAL_BYTES,'process_bytes':PROCESS_BYTES,'processes':MAX_PROCESSES,
                      'time_seconds':10,'regions_per_process':MAX_REGIONS,'threads_per_process':MAX_THREADS},
            'processes':[],'discovery_errors':0,'discovery_complete':True,'bytes_read':0,'valid_snapshot_read_bytes':0}
    found=[]
    # Bound discovery too; no command lines, environment or socket contents.
    with os.scandir(proc) as entries:
        for index,entry in enumerate(entries):
            if index>=32768 or time.monotonic()>=deadline:
                result['discovery_complete']=False;break
            if not entry.name.isdigit():continue
            try:
                who,hint=browser_identity(Path(entry.path),deadline)
                if who:found.append((Path(entry.path),who,hint))
            except (OSError,ValueError,IndexError):result['discovery_errors']+=1
    result['browser_candidates']=len(found)
    for path,who,hint in found[:MAX_PROCESSES]:
        if result['bytes_read']>=TOTAL_BYTES or time.monotonic()>=deadline:break
        row=scan(path,who,hint,min(PROCESS_BYTES,TOTAL_BYTES-result['bytes_read']),min(deadline,time.monotonic()+.1))
        result['processes'].append(row);result['bytes_read']+=row['bytes_read']
        result['valid_snapshot_read_bytes']+=row['valid_snapshot_read_bytes']
    result['unexamined_candidates']=len(found)-len(result['processes'])
    result['finished_at']=time.time();result['elapsed_seconds']=result['finished_at']-started
    return result


def save(report,directory):
    # Never overwrite an existing result or follow a substituted final directory.
    directory=Path(directory)
    if directory.is_symlink():raise PermissionError('Evidence directory must not be a symlink')
    directory.mkdir(mode=0o700,parents=False,exist_ok=True)
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        info=os.fstat(fd)
        if info.st_uid!=os.geteuid() or stat.S_IMODE(info.st_mode)!=0o700:
            raise PermissionError('Evidence directory must be owned by the executing UID with mode 0700')
        name='ram-'+time.strftime('%Y%m%d-%H%M%S',time.gmtime())+'-'+uuid.uuid4().hex[:8]+'.json'
        out=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        with os.fdopen(out,'w') as stream:
            json.dump(report,stream,ensure_ascii=False,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        return directory/name
    finally:os.close(fd)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir',default='/var/tmp/satsuma-ram-evidence')
    args=parser.parse_args();report=collect();path=save(report,args.output_dir)
    print(json.dumps({'result_file':str(path),'browser_candidates':report['browser_candidates'],
         'examined':len(report['processes']),'bytes_read':report['bytes_read'],
         'valid_snapshot_read_bytes':report['valid_snapshot_read_bytes'],
         'malware_verdict':report['malware_verdict'],'raw_memory_persisted':False},ensure_ascii=False,indent=2))


if __name__=='__main__':main()
