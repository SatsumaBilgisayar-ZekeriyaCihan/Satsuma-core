"""Bounded executable-region observation with disjoint, auditable byte counts.

Ayrık ve denetlenebilir bayt sayaçlarıyla sınırlı yürütülebilir bellek gözlemi.
Referans erişimi hatası, RAM okuma hatası veya doğrulanmış bütünlük değildir.

Only existing /proc read permissions are used. No ptrace/SELinux/sysctl changes,
no raw dumps, and no malware/termination verdict from JIT or memfd presence.
"""
import hashlib
import os
import re
import time
from pathlib import Path

MAP_LIMIT=1024*1024
BYTE_LIMIT=2*1024*1024
CHUNK=16384
REGION_LIMIT=256
CATEGORIES=('valid_snapshot_read_bytes','metadata_only_bytes','budget_skipped_bytes',
            'access_denied_bytes','unreadable_bytes','identity_changed_bytes',
            'mapping_changed_bytes','unclassified_bytes')


def access_model(proc_root=Path('/proc')):
    try:scope=(proc_root/'sys/kernel/yama/ptrace_scope').read_text().strip()
    except OSError:scope='UNKNOWN'
    return {'ptrace_scope':scope,'access_model':'existing_read_only_proc_permissions',
            'policy_changed':False,'selinux_changed':False,
            'cross_process_access':'potentially_denied' if scope=='3' else 'not_verified',
            'reference_trust':'requires_independently_verified_reference_provider'}


def _identity(root):
    return ((root/'stat').read_text().rsplit(')',1)[1].split()[19],os.readlink(root/'exe'))


def scan_executable_regions(directory,*,byte_limit=BYTE_LIMIT,time_limit=.05,
        region_offset=0,region_byte_offset=0,resume_identity=None,trusted_reference_reader=None):
    root=Path(directory);started=time.perf_counter();cpu=time.process_time()
    maximum=max(0,min(int(byte_limit),BYTE_LIMIT));limit=max(0,min(float(time_limit),.25))
    deadline=time.monotonic()+limit
    report={'status':'UNVERIFIED','coverage':'UNKNOWN','bytes_read':0,'regions_read':0,
        'access_denied_regions':0,'unreadable_regions':0,'skipped_regions':0,
        'candidate_regions':0,'candidate_bytes':0,'anonymous_regions':0,'memfd_regions':0,
        'file_backed_regions':0,'unclassified_regions':0,'regions':[],
        'reference_verified_bytes':0,'reference_unavailable_regions':0,
        'reference_compared_bytes':0,'reference_match_bytes':0,'reference_difference_bytes':0,
        'reference_access_denied_chunks':0,'reference_error_chunks':0,
        'byte_limit':maximum,'time_limit_seconds':limit,'mapping_metadata_available':False,
        'mapping_denominator_incomplete':True,'next_region_offset':0,'next_region_byte_offset':0,
        'scope':'executable mappings of this process, this pass; not total system RAM',
        'raw_memory_persisted':False,'intervention_authorized':False,'clean_result_claimed':False,
        'coverage_categories':dict.fromkeys(CATEGORIES,0),'invalidated_read_bytes':0}
    categories=report['coverage_categories']

    def finish(status,coverage,reason=None,invalidate=None):
        report.update(status=status,coverage=coverage,elapsed_seconds=time.perf_counter()-started,cpu_seconds=time.process_time()-cpu)
        if reason:report['reason']=reason
        if invalidate:
            for key in CATEGORIES:categories[key]=0
            categories[invalidate]=report['candidate_bytes']
            report['invalidated_read_bytes']=report['bytes_read']
            report['reference_verified_bytes']=0
            report['reference_compared_bytes']=report['reference_match_bytes']=report['reference_difference_bytes']=0
            report['mapping_denominator_incomplete']=True
            for row in report['regions']:
                row['status']='INVALIDATED';row['reference_status']='INVALIDATED';row.pop('sample_sha256',None)
        known=report['candidate_bytes'];valid=categories['valid_snapshot_read_bytes']
        complete_denominator=report['mapping_metadata_available'] and not report['mapping_denominator_incomplete']
        report['read_coverage_percent']=round(100*valid/known,4) if known and complete_denominator else None
        report['partial_observed_coverage_percent']=round(100*valid/known,4) if known and not complete_denominator and not invalidate else None
        report['trusted_reference_coverage_percent']=round(100*report['reference_verified_bytes']/known,4) if known and complete_denominator else None
        report['coverage_formula']='100 * valid_snapshot_read_bytes / executable mapping bytes in this process snapshot; unknown mappings never enter the numerator'
        report['category_total_bytes']=sum(categories.values())
        report['category_totals_consistent']=report['category_total_bytes']==known
        for key in CATEGORIES:report[key]=categories[key]
        return report

    try:
        before=_identity(root)
        with (root/'maps').open() as stream:maps=stream.read(MAP_LIMIT+1)
        if len(maps)>MAP_LIMIT:return finish('UNVERIFIED','UNKNOWN','mapping_list_truncated')
        candidates=[]
        report['mapping_metadata_available']=True;report['mapping_denominator_incomplete']=False
        for line in maps.splitlines():
            if not line.strip():continue
            fields=line.split(None,5)
            try:
                start,end=(int(v,16) for v in fields[0].split('-'))
                if end<=start:raise ValueError()
            except (ValueError,IndexError):
                report['unclassified_regions']+=1;report['mapping_denominator_incomplete']=True;continue
            if len(fields)<5 or not re.fullmatch(r'[r-][w-][x-][ps]',fields[1]):
                report['unclassified_regions']+=1;report['mapping_denominator_incomplete']=True
                report['candidate_bytes']+=end-start;categories['unclassified_bytes']+=end-start
                continue
            if 'x' not in fields[1]:continue
            name=fields[5] if len(fields)>5 else ''
            kind='memfd' if 'memfd:' in name else 'file_backed' if name.startswith('/') and not name.endswith(' (deleted)') else 'anonymous_or_deleted'
            candidates.append((start,end,int(fields[2],16),fields[1],name,kind))
            report['candidate_bytes']+=end-start
            report['memfd_regions' if kind=='memfd' else 'file_backed_regions' if kind=='file_backed' else 'anonymous_regions']+=1
        report['candidate_regions']=len(candidates)
        if not candidates:
            return finish('UNCLASSIFIED_MAPPINGS','UNKNOWN') if report['unclassified_regions'] else finish('NO_EXECUTABLE_REGIONS','NOT_APPLICABLE')
        scan_identity=hashlib.sha256((repr(before)+maps).encode()).hexdigest();report['scan_identity']=scan_identity
        if resume_identity!=scan_identity:region_offset=0;region_byte_offset=0
        offset=max(0,int(region_offset))%len(candidates);ordered=candidates[offset:]+candidates[:offset]
        remaining=maximum
        try:memory=(root/'mem').open('rb',buffering=0)
        except PermissionError:
            report['access_denied_regions']=len(candidates)
            categories['access_denied_bytes']=sum(end-start for start,end,*_ in candidates)
            return finish('ACCESS_DENIED','NONE','kernel_denied_process_memory')
        except OSError:
            report['unreadable_regions']=len(candidates)
            categories['unreadable_bytes']=sum(end-start for start,end,*_ in candidates)
            return finish('UNREADABLE','NONE','process_memory_unavailable')
        with memory:
            for index,(start,end,file_offset,perms,name,kind) in enumerate(ordered):
                if remaining<=0 or time.monotonic()>=deadline or index>=REGION_LIMIT:
                    categories['budget_skipped_bytes']+=sum(b-a for a,b,*_ in ordered[index:])
                    report['skipped_regions']+=len(ordered)-index
                    report['next_region_offset']=(offset+index)%len(candidates);break
                row={'mapping_class':kind,'mapped_bytes':end-start,'bytes_read':0,'permissions':perms,
                     'status':'UNVERIFIED','reference_status':'NOT_AVAILABLE','jit_possible':kind in ('anonymous_or_deleted','memfd')}
                position=max(0,min(int(region_byte_offset),end-start-1)) if index==0 else 0
                row['sample_offset']=position
                # Bytes preceding a resume cursor were not read in this pass.
                categories['budget_skipped_bytes']+=position
                if name=='[vsyscall]' or end>2**63-1:
                    row['status']='METADATA_ONLY_KERNEL_MAPPING'
                    categories['metadata_only_bytes']+=end-start-position
                    report['regions'].append(row);continue
                fingerprint=hashlib.sha256();difference=False;reference_bytes=0
                try:
                    while position<end-start and remaining>0 and time.monotonic()<deadline:
                        size=min(CHUNK,end-start-position,remaining)
                        data=os.pread(memory.fileno(),size,start+position)
                        if not data:
                            row['status']='SHORT_READ';break
                        fingerprint.update(data);read=len(data)
                        row['bytes_read']+=read;report['bytes_read']+=read;categories['valid_snapshot_read_bytes']+=read
                        remaining-=read
                        if kind=='file_backed' and trusted_reference_reader is not None:
                            # The provider is a trust boundary, not a disk/hash fallback.
                            # Failure to obtain a reference never erases a valid RAM read.
                            try:
                                expected=trusted_reference_reader({'path':name,'offset':file_offset+position,
                                    'mapping_start':start,'mapping_end':end,'process_identity':before,
                                    'scan_identity':scan_identity},read)
                            except PermissionError:
                                expected=None;report['reference_access_denied_chunks']+=1
                            except (OSError,RuntimeError,ValueError):
                                expected=None;report['reference_error_chunks']+=1
                            if isinstance(expected,bytes) and len(expected)==read:
                                reference_bytes+=read;different=data!=expected;difference|=different
                                report['reference_compared_bytes']+=read
                                report['reference_difference_bytes' if different else 'reference_match_bytes']+=read
                        position+=read
                        if read<size:row['status']='SHORT_READ';break
                    if row['bytes_read']:
                        row['sample_sha256']=fingerprint.hexdigest();report['regions_read']+=1
                        if row['status']=='UNVERIFIED':row['status']='OBSERVED_UNVERIFIED'
                        if reference_bytes==row['bytes_read'] and kind=='file_backed':
                            row['reference_status']='TRUSTED_REFERENCE_DIFFERENCE_REQUIRES_RELOCATION_REVIEW' if difference else 'CHECKED_BYTES_MATCH_TRUSTED_REFERENCE'
                            report['reference_verified_bytes']+=reference_bytes
                        else:report['reference_unavailable_regions']+=1
                    if row['status']=='SHORT_READ':
                        report['unreadable_regions']+=1;categories['unreadable_bytes']+=end-start-position
                    elif position<end-start:
                        categories['budget_skipped_bytes']+=end-start-position;report['skipped_regions']+=1
                except PermissionError:
                    row['status']='ACCESS_DENIED';report['access_denied_regions']+=1;categories['access_denied_bytes']+=end-start-position
                except (OSError,OverflowError):
                    row['status']='UNREADABLE';report['unreadable_regions']+=1;categories['unreadable_bytes']+=end-start-position
                report['regions'].append(row);report['next_region_offset']=(offset+index+1)%len(candidates)
                if position<end-start and (remaining<=0 or time.monotonic()>=deadline):
                    report['next_region_offset']=(offset+index)%len(candidates);report['next_region_byte_offset']=position
                    categories['budget_skipped_bytes']+=sum(b-a for a,b,*_ in ordered[index+1:])
                    report['skipped_regions']+=len(ordered)-index-1;break
        if _identity(root)!=before:return finish('IDENTITY_CHANGED','UNVERIFIED','process_identity_changed',invalidate='identity_changed_bytes')
        with (root/'maps').open() as stream:after=stream.read(MAP_LIMIT+1)
        if maps!=after:return finish('MAPPINGS_CHANGED','UNVERIFIED',invalidate='mapping_changed_bytes')
        unread=report['candidate_bytes']-categories['valid_snapshot_read_bytes']
        status='OBSERVED_UNVERIFIED' if report['bytes_read'] else 'ACCESS_DENIED' if report['access_denied_regions'] else 'UNREADABLE'
        return finish(status,'COMPLETE_BYTE_READ' if not unread else 'PARTIAL')
    except PermissionError:return finish('ACCESS_DENIED','NONE','process_metadata_access_denied')
    except (OSError,ValueError,IndexError):return finish('UNVERIFIED','UNKNOWN','process_unavailable_or_invalid_maps',invalidate='unclassified_bytes' if report['candidate_bytes'] else None)
