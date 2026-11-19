"""Bounded memory metadata and executable-page integrity validation.

The worker's status says whether the check itself works; how much of the
code could be compared is reported separately as coverage. Field report
2026-10-25: the worker showed "Sorunlu çalışıyor" permanently because any
single process it could not fully compare (JIT memory that changes while
it is read, a program updated on disk while running, more than 1 MiB of
code) turned the whole worker DEGRADED. Now DEGRADED means it inspected
nothing, or most processes were unreadable or denied (a capability
problem). A partial comparison is never reported as clean: coverage is
PARTIAL with the reasons, and a verified code difference is still an event.

Sınırlı bellek bilgisi ve çalıştırılabilir sayfa bütünlüğü doğrulaması.

İşçinin durumu denetimin kendisinin çalışıp çalışmadığını söyler; kodun ne
kadarının karşılaştırılabildiği ayrıca kapsam olarak bildirilir. Saha
bildirimi 2026-10-25: işçi sürekli "Sorunlu çalışıyor" gösteriyordu, çünkü
tam karşılaştıramadığı tek bir süreç (okunurken değişen JIT belleği,
çalışırken diskte güncellenen program, 1 MiB'tan fazla kod) bütün işçiyi
DEGRADED yapıyordu. Artık DEGRADED, hiçbir sürecin incelenemediği ya da
süreçlerin çoğunun okunamadığı veya erişimin reddedildiği (yetki sorunu)
anlamına gelir. Kısmi karşılaştırma asla temiz bildirilmez: kapsam
gerekçeleriyle PARTIAL olur ve doğrulanmış kod farkı yine olay üretir.
"""
from pathlib import Path
from .worker_delivery import delivered_tick
from .memory_validation import validate_executable
from .memory_scope import scan_executable_regions, access_model, CATEGORIES
from .anonymous_exec import inventory as unverifiable_exec
from .ram.proc import kernel_thread
import os
import re,time,hashlib


def _replaced_by_update(exe):
    """The running program's file was replaced in place, as a package update does.

    Field 2026-11-04: after a package update every running program of that
    package looked like "running from a deleted file". When a root-owned,
    non-writable file stands at the same path again, the program was
    updated on disk, not deleted to hide; a binary run from /tmp and then
    removed still counts.
    Paket güncellemesinden sonra çalışan programlar "silinmiş dosyadan
    çalışıyor" görünüyordu. Aynı yolda yine root sahipli, yazılamaz bir dosya
    varsa program diskte güncellenmiştir; /tmp'den çalıştırılıp silinen
    program yine sayılır.
    """
    from .trusted_process import trusted_path
    path=exe.removesuffix(' (deleted)')
    return path.startswith('/') and '/memfd:' not in path and trusted_path(path)


def _anonymous(name):
    """Memory with no file behind it: unnamed, [heap], [stack] or a named [anon:...].

    Field review 2026-11-10: only unnamed regions counted, so writable and
    executable heap, stack or a region named with PR_SET_VMA_ANON_NAME (which
    any program may do for itself) escaped the anonymous_rwx indicator.
    Dosyası olmayan bellek: adsız, [heap], [stack] ya da adlandırılmış
    [anon:...]. Önceden yalnızca adsız bölgeler sayılıyordu; yazılabilir ve
    çalıştırılabilir heap, yığın ya da programın kendine ad verdiği bölge
    anonymous_rwx göstergesinden kaçıyordu.
    """
    # Shared anonymous memory (MAP_SHARED|MAP_ANONYMOUS) is shown as
    # "/dev/zero (deleted)" and System V shared memory as "/SYSV... (deleted)";
    # field run 2026-11-11: an rwx shared anonymous region escaped the check.
    # Paylaşımlı anonim bellek "/dev/zero (deleted)", System V paylaşımlı bellek
    # "/SYSV... (deleted)" görünür; rwx paylaşımlı anonim bölge denetimden kaçıyordu.
    return (not name or name in ('[heap]','[stack]','/dev/zero (deleted)') or name.startswith('[stack:')
            or name.startswith('[anon:') or name.startswith('[anon_shmem:')
            or (name.startswith('/SYSV') and name.endswith(' (deleted)')))


# Directories any user can write to. Code mapped from them was not installed
# by a package: a dropped binary or an injected library (LD_PRELOAD, dlopen).
# Herkesin yazabildiği klasörler; buradan eşlenen kod paketle kurulmamıştır.
WRITABLE_PREFIXES=('/tmp/','/var/tmp/','/dev/shm/','/run/user/')


def tracer_pid(directory):
    """TracerPid from status; None when it cannot be read. İzleyen sürecin PID'i."""
    try:
        with (Path(directory)/'status').open(errors='replace') as stream:
            for line in stream.read(65536).splitlines():
                if line.startswith('TracerPid:'):
                    return int(line.split()[1])
    except (OSError,ValueError,IndexError):
        return None
    return None


# 2.2.56 (owner 2026-11-19): a user program that calls itself a kernel thread. Only real
# kernel threads carry PF_KTHREAD (they are skipped before this point), so a process here
# with a kernel thread's name, or a bracketed command line like "[kworker/0:1]", is a
# disguise whatever folder its file is in and whenever it renamed itself.
# Çekirdek iş parçacığı adı taşıyan ama PF_KTHREAD işareti olmayan süreç sahtedir.
KTHREAD_NAME=re.compile(r'^(?:kworker/|ksoftirqd/|migration/|rcu_\w+|rcuo[sp]?/|cpuhp/|idle_inject/|watchdog/|irq/|'
                        r'jbd2/|kswapd\d|kcompactd\d|scsi_eh_|scsi_tmf_|kthreadd$|khugepaged$|kauditd$|oom_reaper$|'
                        r'kblockd$|kintegrityd$|kdevtmpfs$|writeback$|ksmd$|kstrp$|kthrotld$|ecryptfs-kthread$|'
                        r'card\d+-crtc\d|nvme-|xfs-|btrfs-|dm_bufio_cache$|kcryptd/|zswap-)')


def fake_kernel_thread(directory):
    """True when a user process (not PF_KTHREAD) looks like a kernel thread."""
    directory=Path(directory)
    try:
        comm=(directory/'comm').read_text(errors='replace').strip()
        cmdline=(directory/'cmdline').read_bytes()[:256].split(b'\0',1)[0].decode('utf-8','replace').strip()
    except OSError:
        return False
    bracketed=cmdline.startswith('[') and cmdline.endswith(']') and len(cmdline)>2
    return bool(bracketed or KTHREAD_NAME.match(comm) or KTHREAD_NAME.match(cmdline.strip('[]')))


def inspect_process(directory,replaced=_replaced_by_update):
    directory=Path(directory)
    exe=os.readlink(directory/'exe')
    with (directory/'maps').open(errors='replace') as stream:
        lines=stream.read(262144).splitlines()
    indicators=[]
    if '/memfd:' in exe or exe.startswith('memfd:'):
        indicators.append('memfd_executable')
    if exe.endswith(' (deleted)'):
        indicators.append('replaced_executable' if replaced(exe) else 'deleted_executable')
    for line in lines:
        fields=line.split(None,5)
        if len(fields)<5:continue
        perms=fields[1];name=fields[5] if len(fields)>5 else ''
        if 'rwx' in perms and _anonymous(name):
            indicators.append('anonymous_rwx')
        if 'x' in perms and '/memfd:' in name:
            indicators.append('memfd_mapping')
        if 'x' in perms and name.startswith(WRITABLE_PREFIXES):
            indicators.append('writable_dir_code_mapping')
    # Another process attached with ptrace can read and rewrite this one's
    # memory: the classic way to inject code into a running program.
    # ptrace ile bağlanan başka bir süreç bu sürecin belleğini okuyup yazabilir.
    if tracer_pid(directory):
        indicators.append('process_traced')
    if fake_kernel_thread(directory):
        indicators.append('fake_kernel_thread')
    return sorted(set(indicators))


def _tracer_details(path,indicator):
    """Who traces the process, for the process_traced event. İzleyen sürecin kimliği."""
    if indicator!='process_traced':return {}
    tracer=tracer_pid(path)
    try:exe=os.readlink(path.parent/str(tracer)/'exe') if tracer else None
    except OSError:exe=None
    return {'host.tracer_pid':tracer,'host.tracer_exe':exe}


def memory_event(path,indicator,start,validation,scope):
    """The event one memory indicator becomes; the same for the worker and the tests.

    Bir bellek göstergesinin dönüştüğü olay; işçi ve testler için aynıdır.
    """
    path=Path(path)
    return {'source':'memory','kind':'memory','action':indicator,'timestamp':time.time(),'pid':int(path.name),
            'category':'memory','metadata':{'extensions':{'host.pid':int(path.name),'host.starttime':int(start),
            'host.memory_indicator':indicator,**_tracer_details(path,indicator),'host.memory_validation':validation,
            'host.memory_scope':scope,'host.exe':os.readlink(path/'exe')}}}


class WorkerMemory:
    name='memory'
    def __init__(self,store,config=None,proc_root='/proc'):
        self.store=store;self.config=config or {};self.proc_root=Path(proc_root)
        self.last=0;self.seen={};self.cursor=0;self.scope_cursors={};self.ram_v2=None
    @delivered_tick('seen', 'cursor', 'last')
    def tick(self,pipeline=None):
        now=time.monotonic()
        if now-self.last<5:return
        # ClamAV RAM INSTREAM scanning was retired. Keep a distinct status so
        # legacy UI cannot mistake absent signature scans for clean memory.
        self.store.set('worker.ram_v2.health', {
            'status': 'RETIRED', 'scanner_state': 'DISABLED',
            'reason': 'ClamAV RAM scanning removed; executable integrity checks remain',
            'updated_at': time.time()})
        self.last=now;denied=0;vanished=0;count=0;events=0
        validations={};partial=0;reasons={};unverifiable={};unverifiable_processes=0;examples=[]
        scope_totals={'bytes_read':0,'regions_read':0,'access_denied_regions':0,'unreadable_regions':0,
                      'skipped_regions':0,'candidate_regions':0,'candidate_bytes':0,'reference_verified_bytes':0,
                      'reference_compared_bytes':0,'reference_match_bytes':0,'reference_difference_bytes':0,
                      'reference_access_denied_chunks':0,'reference_error_chunks':0,
                      'metadata_only_bytes':0,'access_denied_bytes':0,'unreadable_bytes':0,**dict.fromkeys(CATEGORIES,0)}
        scope_status={};scope_examples=[];scope_deadline=time.monotonic()+.5;scope_budget=8*1024*1024
        pids=sorted(p for p in self.proc_root.iterdir() if p.name.isdigit())
        batch=pids[self.cursor:self.cursor+128]
        self.cursor=self.cursor+128 if self.cursor+128<len(pids) else 0
        kernel_threads=0
        for path in batch:
            try:
                stat_text=(path/'stat').read_text()
                # A kernel thread has no executable or user memory; it is not
                # a vanished process (field 2026-11-10).
                # Çekirdek iş parçacığı kaybolan süreç sayılmaz.
                if kernel_thread(stat_text):
                    kernel_threads+=1
                    continue
                start=stat_text.rsplit(')',1)[1].split()[19]
                indicators=inspect_process(path)
                scope={'status':'TICK_BUDGET_SKIPPED'}
                validation=validate_executable(path)
                if scope_budget>0 and time.monotonic()<scope_deadline:
                    resume=self.scope_cursors.get(path.name,{})
                    scope=scan_executable_regions(path,byte_limit=min(scope_budget,2*1024*1024),
                        time_limit=min(.05,max(0,scope_deadline-time.monotonic())),
                        region_offset=resume.get('next_region_offset',0),
                        region_byte_offset=resume.get('next_region_byte_offset',0),resume_identity=resume.get('scan_identity'))
                    self.scope_cursors[path.name]={k:scope.get(k) for k in ('scan_identity','next_region_offset','next_region_byte_offset')}
                    scope_budget-=scope['bytes_read']
                    for key in scope_totals:scope_totals[key]+=scope.get(key) or 0
                    scope_status[scope['status']]=scope_status.get(scope['status'],0)+1
                    if len(scope_examples)<8:scope_examples.append({'pid':int(path.name),'summary':scope})
                else:
                    scope_status['TICK_BUDGET_SKIPPED']=scope_status.get('TICK_BUDGET_SKIPPED',0)+1
                validations[validation['status']]=validations.get(validation['status'],0)+1
                if validation['status'] in ('UNVERIFIED','ACCESS_DENIED'):
                    reasons[validation.get('reason','unknown')]=reasons.get(validation.get('reason','unknown'),0)+1
                if validation.get('status')=='CODE_MATCH' and not validation.get('complete'):
                    partial+=1;reasons['code_over_check_budget']=reasons.get('code_over_check_budget',0)+1
                if validation['status']=='CODE_MISMATCH':
                    indicators.append('executable_code_mismatch')
                # Observation only: listed for the user, never an event or a stop.
                observed=unverifiable_exec(path)
                if observed['status']=='OBSERVED' and any(observed['counts'].values()):
                    unverifiable_processes+=1
                    for tag,value in observed['counts'].items():unverifiable[tag]=unverifiable.get(tag,0)+value
                    if len(examples)<8:
                        try:exe=os.readlink(path/'exe')
                        except OSError:exe=None
                        examples.append({'pid':int(path.name),'exe':exe,'counts':observed['counts']})
                after=(path/'stat').read_text().rsplit(')',1)[1].split()[19]
                if after!=start:
                    vanished+=1
                    continue
                count+=1
                signature=hashlib.sha256((start+repr(indicators)+repr(validation)).encode()).hexdigest()
                key=path.name
                if self.seen.get(key)==signature:continue
                for indicator in indicators:
                    event=memory_event(path,indicator,start,validation,scope)
                    if pipeline:pipeline.ingest_host(event)
                    events+=1
                self.seen[key]=signature
            except (FileNotFoundError,ProcessLookupError):vanished+=1
            except (OSError,ValueError,IndexError):denied+=1
        active={p.name for p in pids};self.scope_cursors={k:v for k,v in self.scope_cursors.items() if k in active}
        self.seen={k:v for k,v in self.seen.items() if k in active}
        incomplete=validations.get('ACCESS_DENIED',0)+validations.get('UNVERIFIED',0)+partial
        blocked=denied+validations.get('ACCESS_DENIED',0)
        degraded=None
        if not count and (not batch or len(batch)>kernel_threads):degraded='Bu turda hiçbir süreç incelenemedi'
        elif blocked*2>count+denied:degraded=str(blocked)+' süreç okunamadı ya da erişim reddedildi; servis yetkilerini inceleyin'
        denominator_incomplete=bool(denied or len(batch)<len(pids) or any(scope_status.get(k) for k in ('TICK_BUDGET_SKIPPED','UNVERIFIED','UNCLASSIFIED_MAPPINGS','MAPPINGS_CHANGED','IDENTITY_CHANGED')))
        health={'status':'DEGRADED' if degraded else 'RUNNING','updated_at':time.time(),'inspected':count,'unreadable':denied,'vanished':vanished,'kernel_threads':kernel_threads,'events_count':events,'validation_counts':validations,'incomplete_validations':incomplete,
                'coverage':'PARTIAL' if incomplete or denied or len(batch)<len(pids) else 'COMPLETE',
                'coverage_scope':'main executable comparison in the current process batch; not global RAM',
                'enumerated_processes':len(pids),'batch_processes':len(batch),'incomplete_reasons':reasons,
                'partial_matches':partial,
                'unverifiable_exec_processes':unverifiable_processes,'unverifiable_exec_totals':unverifiable,
                'unverifiable_exec_examples':examples,
                'unverifiable_exec_scope':'executable memory without a verifiable file (anonymous, memfd, deleted); observation only; never authorizes termination; JIT uses it legitimately',
                'coverage_note':(str(incomplete)+' süreç tam karşılaştırılamadı (değişen JIT belleği, çalışırken güncellenen dosya ya da 1 MiB üstü kod); bu tek başına saldırı göstergesi değildir, temiz olduğu da kanıtlanmadı') if incomplete else None,
                'extended_scope':{'engine_state':'OBSERVATION_ONLY','coverage':'BOUNDED_PARTIAL',
                    'totals':scope_totals,'status_counts':scope_status,
                    'read_coverage_percent':round(100*scope_totals['valid_snapshot_read_bytes']/scope_totals['candidate_bytes'],4) if scope_totals['candidate_bytes'] and not denominator_incomplete else None,
                    'partial_observed_coverage_percent':round(100*scope_totals['valid_snapshot_read_bytes']/scope_totals['candidate_bytes'],4) if scope_totals['candidate_bytes'] and denominator_incomplete else None,
                    'byte_categories':{key:scope_totals[key] for key in CATEGORIES},
                    'category_totals_consistent':sum(scope_totals[key] for key in CATEGORIES)==scope_totals['candidate_bytes'],
                    'percentage_scope':'observed executable mappings in examined processes this pass; never total system RAM',
                    'mapping_denominator_incomplete':denominator_incomplete,'examples':scope_examples,
                    'access_model':access_model(self.proc_root),'tick_byte_limit':8*1024*1024,
                    'tick_time_limit_seconds':.5,'trusted_reference_provider_configured':False,
                    'raw_memory_persisted':False,'intervention_executed':False},
                'scope':'main executable validation plus bounded executable-region observation; no memory dump persisted'}
        if degraded:health['degraded_reason']=degraded
        self.store.set('worker.memory.health',health)

    def _commit_delivery(self):
        # No RAM-ClamAV coordinator or pending reports remain.
        pass
