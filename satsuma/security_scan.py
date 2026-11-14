"""Hourly, sequential host scanner integration for Satsuma Core.

2.2.11: ClamAV falls back from clamdscan to clamscan when the clamd service
is not answering; the scan covers the places malware is usually dropped
(/tmp, /var/tmp, /dev/shm, /root, /usr/bin, /usr/sbin besides /etc, /opt,
/usr/local and /home); every ClamAV detection outside the system
directories is quarantined automatically (satsuma.scan_quarantine), and the
scanner's own error line (e.g. a missing virus database) is kept so the
dashboard can say why a scan failed.

2026-11-03: chkrootkit output is parsed instead of counting the word "infected".
Possible LKM trojan, hidden-process, packet-sniffer and similar lines are
findings (by kind); "not infected" and similar clean lines never are; and
"Permission denied" lines mark the scan incomplete instead of reporting a clean
"completed" result.

2.2.31: unhide looks for hidden processes and ports after the scanners; an
object becomes a finding (SATSUMA-SCAN-002) only if it verifies again.

Saatlik, sıralı tarayıcı bütünleşmesi. 2.2.11: clamd servisi cevap vermezse
ClamAV clamdscan yerine clamscan ile tarar; kötü amaçlı yazılımın sık
bırakıldığı yerler (/tmp, /var/tmp, /dev/shm, /root, /usr/bin, /usr/sbin)
de taranır; 2.2.31'den beri tarayıcılardan sonra unhide gizli süreç ve port
arar, yalnızca yeniden doğrulanan nesne bulgu olur (SATSUMA-SCAN-002); sistem
klasörleri dışındaki her ClamAV bulgusu otomatik
karantinaya alınır ve tarayıcının hata satırı (ör. virüs veritabanı yok)
saklanır, böylece panel taramanın neden başarısız olduğunu söyleyebilir.
"""
import json
import fcntl
import hashlib
import os
import re
import shutil
import subprocess
import uuid
import time
import selectors
import signal
from pathlib import Path

from .host_store import HostStore

SCAN_TARGETS = ('/etc', '/opt', '/usr/local', '/home', '/root', '/tmp', '/var/tmp', '/dev/shm',
                '/usr/bin', '/usr/sbin')
OUTPUT_LIMIT = 64 * 1024
COMMAND_TIMEOUT = 15 * 60
MAX_OUTPUT_BYTES = 16 * 1024 * 1024


def bounded_run(command, *, stdout, stderr=None, timeout=COMMAND_TIMEOUT, check=False, start_new_session=True):
    process=subprocess.Popen(command,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True,
                             env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    selector=selectors.DefaultSelector();selector.register(process.stdout,selectors.EVENT_READ)
    deadline=time.monotonic()+timeout;total=0
    try:
        while True:
            if time.monotonic()>deadline:
                raise subprocess.TimeoutExpired(command,timeout)
            if not selector.select(min(1,max(0,deadline-time.monotonic()))):continue
            chunk=os.read(process.stdout.fileno(),65536)
            if not chunk:break
            total+=len(chunk)
            if total>MAX_OUTPUT_BYTES:
                raise RuntimeError('Scanner output capacity exceeded; scan incomplete')
            stdout.write(chunk)
        return subprocess.CompletedProcess(command,process.wait(timeout=5))
    finally:
        selector.close()
        if process.poll() is None:
            try:os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError:pass
            process.wait(timeout=5)
        process.stdout.close()


# chkrootkit prints one line per problem with -q. Each pattern is a kind of finding.
CHKROOTKIT_KINDS=(
    ('infected',re.compile(r'(?<!not )\binfected\b',re.I)),
    ('lkm_trojan',re.compile(r'possible lkm trojan',re.I)),
    ('hidden_process',re.compile(r'processes? hidden|hidden for ps|hidden from ps',re.I)),
    ('packet_sniffer',re.compile(r'packet sniffer',re.I)),
    ('suspicious_file',re.compile(r'suspicious (?:files?|director(?:y|ies)|tty|process)|files? (?:was|were) found',re.I)),
)
CLEAN_LINE=re.compile(r'not infected|nothing found|nothing deleted|not found|not tested|no suspect|not promisc',re.I)


def parse_chkrootkit(text):
    """Findings by kind from chkrootkit output, and whether the scan could read everything.

    chkrootkit çıktısından türe göre bulgular ve taramanın her şeyi okuyup okuyamadığı.
    """
    kinds={name:0 for name,_ in CHKROOTKIT_KINDS};lines=[];denied=0;seen=set()
    for raw in text.splitlines():
        line=raw.strip()
        if not line:continue
        if 'permission denied' in line.lower():
            denied+=1;continue
        if CLEAN_LINE.search(line) and not re.search(r'(?<!not )\binfected\b',line,re.I):continue
        # chkrootkit prints one warning both with and without its "Checking `x'..." prefix.
        core=re.sub(r"^Checking `[^']*'\.\.\.\s*",'',line).lower()
        if core in seen:continue
        for name,pattern in CHKROOTKIT_KINDS:
            if pattern.search(line):
                kinds[name]+=1;seen.add(core)
                if len(lines)<32:lines.append(line[:300])
                break
    return {'findings':sum(kinds.values()),'kinds':{k:v for k,v in kinds.items() if v},'lines':lines,
            'permission_denied':denied,'incomplete':denied>0}


def _result(tool, command, runner=bounded_run, now=time.time, archive=None):
    started=now()
    archive=Path(archive) if archive is not None else Path("/var/lib/satsuma-core/host/scan-outputs")
    archive.mkdir(mode=0o700,parents=True,exist_ok=True)
    # Scanner logs may contain paths, usernames and detection details.  They must
    # never inherit the process umask (which may allow other users to read them).
    # O_EXCL and O_NOFOLLOW prevent replacing a pre-existing output with a link.
    output_path = archive / (uuid.uuid4().hex + ".log")
    descriptor = os.open(output_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w+b") as output:
        try:
            completed=runner(command,stdout=output,stderr=subprocess.STDOUT,timeout=COMMAND_TIMEOUT,
                             check=False,start_new_session=True)
            exit_code=completed.returncode;error=None
        except subprocess.TimeoutExpired:
            exit_code=None;error=f'{COMMAND_TIMEOUT} saniye zaman aşımı'
        except (OSError,RuntimeError) as exc:
            exit_code=None;error=str(exc)[:500]
        output.flush();output.seek(0)
        digest=hashlib.sha256();sample=bytearray();total=0
        while True:
            chunk=output.read(64*1024)
            if not chunk:break
            digest.update(chunk);total+=len(chunk)
            if len(sample)<OUTPUT_LIMIT:sample.extend(chunk[:OUTPUT_LIMIT-len(sample)])
    text=bytes(sample).decode('utf-8','replace')
    if error is None and exit_code not in (0,1):
        # The scanner's own reason, e.g. "ERROR: Could not connect to clamd" or
        # "LibClamAV Error: cli_loaddbdir(): No supported database files found".
        reason=next((line.strip() for line in text.splitlines()
                     if line.lstrip().startswith(('ERROR','LibClamAV Error','WARNING: Can'))),None)
        if reason:error=reason[:500]
    status='ERROR' if error is not None else 'COMPLETED'
    findings=0;details=None
    if tool=='clamav':
        match=re.search(r'Infected files:\s*(\d+)',text,re.I);findings=int(match.group(1)) if match else (1 if exit_code==1 else 0)
    elif tool=='rkhunter':
        findings=sum(1 for line in text.splitlines() if 'warning' in line.lower())
    elif tool=='chkrootkit':
        details=parse_chkrootkit(text);findings=details['findings']
    if findings and error is None:status='FINDINGS'
    elif exit_code not in (0,None) and status!='ERROR':status='WARNING'
    elif details and details['incomplete'] and error is None:status='WARNING'
    files=[]
    if tool=='clamav' and exit_code==1 and error is None:
        from .scan_quarantine import inspect_target
        for line in text.splitlines():
            if len(files)>=32:break
            if not line.endswith(' FOUND') or ': ' not in line:continue
            path,signature=line[:-6].rsplit(': ',1)
            try:files.append({**inspect_target(path),'signature':signature})
            except (OSError,ValueError) as exc:
                files.append({'path':path,'signature':signature,'unavailable_reason':str(exc)[:250]})
    return {'timestamp':started,'completed_at':now(),'tool':tool,'status':status,'exit_code':exit_code,
            'findings':findings,'command':command[0],'output_excerpt':text,'output_bytes':total,
            'output_sha256':digest.hexdigest(),'truncated':total>OUTPUT_LIMIT,'error':error,'files':files,
            **({'finding_kinds':details['kinds'],'finding_lines':details['lines'],
                'incomplete':details['incomplete'],'permission_denied':details['permission_denied']}
               if details is not None else {})}




def clamscan_command(which=shutil.which):
    clamscan=which('clamscan')
    return [clamscan,'--recursive=yes','--infected','--cross-fs=yes',*SCAN_TARGETS] if clamscan else None


def commands(which=shutil.which):
    result=[]
    clamd=which('clamdscan')
    if clamd:result.append(('clamav',[clamd,'--fdpass','--multiscan',*SCAN_TARGETS]))
    else:result.append(('clamav',clamscan_command(which)))
    rkhunter=which('rkhunter');result.append(('rkhunter',[rkhunter,'--check','--skip-keypress','--report-warnings-only']) if rkhunter else ('rkhunter',None))
    chkrootkit=which('chkrootkit');result.append(('chkrootkit',[chkrootkit,'-q']) if chkrootkit else ('chkrootkit',None))
    return result


def run_once(store=None, runner=bounded_run, which=shutil.which, now=time.time, scan_policy=None, manual=False,
             binary_audit=None, ssh_audit=None, python_audit=None, media_audit=None, systemd_audit=None,
             boot_correlator=None, mitm_watch=None, unhide=None):
    own=store is None;store=store or HostStore()
    results=[]
    try:
        selected=scan_policy or {'enabled':True,'order':['clamav','rkhunter','chkrootkit']}
        if not selected['enabled']:
            store.set('security_scan_health',{'status':'DISABLED','updated_at':now()});return []
        available=dict(commands(which))
        for tool in selected['order']:
            command=available[tool]
            if command is None:
                item={'timestamp':now(),'completed_at':now(),'tool':tool,'status':'UNAVAILABLE',
                      'findings':0,'error':tool+' komutu bulunamadı'}
            else:
                item=_result(tool,command,runner=runner,now=now)
                fallback=clamscan_command(which) if tool=='clamav' and command[0].endswith('clamdscan') else None
                if fallback and item['status'] in ('ERROR','WARNING'):
                    # clamd not answering: scan with clamscan instead of giving up.
                    first=item.get('error') or 'clamdscan exit '+str(item.get('exit_code'))
                    item={**_result(tool,fallback,runner=runner,now=now),'fallback_from':'clamdscan','fallback_reason':first}
            if tool=='clamav' and item.get('files') and selected.get('automatic_quarantine'):
                item['quarantine']=quarantine_files(store,item['files'])
            ident=store.add('security_scan',item)
            if item.get('findings',0)>0:
                finding={'finding_id':'scan:'+str(ident), 'rule_id':'SATSUMA-SCAN-001', 'timestamp':item['timestamp'],
                         'title':tool+' taramasında inceleme gerektiren sonuç', 'summary':tool+': '+str(item['findings'])+' tarayıcı göstergesi',
                         'severity':'high' if tool=='clamav' else 'medium',
                         'classification':'suspicious' if tool=='clamav' else 'indicator', 'source':tool,
                         'scan_record_id':ident, 'output_sha256':item.get('output_sha256'),
                         'automatic_quarantine':bool(item.get('quarantine')),
                         'quarantined':[q['source'] for q in item.get('quarantine',[]) if q.get('status')=='quarantined'],
                         'status':'QUARANTINED' if item.get('quarantine') and all(q.get('status')=='quarantined' for q in item['quarantine']) else 'REVIEW',
                         'interpretation':'Tarayıcı göstergesi; tek başına doğrulanmış saldırı değildir'}
                store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                                 (finding['finding_id'],time.time(),json.dumps(finding,ensure_ascii=False)))
                store.db.commit()
            results.append(item)
        # Hidden processes and ports (unhide, 2.2.31); every object verified again.
        try:
            from .unhide_scan import installed as unhide_installed
            if unhide is None:
                from .unhide_scan import run as unhide
            hidden=unhide() if manual or unhide_installed(which) else None
        except Exception as exc:
            hidden={'findings':[],'errors':[str(exc)[:300]],'available':False}
        if hidden is not None:
            item={'timestamp':now(),'completed_at':now(),'tool':'unhide','findings':len(hidden['findings']),
                  'status':'FINDINGS' if hidden['findings'] else 'ERROR' if hidden.get('errors') else 'COMPLETED',
                  'error':'; '.join(hidden.get('errors') or []) or None,'hidden':hidden['findings'],
                  'discarded':len(hidden.get('discarded',[]))}
            ident=store.add('security_scan',item)
            for obj in hidden['findings']:
                subject=str(obj.get('pid') or str(obj.get('proto'))+'/'+str(obj.get('port')))
                finding={'finding_id':'unhide:'+obj['kind']+':'+subject,'rule_id':'SATSUMA-SCAN-002','timestamp':item['timestamp'],
                         'title':'Gizlenmiş '+('süreç' if obj['kind']!='hidden_port' else 'port')+' (yeniden doğrulandı)',
                         'summary':obj['kind']+' '+subject+' '+str(obj.get('executable') or obj.get('command') or ''),
                         'severity':'high','classification':'suspicious','source':'unhide','scan_record_id':ident,
                         'item':obj,'status':'REVIEW','interpretation':'Çekirdek görünümleri arasında fark; ikinci denetimde de sürdü'}
                store.db.execute('INSERT OR IGNORE INTO findings(finding_id,last_seen,body) VALUES(?,?,?)',
                                 (finding['finding_id'],time.time(),json.dumps(finding,ensure_ascii=False)))
            store.db.commit()
            results.append(item)
        # System programs against the RPM database, daily or on a manual scan.
        clam_paths=[f['path'] for x in results if x.get('tool')=='clamav' for f in x.get('files',[])]
        try:
            if binary_audit is None:
                from .binary_audit import run as binary_audit
            binary=binary_audit(store,manual=manual,clamav_paths=clam_paths)
        except Exception as exc:
            binary={'error':str(exc)[:300]}
        # Python scripts (satsuma.python_audit), daily or on a manual scan.
        try:
            if python_audit is None:
                from .python_audit import run as python_audit
            python=python_audit(store,manual=manual)
        except Exception as exc:
            python={'error':str(exc)[:300]}
        # Man pages, SVG, PNG and fonts (satsuma.media_audit), daily or manual.
        try:
            if media_audit is None:
                from .media_audit import run as media_audit
            media=media_audit(store,manual=manual)
        except Exception as exc:
            media={'error':str(exc)[:300]}
        # systemd units, generators and boot timing (satsuma.systemd_audit).
        try:
            if systemd_audit is None:
                from .systemd_audit import run as systemd_audit
            units=systemd_audit(store,manual=manual)
        except Exception as exc:
            units={'error':str(exc)[:300]}
        # Boot problems (satsuma.boot_correlator), once per settled boot.
        try:
            if boot_correlator is None:
                from .boot_correlator import run as boot_correlator
            boot=boot_correlator(store,manual=manual)
        except Exception as exc:
            boot={'error':str(exc)[:300]}
        # SSH keys and sshd (satsuma.ssh_keys), every scan; read-only.
        try:
            if ssh_audit is None:
                from .ssh_keys import run as ssh_audit
            ssh=ssh_audit(store)
        except Exception as exc:
            ssh={'error':str(exc)[:300]}
        # DNS, routes, network profiles, kernel settings, remote access (satsuma.mitm_watch).
        try:
            if mitm_watch is None:
                from .mitm_watch import run as mitm_run
                from .store import Store
                def mitm_watch(host):
                    core=Store()
                    try:return mitm_run(host,core)
                    finally:core.close()
            mitm=mitm_watch(store)
        except Exception as exc:
            mitm={'error':str(exc)[:300]}
        # Passwordless sudo grants on disk (satsuma.sudo_nopasswd), every scan.
        from .sudo_nopasswd import grants, record as record_sudo
        sudo_grants=grants()
        record_sudo(store,sudo_grants)
        state='FINDINGS' if any(x['status']=='FINDINGS' for x in results) else 'DEGRADED' if any(x['status'] in ('ERROR','WARNING','UNAVAILABLE') for x in results) else 'COMPLETED'
        store.set('security_scan_health',{'status':state,'updated_at':now(),'interval_seconds':3600,
                  'tools':{x['tool']:x['status'] for x in results},'finding_count':sum(x.get('findings',0) for x in results),
                  'errors':{x['tool']:x['error'] for x in results if x.get('error')},
                  'quarantined_count':sum(1 for x in results for q in x.get('quarantine',[]) if q.get('status')=='quarantined'),
                  'sudo_nopasswd':sudo_grants,
                  'binary_audit':{k:binary.get(k) for k in ('updated_at','counts','quarantined','virustotal','error')},
                  'ssh_keys':ssh,
                  'mitm_watch':{k:mitm.get(k) for k in ('updated_at','counts','active','unavailable','error')},
                  'python_audit':{k:python.get(k) for k in ('updated_at','modified','high','medium','error')},
                  'media_audit':{k:media.get(k) for k in ('updated_at','high','other','error')},
                  'systemd_audit':{k:units.get(k) for k in ('updated_at','modified','new_units','flagged_units','error')},
                  'boot_correlation':{'boot_id':boot.get('boot_id'),'problems':len(boot.get('problems') or []),
                                      'error':boot.get('error')}})
        return results
    finally:
        if own:store.close()


def quarantine_files(store, files):
    """Quarantine every detected file that has a verified identity."""
    from .scan_quarantine import quarantine_target
    results=[]
    # A signature engine may report one file several times. Never attempt a
    # second destructive move for the same verified file identity.
    seen=set()
    for target in files:
        identity=(target.get('path'), target.get('sha256'),
                  target.get('device'), target.get('inode'))
        if target.get('sha256') and identity in seen:
            results.append({'status':'skipped','source':target.get('path'),
                            'reason':'duplicate scan finding'})
            continue
        if target.get('sha256'):
            seen.add(identity)
        if not target.get('sha256'):
            results.append({'status':'skipped','source':target.get('path'),'reason':target.get('unavailable_reason','kimlik okunamadı')})
            continue
        try:
            results.append(quarantine_target(target,lambda record:store.add('quarantine_actions',
                {**record,'automatic':True,'timestamp':time.time()})))
        except (OSError,ValueError,RuntimeError) as exc:
            results.append({'status':'not_quarantined','source':target.get('path'),'reason':str(exc)[:250]})
    return results


def scan_due(health, policy, now):
    return health.get('status')=='DISABLED' or not health.get('updated_at') or now-health['updated_at']>=policy['interval_seconds']


def run():
    from satsuma.runtime_user import require_service_user; require_service_user()
    os.umask(0o077);root=Path('/var/lib/satsuma-core/host');root.mkdir(parents=True,exist_ok=True)
    lock=os.open(root/'security-scan.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    try:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        from .config import load_with_policy
        config,_,_=load_with_policy()
        selected=config['scheduled_scans']
        host=HostStore()
        try:
            manual=os.environ.get('SATSUMA_SCAN_MANUAL')=='1'
            if manual or not selected['enabled'] or scan_due(host.get('security_scan_health',{}) or {}, selected, time.time()):
                run_once(store=host,scan_policy=selected,manual=manual)
        finally:host.close()
    finally:os.close(lock)
