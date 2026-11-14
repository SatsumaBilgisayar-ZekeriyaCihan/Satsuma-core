"""Durable, observational process follow-up; never authorizes or sends signals.

Bulguya bağlı kalıcı süreç gözlemi; yetki vermez ve sinyal göndermez.
"""
import json
import os
from pathlib import Path
import sqlite3
import time
from .process_identity import evidence_pid, evidence_exe, evidence_starttime

ROOT=Path('/proc')
WINDOW=86400
MAX_MEMBERS=64


def install(db):
    for sql in (
        'CREATE TABLE IF NOT EXISTS process_followup(finding_id TEXT PRIMARY KEY,updated REAL,expires REAL,body TEXT,active INTEGER NOT NULL DEFAULT 1)',
        'CREATE INDEX IF NOT EXISTS process_followup_due ON process_followup(active,updated,finding_id)',
        'CREATE TABLE IF NOT EXISTS process_followup_events(id INTEGER PRIMARY KEY,finding_id TEXT,created REAL,body TEXT)',
        'CREATE INDEX IF NOT EXISTS process_followup_event_key ON process_followup_events(finding_id,id)'):
        db.execute(sql)


def _supported(store):
    # Only the atomic Core Store owns these tables. Lightweight/host adapters
    # keep their existing response records; do not migrate their DB here.
    return (isinstance(getattr(store,'db',None),sqlite3.Connection)
            and callable(getattr(store,'atomic',None)) and callable(getattr(store,'_commit',None)))


def _boot():
    return (ROOT/'sys/kernel/random/boot_id').read_text().strip()


def _boot_time():
    for line in (ROOT/'stat').read_text().splitlines():
        if line.startswith('btime '):return int(line.split()[1])
    raise ValueError('boot time missing')


def _process(pid):
    directory=ROOT/str(pid)
    text=(directory/'stat').read_text()
    fields=text.rsplit(')',1)[1].split()
    start=int(fields[19]);state=fields[0];ppid=int(fields[1])
    if state in ('Z','X'):return {'pid':pid,'starttime':start,'state':'EXITED','ppid':ppid}
    exe=os.readlink(directory/'exe').removesuffix(' (deleted)')
    info=(directory/'exe').stat()
    uid=None
    for line in (directory/'status').read_text().splitlines():
        if line.startswith('Uid:'):
            uid=int(line.split()[1]);break
    row={'pid':pid,'starttime':start,'state':'RUNNING','ppid':ppid,'exe':exe,
         'uid':uid,'device':info.st_dev,'inode':info.st_ino}
    again=(directory/'exe').stat()
    if (int((directory/'stat').read_text().rsplit(')',1)[1].split()[19])!=start
            or os.readlink(directory/'exe').removesuffix(' (deleted)')!=exe
            or (again.st_dev,again.st_ino)!=(info.st_dev,info.st_ino)):
        raise ValueError('identity changed during observation')
    return row


def snapshot():
    started=time.monotonic();rows={};errors=0;complete=True
    boot=_boot()
    for directory in ROOT.iterdir():
        if not directory.name.isdigit():continue
        if len(rows)>=4096 or time.monotonic()-started>.5:
            complete=False;break
        try:
            row=_process(int(directory.name));rows[row['pid']]=row
        except (OSError,ValueError,IndexError):
            errors+=1
    # Missing exe/permission/racing processes make enumeration incomplete.
    return {'boot_id':boot,'rows':rows,'complete':complete and not errors,'errors':errors}


def _event(db,fid,now,kind,**body):
    db.execute('INSERT INTO process_followup_events(finding_id,created,body) VALUES(?,?,?)',
               (fid,now,json.dumps({'kind':kind,'timestamp':now,**body},ensure_ascii=True)))


def _save(db,fid,case,now):
    db.execute('UPDATE process_followup SET updated=?,body=?,active=? WHERE finding_id=?',
               (now,json.dumps(case,ensure_ascii=True),int(not case.get('closed',False)),fid))


def evidence_summary(finding):
    event=finding.get('event') if isinstance(finding,dict) else None
    event=event if isinstance(event,dict) else {}
    metadata=event.get('metadata');metadata=metadata if isinstance(metadata,dict) else {}
    extensions=metadata.get('extensions');extensions=extensions if isinstance(extensions,dict) else {}
    ram=extensions.get('host.ram_v2')
    return {'pid':evidence_pid(event),'exe':evidence_exe(event),
            'signature':str(ram.get('signature',''))[:300] if isinstance(ram,dict) else None}


def register(store,finding,*,commit=True):
    if not _supported(store) or not isinstance(finding,dict):return
    fid=finding.get('finding_id')
    if not fid or finding.get('classification') not in ('suspicious','likely','confirmed'):return
    event=finding.get('event') or {};pid=evidence_pid(event)
    if not pid:return
    if store.db.execute('SELECT 1 FROM process_followup WHERE finding_id=?',(str(fid),)).fetchone():return
    now=time.time();start=evidence_starttime(event);exe=evidence_exe(event)
    case={'finding_id':str(fid),'rule_id':finding.get('rule_id'),'registered_at':now,
          'decision':{'status':'NOT_EVALUATED','signal_sent':False,'exit_verified':False},
          'state':'IDENTITY_INCOMPLETE','members':[],'scope':'bounded periodic observation; no inherited threat verdict'}
    metadata=event.get('metadata') if isinstance(event,dict) else None
    extensions=metadata.get('extensions') if isinstance(metadata,dict) else None
    ram=extensions.get('host.ram_v2') if isinstance(extensions,dict) else None
    evidence_boot=event.get('boot_id') or (extensions.get('host.boot_id') if isinstance(extensions,dict) else None)
    case['evidence_summary']=evidence_summary(finding)
    try:
        from .presentation import epoch
        stamp=epoch(event.get('timestamp'));boot=_boot()
        # Do not attach pre-boot evidence to a reused PID on the current boot.
        if boot and (not evidence_boot or evidence_boot==boot) and start and start[1]=='jiffies' and exe and _boot_time()<=stamp<=now+60:
            root={'pid':pid,'starttime':int(start[0]),'exe':exe,'relation':'ROOT',
                  'state':'PENDING','first_seen':now,'last_seen':None}
            try:
                live=_process(pid)
                if live['starttime']==root['starttime'] and live.get('exe')==exe:
                    root.update({k:live[k] for k in ('uid','device','inode') if k in live})
            except (OSError,ValueError,IndexError):pass
            case.update(boot_id=boot,members=[root],state='PENDING',
                        watch_start_ticks=int(float((ROOT/'uptime').read_text().split()[0])*os.sysconf('SC_CLK_TCK')))
    except (OSError,TypeError,ValueError,OverflowError):pass
    inserted=store.db.execute('INSERT OR IGNORE INTO process_followup(finding_id,updated,expires,body) VALUES(?,?,?,?)',
                     (str(fid),now,now+WINDOW,json.dumps(case,ensure_ascii=True)))
    if inserted.rowcount:_event(store.db,str(fid),now,'FINDING_REGISTERED',state=case['state'])
    if commit:store._commit()


def decision(store,finding,record,*,commit=True):
    if not _supported(store):return
    register(store,finding,commit=False)
    fid=str(finding.get('finding_id') or '')
    store.db.execute('UPDATE process_followup SET updated=updated WHERE finding_id=?',(fid,))
    row=store.db.execute('SELECT body FROM process_followup WHERE finding_id=?',(fid,)).fetchone()
    if row:
        now=time.time();case=json.loads(row[0])
        keys=('status','reasons','exemption','signal_sent','exit_verified','event_time','decision_explanation','identity_check','outcome_known')
        case['decision']={k:record[k] for k in keys if k in record}
        case['decision']['recorded_at']=now
        _event(store.db,fid,now,'RESPONSE_DECISION',**case['decision'])
        _save(store.db,fid,case,now)
    if commit:store._commit()


def duplicate(store,finding):
    if not _supported(store):return
    fid=str(finding.get('finding_id') or '')
    with store.atomic():
        store.db.execute('UPDATE process_followup SET updated=updated WHERE finding_id=?',(fid,))
        row=store.db.execute('SELECT body FROM process_followup WHERE finding_id=?',(fid,)).fetchone()
        if row and json.loads(row[0])['decision'].get('status')=='NOT_EVALUATED':
            record={'timestamp':time.time(),'action':'process.followup','finding_id':fid,
                    'rule_id':finding.get('rule_id'),'status':'duplicate_without_result',
                    'signal_sent':None,'exit_verified':None,'reasons':['previous_delivery_has_no_recorded_decision']}
            store.add('actions',record)
            decision(store,finding,record,commit=False)


def tick(store,*,observe=snapshot,probe=_process,now=None):
    if not _supported(store):return
    now=time.time() if now is None else now
    active_count=store.db.execute('SELECT count(*) FROM process_followup WHERE active=1').fetchone()[0]
    pending=store.db.execute('SELECT finding_id,expires,body FROM process_followup '
                             'WHERE active=1 ORDER BY updated,finding_id LIMIT 32').fetchall()
    if not pending:return
    view=observe();rows=view['rows'];processed=0
    with store.atomic():
        # Acquire the writer lock before reading cases again: a decision may
        # have arrived while /proc was scanned. Never overwrite it with an old body.
        store.db.execute('UPDATE process_followup SET updated=updated WHERE finding_id=?',(pending[0][0],))
        active_count=store.db.execute('SELECT count(*) FROM process_followup WHERE active=1').fetchone()[0]
        pending=store.db.execute('SELECT finding_id,expires,body FROM process_followup '
                                 'WHERE active=1 ORDER BY updated,finding_id LIMIT 32').fetchall()
        for fid,expires,body in pending:
            case=json.loads(body)
            if expires<=now:
                case.update(state='WATCH_FINISHED',closed=True)
                _event(store.db,fid,now,'WATCH_FINISHED')
            elif case.get('boot_id') and case['boot_id']!=view['boot_id']:
                case.update(state='BOOT_CHANGED',closed=True)
                _event(store.db,fid,now,'BOOT_CHANGED')
            elif case['members']:
                for member in case['members']:
                    live=rows.get(member['pid']);status='UNKNOWN'
                    if live is None:
                        # Enumeration errors never prove exit. Probe the exact PID.
                        try:live=probe(member['pid'])
                        except ProcessLookupError:status='GONE'
                        except FileNotFoundError:
                            status='GONE' if not (ROOT/str(member['pid'])).exists() else 'UNKNOWN'
                        except (OSError,ValueError,IndexError):pass
                    if live is not None:
                        status=('PID_REUSED' if live['starttime']!=member['starttime'] else
                                'EXITED' if live.get('state')=='EXITED' else
                                'EXEC_CHANGED' if live.get('exe')!=member['exe'] else 'RUNNING')
                    if status!=member['state']:
                        _event(store.db,fid,now,'PROCESS_STATE',pid=member['pid'],starttime=member['starttime'],state=status,observed_exe=live.get('exe') if live else None)
                    member.update(state=status,last_seen=now)
                    if live and live.get('exe'):member['observed_exe']=live['exe']
                root=case['members'][0];known={(m['pid'],m['starttime']) for m in case['members']}
                # Up to four generations in this observation, without inheriting guilt.
                for _ in range(4):
                    added=False
                    for live in rows.values():
                        key=(live['pid'],live['starttime'])
                        if key in known or live.get('state')!='RUNNING':continue
                        parent=rows.get(live.get('ppid'))
                        relation=None
                        if (parent and (parent['pid'],parent['starttime']) in known
                                and parent['starttime']<=live['starttime']):relation='CHILD_OBSERVED'
                        elif (all(root.get(k) is not None and root.get(k)==live.get(k) for k in ('exe','uid','device','inode'))
                              and live['starttime']>=case.get('watch_start_ticks',float('inf'))):
                            relation='SAME_EXECUTABLE_CANDIDATE'
                        if not relation:continue
                        if len(case['members'])>=MAX_MEMBERS:
                            case['member_capacity_reached']=True;break
                        member={k:live[k] for k in ('pid','starttime','exe','uid','device','inode','ppid') if k in live}
                        member.update(relation=relation,state='RUNNING',first_seen=now,last_seen=now)
                        if relation=='CHILD_OBSERVED':member['parent_starttime']=parent['starttime']
                        case['members'].append(member);known.add(key);added=True
                        _event(store.db,fid,now,relation,**member)
                    if not added:break
                case.update(state=root['state'],last_observed_at=now,
                            observation_complete=view['complete'],observation_errors=view.get('errors',0))
            _save(store.db,fid,case,now);processed+=1
        store.set('process_followup.health',{'updated_at':now,'processed':processed,
                  'deferred_cases':max(0,active_count-len(pending)),
                  'process_snapshot_complete':view['complete'],'scope':'periodic /proc observation; short-lived/reparented processes can be missed'})


LABELS={'PENDING':'İlk gözlem bekleniyor','RUNNING':'Aynı süreç çalışıyor',
        'GONE':'Süreç artık gözlenmiyor; sonlanma nedeni bilinmiyor',
        'EXITED':'Süreç çıkışı gözlendi; nedeni bilinmiyor','PID_REUSED':'PID başka bir süreç tarafından kullanılıyor',
        'EXEC_CHANGED':'Aynı süreç başka program çalıştırmış','UNKNOWN':'Süreç durumu okunamadı',
        'BOOT_CHANGED':'Makine yeniden başlamış; eski süreçle bağ kurulmadı',
        'WATCH_FINISHED':'24 saatlik takip penceresi tamamlandı',
        'IDENTITY_INCOMPLETE':'Bulgu kimliği eksik veya farklı açılışa ait; güvenli takip kurulamadı'}


def read(db,fid,*,details=False):
    try:row=db.execute('SELECT body FROM process_followup WHERE finding_id=?',(str(fid),)).fetchone()
    except sqlite3.OperationalError as exc:
        if 'no such table' not in str(exc):raise
        row=None
    if not row:return {'state':'NOT_RECORDED','summary':'Bu bulgu için takip kaydı yok; geçmişe yönelik müdahale sonucu çıkarılamaz.'}
    case=json.loads(row[0]);members=case.pop('members',[])
    case.update(summary=LABELS.get(case['state'],case['state']),related_count=max(0,len(members)-1),
                tracking_fresh=bool(case.get('last_observed_at') and 0<=time.time()-case['last_observed_at']<=30))
    if case.get('last_observed_at') and not case['tracking_fresh']:
        case['summary']+=' (son gözlem güncel değil)'
    status=case['decision'].get('status','NOT_EVALUATED')
    case['decision_summary']={
        'NOT_EVALUATED':'Müdahale kararı henüz kaydedilmedi',
        'policy_denied':'Müdahale uygulanmadı; gerekçeyi inceleyin',
        'exempt':'Korunan süreç istisnası nedeniyle müdahale uygulanmadı',
        'report_only':'Yalnızca raporlandı',
        'duplicate_without_result':'Önceki teslimin sonuç kaydı eksik; otomatik tekrar yapılmadı',
        'response_error':'Müdahale sırasında hata; sinyal/çıkış sonucu bilinmiyor',
        'termination_pending':'Sinyal gönderildi; süreç çıkışı doğrulanmadı',
        'integrity_locked':'Bütünlük koşulları müdahaleye izin vermedi',
    }.get(status,status)
    if status=='terminated':
        case['decision_summary']=('Satsuma sinyal gönderdi ve çıkışı doğruladı'
            if case['decision'].get('signal_sent') is True and case['decision'].get('exit_verified') is True
            else 'Sonlandırma sonucu eksik; doğrulanmış çıkış kaydı yok')
    from .presentation import REASONS
    reasons=case['decision'].get('reasons') or []
    case['decision_reasons']=[REASONS.get(reason,{
        'ram_signature_revalidation_failed':'RAM imzası veya süreç kimliği son kontrolde yeniden doğrulanamadı',
        'previous_delivery_has_no_recorded_decision':'Önceki olay tesliminde karar kaydı tamamlanmamış',
    }.get(reason,reason)) for reason in reasons]
    exemption=case['decision'].get('exemption')
    if exemption:case['decision_reasons'].append('Korunan program/birim istisnası: '+str(exemption))
    identity_reason=(case['decision'].get('identity_check') or {}).get('reason')
    if identity_reason and identity_reason!='ok':case['decision_reasons'].append('Süreç kimliği kontrolü: '+identity_reason)
    if case['decision_reasons']:case['decision_summary']+=' · '+'; '.join(case['decision_reasons'])
    if details:
        relation_labels={'ROOT':'Bulgudaki asıl süreç','CHILD_OBSERVED':'Çocuk süreç (ebeveyn kimliği gözlendi)',
                         'SAME_EXECUTABLE_CANDIDATE':'Aynı programın sonradan başlayan örneği; ilişki adayı'}
        for member in members:
            member['relation_label']=relation_labels.get(member['relation'],member['relation'])
            member['state_label']=LABELS.get(member['state'],member['state'])
        case['members']=members
        case['timeline']=[json.loads(r[0]) for r in db.execute('SELECT body FROM process_followup_events WHERE finding_id=? ORDER BY id DESC LIMIT 100',(str(fid),))][::-1]
        case['timeline_count']=db.execute('SELECT count(*) FROM process_followup_events WHERE finding_id=?',(str(fid),)).fetchone()[0]
        case['timeline_limit']=100
    return case
