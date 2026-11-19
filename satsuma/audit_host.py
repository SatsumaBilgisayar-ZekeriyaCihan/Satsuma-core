"""Parse an existing audit log without installing, deleting or changing rules.

When auditd rotates the log, the reader finishes the old file before it
opens the new one. Only a shrinking file that is still the same file counts
as truncated; comparing the new file's size with the position in the old
one made the reader restart the old file forever and miss every new event.

Mevcut audit günlüğünü kural kurmadan, silmeden ya da değiştirmeden okur.

auditd günlüğü döndürdüğünde okuyucu yenisini açmadan önce eski dosyayı
bitirir. Yalnızca hâlâ aynı dosya olan ve küçülen bir dosya kesilmiş sayılır;
yeni dosyanın boyutunu eski dosyadaki konumla karşılaştırmak okuyucunun eski
dosyayı sonsuza dek baştan okumasına ve bütün yeni olayları kaçırmasına yol
açıyordu.
"""
import json,os,posixpath,re,shlex,time
from pathlib import Path

MARK=re.compile(r'(?:^|\s)type=(\S+).*?msg=audit\((\d+(?:\.\d+)?):(\d+)\)')


def fields(line):
    try:tokens=shlex.split(line)
    except ValueError:tokens=line.split()
    return dict(token.split('=',1) for token in tokens if '=' in token)


def decode(value):
    if value and len(value)%2==0 and re.fullmatch('[0-9A-Fa-f]+',value):
        try:return bytes.fromhex(value).decode('utf-8').replace('\x00',' ')
        except (ValueError,UnicodeError):pass
    return value


def decoded_field(line,parsed,key):
    match=re.search(r'(?:^|\s)'+re.escape(key)+r'=(.)',line)
    if match and match[1] in ('"',"'"):return parsed.get(key)
    return decode(parsed.get(key))


def event(lines,complete):
    first=MARK.search(lines[0])
    out={'timestamp':float(first[2]),'serial':first[3],'complete':complete,
         'raw':lines,'paths':[],'types':[]}
    for line in lines:
        mark=MARK.search(line)
        if not mark:continue
        kind=mark[1];parsed=fields(line);out['types'].append(kind)
        if kind=='SYSCALL':
            for key in ('pid','ppid','uid','auid','comm','exe','syscall','arch','success','exit','key','a0','a1','a2','a3'):
                out[key]=decoded_field(line,parsed,key) if key in ('comm','exe','key') else parsed.get(key)
        elif kind=='EXECVE':
            out['execve']={key:decoded_field(line,parsed,key) for key in parsed if key=='argc' or re.fullmatch(r'a\d+(?:\[\d+\])?',key)}
        elif kind=='CWD':out['cwd']=decoded_field(line,parsed,'cwd')
        elif kind=='PROCTITLE':out['proctitle']=decoded_field(line,parsed,'proctitle')
        elif kind=='PATH':
            out['paths'].append({key:decoded_field(line,parsed,key) if key=='name' else parsed.get(key)
                                 for key in ('name','inode','dev','nametype','mode','ouid')})
        elif kind in ('USER_AUTH','USER_LOGIN','USER_ACCT','USER_START','USER_END','CRED_ACQ','CRED_DISP','USER_CMD'):
            # Audit user messages nest key=value fields inside a quoted msg.
            nested = fields(parsed.get('msg', ''))
            parsed = {**parsed, **nested}
            for key in ('pid','uid','auid','exe','comm','acct','res'):
                value = decoded_field(line, parsed, key) if key in ('exe','comm','acct') else parsed.get(key)
                if value is not None and out.get(key) is None:out[key]=value
            if out.get('success') is None and parsed.get('res') in ('success','failed'):
                out['success'] = 'yes' if parsed['res']=='success' else 'no'
            out.setdefault('user_events', []).append({
                'type': kind,
                'uid': parsed.get('uid'),
                'auid': parsed.get('auid'),
                'acct': decoded_field(line, parsed, 'acct'),
                'res': parsed.get('res'),
                'exe': decoded_field(line, parsed, 'exe'),
                'addr': parsed.get('addr'),
                'terminal': parsed.get('terminal'),
            })
    for item in out['paths']:
        name=item['name']
        if name and name!='(null)':
            item['path']=posixpath.normpath(name if name.startswith('/') else posixpath.join(out.get('cwd') or '',name))
    out['status']='AUDIT_EVENT' if complete else 'AUDIT_PARTIAL'
    return out


class AuditReader:
    def __init__(self,store,path='/var/log/audit/audit.log'):
        self.store=store;self.path=Path(path);self.stream=None;self.groups={}
        self.identity=None;self.status='STARTING';self.last_event=None;self.bad=0;self.lag_bytes=None

    def flush(self,all=False):
        now=time.monotonic()
        for key,(lines,touched) in list(self.groups.items()):
            if all or now-touched>2:
                self.store.add('audit',event(lines,False));del self.groups[key]

    def poll(self):
        try:
            bad_before=self.bad
            if self.stream is None:
                fd=os.open(self.path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK);info=os.fstat(fd)
                import stat
                if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0,os.geteuid()) or info.st_mode & 0o022:
                    os.close(fd)
                    raise ValueError('Audit source must be a trusted regular file')
                self.stream=os.fdopen(fd,'rb');self.identity=[info.st_dev,info.st_ino]
                saved=self.store.get('audit_cursor',{})
                if saved.get('identity')==self.identity and saved.get('offset',0)<=info.st_size:self.stream.seek(saved['offset'])
                elif saved and not saved.get('rotation_followed'):self.store.add('host_errors',{'timestamp':time.time(),'status':'AUDIT_SOURCE_CHANGED','detail':'Stored inode unavailable or file truncated; current file read from start; rotated files may be missing.'})
            for _ in range(500):
                start=self.stream.tell();line=self.stream.readline(65537)
                if not line:break
                if len(line)>65536:self.bad+=1;self.status='OVERSIZED_AUDIT_LINE';continue
                if not line.endswith(b'\n'):self.stream.seek(start);break
                text=line.decode('utf-8',errors='replace').rstrip();mark=MARK.search(text)
                if not mark:self.bad+=1;continue
                node=fields(text).get('node','');key=(node,mark[2],mark[3]);self.last_event=float(mark[2])
                lines,_=self.groups.get(key,([],0));lines.append(text);self.groups[key]=(lines,time.monotonic())
                if mark[1]=='EOE' or len(lines)>=128 or sum(map(len,lines))>256*1024:
                    self.store.add('audit',event(lines,mark[1]=='EOE'));del self.groups[key]
                if len(self.groups)>1024:self.flush(all=True)
            self.flush();self.status='READING' if self.bad==bad_before else 'READING_WITH_REJECTIONS'
            self.lag_bytes=max(0,os.fstat(self.stream.fileno()).st_size-self.stream.tell())
            if not self.groups:self.store.set('audit_cursor',{'identity':self.identity,'offset':self.stream.tell()})
            info=self.path.stat();rotated=[info.st_dev,info.st_ino]!=self.identity
            if rotated and self.stream.tell()>=os.fstat(self.stream.fileno()).st_size:
                # 2.2.51: the old file was read to its end; the new one starts at 0. Not an error
                # (every auditd rotation was reported as AUDIT_SOURCE_CHANGED, field 2026-11-19).
                self.flush(all=True);self.stream.close();self.stream=None
                self.store.set('audit_cursor',{'identity':None,'offset':0,'rotation_followed':True,'previous':self.identity})
            elif not rotated and info.st_size<self.stream.tell():
                self.flush(all=True);self.stream.seek(0);self.store.add('host_errors',{'timestamp':time.time(),'status':'AUDIT_TRUNCATED'})
        except (OSError,ValueError) as exc:self.status='UNAVAILABLE: '+str(exc)[:180]
        return {'status':self.status,'last_event':self.last_event,'unparsed_lines':self.bad,
                'source':str(self.path),'lag_bytes':self.lag_bytes,'pending_groups':len(self.groups)}

    def close(self):
        self.flush(all=True)
        if self.stream:self.stream.close()


def correlate(store,result,window=7*86400,limit=20):
    """Return path/time candidates; never claim unsupported writer attribution."""
    output=[];snapshot=result.get('target') or {};path=snapshot.get('path');start=result.get('started_at',0)
    if not path:return output
    rows=store.db.execute("SELECT r.id,r.body FROM audit_paths p JOIN records r ON r.id=p.record_id WHERE p.path=? AND p.event_time BETWEEN ? AND ? ORDER BY p.event_time DESC LIMIT ?",(path,start-window,result.get('finished_at',start)+2,limit)).fetchall()
    for ident,body in rows:
        item=json.loads(body)
        if not start-window<=item.get('timestamp',0)<=result.get('finished_at',start)+2:continue
        for candidate in item.get('paths',[]):
            if candidate.get('path')==path:
                inode_equal=str(candidate.get('inode'))==str(snapshot.get('inode'))
                expected_dev=f"{os.major(snapshot['device']):02x}:{os.minor(snapshot['device']):02x}" if 'device' in snapshot else None
                device_equal=candidate.get('dev')==expected_dev
                output.append({'audit_record_id':ident,'relationship':'PATH_INODE_DEVICE_TIME' if inode_equal and device_equal else 'PATH_TIME_ONLY','attribution':'CANDIDATE_NOT_CONFIRMED_WRITER','audit':item})
                break
        if len(output)>=limit:break
    return output
