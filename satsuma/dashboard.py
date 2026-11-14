"""DEPRECATED legacy curses dashboard (compatibility only).

Production entrypoint is ``python -m satsuma.dashboard_qt.app`` / ``main.py
--dashboard`` and reads through the read-only reader socket.
"""
import curses,json,os,sqlite3,subprocess,time
from pathlib import Path
from .protected_storage import check
from .sentinel import DialogController

MODULES=[('1','Overview','GENEL BAKIŞ'),('2','dns','DNS'),('3','security','GÜVENLİK'),('4','connections','BAĞLANTILAR'),('5','otx','OTX'),('6','file_security','DOSYA'),('7','policy','AYARLAR'),('8','events','OLAYLAR'),('9','errors','HATALAR')]

def state(db,key,default=None):
    row=db.execute('SELECT body FROM state WHERE key=?',(key,)).fetchone()
    try:return json.loads(row[0]) if row else default
    except (ValueError,TypeError):return default

def rows(db,kind,limit=8):
    return [json.loads(body) for _,body in db.execute('SELECT id,body FROM records WHERE kind=? ORDER BY id DESC LIMIT ?',(kind,limit))]

def clean(value):return ''.join(c if c.isprintable() else ' ' for c in str(value))

def time_text(value):
    try:return time.strftime('%d.%m %H:%M:%S',time.localtime(float(value)))
    except (TypeError,ValueError,OverflowError):return str(value or '-')

def policy_lines(policy):
    """Turn the effective policy into operator-readable behaviour, not JSON."""
    workers=policy.get('workers',{}) if isinstance(policy,dict) else {}
    lines=[('POLICY DAVRANISI', 'Uygulanan politika ve worker davranışları')]
    names={'suricata_collector':'Suricata olay toplama','dns_monitor':'DNS/PTR izleme','response':'NFTables aksiyonları',
           'audit':'Audit değişiklik izleme','finding':'Bulgu korelasyonu','evidence':'Kanıt arşivi'}
    for key,label in names.items():
        item=workers.get(key,{}) or {}; enabled=item.get('enabled','?')
        lines.append((label, 'AKTİF' if enabled is True else 'PASİF' if enabled is False else str(enabled)))
        if key=='suricata_collector': lines.append(('  Kaynak',item.get('eve_path','-')))
        elif key=='dns_monitor':
            lines.append(('  Beklenen DNS',', '.join(map(str,item.get('expected_servers',[]))) or '-'))
            lines.append(('  İzlenen alanlar',', '.join(map(str,item.get('watch_domains',[]))) or '-'))
            lines.append(('  DNS aksiyonları',', '.join(map(str,item.get('actions',[]))) or 'Yok'))
        elif key=='response':
            nft=item.get('nft',{}) or {}; lines.append(('  NFT set',f"{nft.get('family','-')} {nft.get('table','-')} / IPv4:{nft.get('ipv4_set','-')} IPv6:{nft.get('ipv6_set','-')}"))
        elif key=='audit': lines.append(('  Audit kaynağı',item.get('log_path','-')))
        elif key=='finding': lines.append(('  Korelasyon',f"{item.get('correlation_window_seconds','-')} sn / {item.get('audit_candidate_limit','-')} aday"))
        elif key=='evidence': lines.append(('  Kanıt bütçesi',f"{item.get('archive_budget_bytes','-')} bayt"))
    corr=policy.get('correlation',{}) or {}; lines.append(('Frekans penceresi',f"{corr.get('frequency_window_seconds','-')} saniye"))
    return lines

def readable(kind,item):
    """Render stored records as concise operator fields while retaining evidence."""
    if not isinstance(item,dict): return [('Veri',str(item))]
    out=[]
    if kind in ('alerts','events'):
        alert=item.get('alert',{}) if isinstance(item.get('alert'),dict) else item
        event=item.get('event_type',item.get('type','-')); out.append(('Olay',str(event).upper()))
        out.append(('Zaman',time_text(item.get('timestamp'))))
        if item.get('signature') or alert.get('signature'): out.append(('İmza',item.get('signature',alert.get('signature'))))
        if item.get('severity') is not None or alert.get('severity') is not None: out.append(('Önem',str(item.get('severity',alert.get('severity')))))
        if item.get('category') or alert.get('category'): out.append(('Kategori',item.get('category',alert.get('category'))))
        if item.get('src_ip') or item.get('sources'): out.append(('Kaynak',item.get('src_ip') or ', '.join(map(str,item.get('sources',[])))))
        if item.get('dest_ip') or item.get('destinations'): out.append(('Hedef',item.get('dest_ip') or ', '.join(map(str,item.get('destinations',[])))))
        if item.get('src_port') or item.get('dest_port'): out.append(('Port',f"{item.get('src_port','-')} → {item.get('dest_port','-')}"))
        if item.get('suricata_action'): out.append(('Suricata kararı',item['suricata_action']))
        if item.get('risk_level'): out.append(('Risk',f"{item['risk_level']} ({item.get('risk_score','-')})"))
        if item.get('analysis',{}).get('reasons'): out.append(('Gerekçe',', '.join(item['analysis']['reasons'])))
        if isinstance(item.get('dns'),dict): out.append(('DNS kaydı',item['dns'].get('query',item['dns'].get('rrname','-'))))
        if item.get('raw_id') is not None: out.append(('Kayıt no',item['raw_id']))
        return out
    if kind=='actions':
        return [('Zaman',time_text(item.get('timestamp'))),('İşlem',str(item.get('status','-')).replace('_',' ').upper()),
                ('Hedef',item.get('target') or 'Operatör seçimi gerekli'),('Neden',item.get('reason','-')),
                ('NFT doğrulama',item.get('traffic_drop_verified',item.get('drop_rule_verification','-'))),('Kayıt no',item.get('raw_id','-'))]
    if kind=='sentinel':
        ips=item.get('target') or ', '.join(map(str,item.get('ips',[]))) or '-'
        return [('Zaman',time_text(item.get('timestamp'))),('Karar',str(item.get('status',item.get('decision','-'))).replace('_',' ').upper()),
                ('Alt ağ / IP',item.get('subnet',ips)),('IP listesi',ips),('Neden',item.get('reason','PTR yokluğu / operatör kararı')),('NFT sonucu',item.get('drop_rule_verification','-'))]
    if kind=='errors': return [('Zaman',time_text(item.get('timestamp'))),('Bileşen',item.get('component','-')),('Hata',item.get('error','-')),('Kayıt no',item.get('raw_id','-'))]
    if kind=='dns':
        resolver=item.get('resolver') or item.get('dest_ip') or '-'
        ips=', '.join(map(str,item.get('ips',[]))) or item.get('target_ip','-')
        rcode=item.get('rcode') or ('YANIT BEKLENİYOR' if item.get('type')=='request' else '-')
        return [('Zaman',time_text(item.get('timestamp'))),('Sorgulanan alan adı',item.get('query',item.get('domain','-'))),('Sorgunun gönderildiği DNS',resolver),('DNS yanıtı',rcode),('Dönen IP adresi',ips),('Kayıt türü',item.get('rrtype','-'))]
    return [(str(k).replace('_',' ').title(),str(v)) for k,v in list(item.items())[:8]]

def run_dashboard():
    """Kanonik PyQt dashboard'a yonlendir (eski curses entrypoint kaldirildi).

    ``console`` ve ``screen`` yalnizca geriye donuk test/uyumluluk icin
    tutulur; production call-path bu fonksiyondan gecmez.
    """
    from .dashboard_qt.app import run as run_qt
    return run_qt()

def console(s,db):
    """Compatibility entry point used by the worker/dashboard tests."""
    dialogs=DialogController()
    try:
        return screen(s,db,dialogs)
    finally:
        dialogs.close()

def _forward_dns(rows_in):
    """User-facing DNS list: forward A/AAAA questions only, never reverse .arpa PTR rows."""
    out=[]
    seen=set()
    for item in rows_in:
        if not isinstance(item,dict): continue
        q=str(item.get('query') or '').rstrip('.').lower()
        rr=str(item.get('rrtype') or '').upper()
        if not q or q.endswith('.in-addr.arpa') or q.endswith('.ip6.arpa') or rr=='PTR':
            continue
        if rr not in ('A','AAAA','CNAME','HTTPS','SVCB'):
            continue
        # Prefer responses. Keep one row per transaction/question/answer set.
        key=(item.get('flow_id'),item.get('tx_id'),q,rr,tuple(item.get('ips') or []),item.get('rcode'))
        if key in seen: continue
        seen.add(key);out.append(item)
    return out


def _system_metrics():
    """Read lightweight host metrics without adding a dependency."""
    cpu=0
    try:
        load=os.getloadavg()[0]; cpus=max(1,os.cpu_count() or 1); cpu=min(100,int(load*100/cpus))
    except Exception: pass
    ram=0
    try:
        vals={}
        for line in Path('/proc/meminfo').read_text().splitlines():
            k,v=line.split(':',1); vals[k]=int(v.strip().split()[0])
        total=vals.get('MemTotal',0); avail=vals.get('MemAvailable',0)
        ram=int((total-avail)*100/total) if total else 0
    except Exception: pass
    disk=0
    try:
        st=os.statvfs('/'); disk=int((st.f_blocks-st.f_bavail)*100/st.f_blocks) if st.f_blocks else 0
    except Exception: pass
    return cpu,ram,disk

def _net_bytes():
    total=0
    try:
        for line in Path('/proc/net/dev').read_text().splitlines()[2:]:
            _,data=line.split(':',1); f=data.split(); total+=int(f[0])+int(f[8])
    except Exception: pass
    return total


def _fit(text,width):
    text=clean(text)
    return text if len(text)<=width else text[:max(0,width-1)]+'…'


def screen(s,db,dialogs):
    curses.curs_set(0);s.timeout(700);tab=0;message='';traffic=[];last_net=_net_bytes();last_net_at=time.monotonic()
    if curses.has_colors():
        curses.start_color();curses.use_default_colors()
        # Satsuma visual identity: orange + navy, with semantic green/red.
        if getattr(curses,'COLORS',0) >= 256:
            orange,navy,softblue = 208,17,39
        else:
            orange,navy,softblue = curses.COLOR_YELLOW,curses.COLOR_BLUE,curses.COLOR_CYAN
        curses.init_pair(1,softblue,-1)       # information
        curses.init_pair(2,curses.COLOR_GREEN,-1)
        curses.init_pair(3,orange,-1)         # Satsuma accent
        curses.init_pair(4,curses.COLOR_RED,-1)
        curses.init_pair(5,navy if getattr(curses,'COLORS',0)>=256 else curses.COLOR_BLUE,-1)
        curses.init_pair(6,curses.COLOR_WHITE,navy if getattr(curses,'COLORS',0)>=256 else curses.COLOR_BLUE)
        curses.init_pair(7,orange,navy if getattr(curses,'COLORS',0)>=256 else curses.COLOR_BLUE)
    def put(y,x,text,style=0,maxw=None):
        h,w=s.getmaxyx()
        if 0<=y<h and 0<=x<w:
            try:s.addnstr(y,x,clean(text),max(0,min(w-x-1,maxw if maxw is not None else w-x-1)),style)
            except curses.error:pass
    def box(y,x,h,w,title='',style=0):
        if h<3 or w<6:return
        put(y,x,'┌'+'─'*(w-2)+'┐');put(y+h-1,x,'└'+'─'*(w-2)+'┘')
        for yy in range(y+1,y+h-1):put(yy,x,'│');put(yy,x+w-1,'│')
        if title:put(y,x+2,' '+title+' ',style or curses.A_BOLD|curses.color_pair(1),w-4)
    def card(y,x,w,title,value,ok=True):
        box(y,x,4,w,title,curses.A_BOLD|curses.color_pair(1));put(y+2,x+2,_fit(value,w-4),curses.A_BOLD|curses.color_pair(2 if ok else 3),w-4)
    def bar(y,x,label,value,maxv,width=16):
        ratio=0 if not maxv else max(0,min(1,float(value)/maxv));n=int(width*ratio)
        put(y,x,f'{label:<6} ');put(y,x+7,'█'*n+'░'*(width-n),curses.color_pair(2));put(y,x+8+width,f'{int(value):>3}%')
    def table_header(y,x,cols):
        off=x
        for title,width in cols:
            put(y,off,_fit(title,width),curses.A_BOLD|curses.color_pair(1),width);off+=width+1
        put(y+1,x,'─'*max(1,off-x-1),curses.color_pair(1),off-x-1)
    while True:
        dialogs.tick(db);s.erase();h,w=s.getmaxyx()
        if h<28 or w<110:
            put(1,2,'Satsuma Güvenlik Merkezi için terminali en az 110x28 boyutuna büyütün.',curses.color_pair(3));put(3,2,'Q: çıkış')
            s.refresh();k=s.getch()
            if k in (ord('q'),ord('Q')):return
            continue
        health=state(db,'health',{}) or {};sh=state(db,'sentinel_health',{}) or {};policy=health.get('policy',{}) or {}
        stale=time.time()-health.get('updated_at',0)>8
        # Product header
        put(0,0,' '*(w-1),curses.color_pair(6),w-1)
        put(1,0,' '*(w-1),curses.color_pair(6),w-1)
        put(0,2,'SATSUMA-SECURITY',curses.A_BOLD|curses.color_pair(7),20)
        put(0,20,'Powered by GPT  •  by SatsumaBilgisayar',curses.A_BOLD|curses.color_pair(6),42)
        put(0,max(66,w-24),f"CORE v{health.get('version','-')}",curses.A_BOLD|curses.color_pair(7),20)
        put(1,2,'satsumabilgisayar.com  •  0 506 030 70 85  •  Maltepe / İstanbul',curses.color_pair(6),66)
        put(1,max(70,w-22),time.strftime('%d.%m.%Y  %H:%M:%S'),curses.color_pair(6),20)
        # Compact product navigation, current module highlighted.
        x=2
        for i,(k,_,label) in enumerate(MODULES):
            token=f' {k} {label.title()} '
            style=curses.A_BOLD|(curses.color_pair(3) if i==tab else curses.color_pair(1))
            put(3,x,token,style,len(token));x+=len(token)+1
            if x>w-18:break
        put(4,0,'─'*(w-1),curses.color_pair(5),w-1)
        y0=6
        kind=MODULES[tab][1]
        if kind=='Overview':
            # Executive overview: status first, then live module feed and security posture.
            alert=(rows(db,'alerts',1) or [{}])[0]
            dnslist=_forward_dns(rows(db,'dns',80)); dnsitem=dnslist[0] if dnslist else {}
            action=(rows(db,'actions',1) or [{}])[0]
            audit=(rows(db,'audit',1) or [{}])[0]
            otx=(rows(db,'otx',1) or [{}])[0]; otxh=state(db,'otx_health',{}) or {}

            # Four larger cards are easier to read than the previous six tiny boxes.
            gap=2; cw=(w-6-gap*3)//4
            cards=[
                ('KORUMA','AKTİF' if health.get('status')=='running' else 'BEKLİYOR',health.get('status')=='running'),
                ('SURICATA','IDS • İZLİYOR',bool(health.get('last_event'))),
                ('IP ENGELLEME',f"{len(rows(db,'actions',500))} AKSİYON",bool(health.get('response_enabled'))),
                ('DNS',f"{health.get('dns_records',0)} DNS KAYDI",True),
            ]
            for i,c in enumerate(cards): card(y0,2+i*(cw+gap),cw,*c)

            mainy=y0+5
            leftw=max(62,int(w*.64)); rightx=leftw+3; rightw=w-rightx-2
            box(mainy,2,h-mainy-3,leftw,'CANLI KORUMA AKIŞI',curses.A_BOLD|curses.color_pair(3))
            box(mainy,rightx,h-mainy-3,rightw,'KONTROL MERKEZİ',curses.A_BOLD|curses.color_pair(3))

            live=[
              ('SURICATA IDS', alert.get('signature') or alert.get('category') or 'Olay bekleniyor', time_text(alert.get('timestamp'))[-8:] if alert else '-','net'),
              ('DNS', (str(dnsitem.get('query','-'))+'  →  '+(', '.join(dnsitem.get('ips') or []) or str(dnsitem.get('rcode','-')))) if dnsitem else 'DNS kaydı bekleniyor', time_text(dnsitem.get('timestamp'))[-8:] if dnsitem else '-','dns'),
              ('AUDIT', audit.get('exe') or audit.get('path') or audit.get('comm') or 'Olay bekleniyor', time_text(audit.get('timestamp'))[-8:] if audit else '-','audit'),
              ('OTX', ('%s  •  Skor %s' % (otx.get('ip','-'),otx.get('satsuma_otx_risk_score','-'))) if otx else str(otxh.get('status','YAPILANDIRILMADI')).upper(), time_text(otx.get('timestamp'))[-8:] if otx else '-','otx'),
              ('IP ENGELLEME', (str(action.get('target','-'))+'  •  '+str(action.get('status','-')).replace('_',' ').upper()) if action else 'Aksiyon bekleniyor', time_text(action.get('timestamp'))[-8:] if action else '-','block'),
              ('BAĞLANTILAR', f"{sh.get('peers',0)} aktif eş  •  {sh.get('subnets',0)} subnet", time_text(sh.get('updated_at'))[-8:],'conn'),
            ]
            yy=mainy+2
            put(yy,4,'MODÜL',curses.A_BOLD|curses.color_pair(1),15)
            put(yy,20,'SON DURUM / SON ÇIKTI',curses.A_BOLD|curses.color_pair(1),leftw-34)
            put(yy,2+leftw-10,'ZAMAN',curses.A_BOLD|curses.color_pair(1),8)
            put(yy+1,4,'─'*(leftw-6),curses.color_pair(5),leftw-6); yy+=2
            max_live=max(0,min(len(live),h-mainy-10))
            for name,value,stamp,_ in live[:max_live]:
                put(yy,4,f'● {name:<12}',curses.A_BOLD|curses.color_pair(3),15)
                style=curses.color_pair(2) if 'HATA' not in str(value).upper() and 'FAILED' not in str(value).upper() else curses.color_pair(4)
                put(yy,20,_fit(value,leftw-34),style,leftw-34)
                put(yy,2+leftw-10,stamp,curses.color_pair(1),8); yy+=1

            # Recent security timeline in the unused lower-left space.
            if yy < h-6:
                yy+=1; put(yy,4,'SON GÜVENLİK OLAYLARI',curses.A_BOLD|curses.color_pair(3),leftw-6); yy+=1
                put(yy,4,'─'*(leftw-6),curses.color_pair(5),leftw-6); yy+=1
                for it in rows(db,'alerts',max(0,min(4,h-yy-4))):
                    txt=f"{time_text(it.get('timestamp'))[-8:]}  {it.get('signature') or it.get('category') or 'Ağ olayı'}"
                    put(yy,4,'› '+_fit(txt,leftw-8),0,leftw-6); yy+=1

            ry=mainy+2
            put(ry,rightx+2,'SİSTEM SAĞLIĞI',curses.A_BOLD|curses.color_pair(3),rightw-4)
            cpu,ram,disk=_system_metrics(); bw=max(8,min(18,rightw-18))
            bar(ry+2,rightx+2,'CPU',cpu,100,bw);bar(ry+3,rightx+2,'RAM',ram,100,bw);bar(ry+4,rightx+2,'DİSK',disk,100,bw)
            put(ry+6,rightx+2,'AĞ TRAFİĞİ',curses.A_BOLD|curses.color_pair(3),rightw-4)
            now=time.monotonic();cur=_net_bytes();rate=max(0,int((cur-last_net)/max(.1,now-last_net_at)));last_net=cur;last_net_at=now
            traffic.append(rate);traffic[:]=traffic[-60:];peak=max(1,max(traffic or [0]));gw=max(8,rightw-5)
            blocks='▁▂▃▄▅▆▇█'; graph=''.join(blocks[min(7,int(v*7/peak))] for v in traffic[-gw:])
            put(ry+8,rightx+2,_fit(graph,gw),curses.color_pair(3),gw)
            put(ry+9,rightx+2,f'{rate/1024:.1f} KiB/sn  •  tepe {peak/1024:.1f}',0,rightw-4)

            put(ry+11,rightx+2,'KORUMA DURUMU',curses.A_BOLD|curses.color_pair(3),rightw-4)
            protections=[
                ('Suricata', 'IDS', True),
                ('nftables', 'AÇIK' if health.get('response_enabled') else 'KAPALI', bool(health.get('response_enabled'))),
                ('OTX', str(otxh.get('status','YAPILANDIRILMADI')).upper(), str(otxh.get('status','')).lower() in ('active','ok','running','connected')),
                ('Tarama', 'SAATLİK', True),
            ]
            for i,(name,val,ok) in enumerate(protections):
                put(ry+12+i,rightx+2,f"{'●' if ok else '○'} {name:<10}",curses.color_pair(2 if ok else 3),13)
                put(ry+12+i,rightx+15,_fit(val,rightw-18),curses.A_BOLD,rightw-18)

            sy=ry+17
            if sy < h-5:
                put(sy,rightx+2,'BUGÜN / CANLI',curses.A_BOLD|curses.color_pair(3),rightw-4)
                metrics=[('Ağ olayı',health.get('events',0)),('DNS kayıtları',health.get('dns_records',0)),('Engel aksiyonu',len(rows(db,'actions',500))),('Aktif eş',sh.get('peers','-'))]
                for i,(a,b) in enumerate(metrics):
                    if sy+1+i>=h-3:break
                    put(sy+1+i,rightx+2,f'{a:<16}',curses.color_pair(1),16);put(sy+1+i,rightx+19,str(b),curses.A_BOLD|curses.color_pair(3),rightw-21)
        elif kind=='dns':
            box(y0,2,h-y0-3,w-4,'DNS KAYITLARI')
            dnsrows=_forward_dns(rows(db,'dns',160))
            cols=[('Zaman',10),('Sorgulanan Alan Adı',max(24,int((w-10)*.30))),('DNS Sunucusu',16),('Sonuç (IP)',max(18,int((w-10)*.25))),('Tür',7)]
            table_header(y0+2,4,cols);yy=y0+4
            for item in dnsrows[:h-y0-8]:
                vals=[time_text(item.get('timestamp'))[-8:],item.get('query','-'),item.get('resolver','-'),', '.join(item.get('ips') or []) or item.get('rcode') or 'Yanıt bekleniyor',item.get('rrtype','-')]
                xx=4
                for val,(_,ww) in zip(vals,cols):put(yy,xx,_fit(val,ww),curses.color_pair(2) if val in (item.get('ips') or []) else 0,ww);xx+=ww+1
                yy+=1
            if not dnsrows:put(y0+4,4,'Henüz kullanıcıya gösterilecek A/AAAA DNS kaydı yok.',curses.color_pair(3))
            put(h-4,4,'PTR / .arpa ters DNS sorguları bu kullanıcı ekranında gösterilmez; teknik kayıtlarda korunur.',curses.color_pair(3),w-8)
        elif kind=='security':
            box(y0,2,h-y0-3,w-4,'GÜVENLİK DURUMU')
            vals=[('ENGELLENEN IP',len(rows(db,'actions',500))),('ŞÜPHELİ OLAY',len(rows(db,'alerts',500))),('İZLENEN BAĞLANTI',sh.get('peers',0)),('DNS KAYITLARI',health.get('dns_records',0))]
            cw=(w-11)//4
            for i,(a,b) in enumerate(vals):card(y0+2,4+i*(cw+1),cw,a,str(b),a!='ŞÜPHELİ OLAY' or not b)
            box(y0+7,4,h-y0-12,(w-11)//2,'SON GÜVENLİK OLAYLARI');box(y0+7,6+(w-11)//2,h-y0-12,(w-11)//2,'GÜVENLİK SERVİSLERİ')
            for i,it in enumerate(rows(db,'alerts',min(10,h-y0-16))):put(y0+9+i,6,_fit(f"{time_text(it.get('timestamp'))[-8:]}  {it.get('signature') or it.get('category') or 'Ağ olayı'}",(w-17)//2),0,(w-17)//2)
            sx=8+(w-11)//2;services=[('Satsuma Core',health.get('status')=='running'),('DNS İzleme',health.get('dns_records') is not None),('IP Engelleme',health.get('response_enabled')),('Bağlantı İzleme',sh.get('status') in ('running','active')),('Dosya Güvenliği',True)]
            for i,(name,ok) in enumerate(services):put(y0+9+i,sx,f"{'●' if ok else '○'} {name:<24} {'AKTİF' if ok else 'BEKLİYOR'}",curses.color_pair(2 if ok else 3))
        elif kind=='connections':
            box(y0,2,h-y0-3,w-4,'BAĞLANTI İZLEME')
            table_header(y0+2,4,[('Zaman',10),('Hedef / IP',28),('Karar',18),('Neden',w-66)])
            for i,it in enumerate(rows(db,'sentinel',h-y0-8)):
                vals=[time_text(it.get('timestamp'))[-8:],it.get('target') or it.get('subnet') or ', '.join(it.get('ips',[])) or '-',str(it.get('status',it.get('decision','-'))).upper(),it.get('reason','-')]
                widths=[10,28,18,w-66];xx=4
                for v,ww in zip(vals,widths):put(y0+4+i,xx,_fit(v,ww),0,ww);xx+=ww+1
        elif kind=='otx':
            box(y0,2,h-y0-3,w-4,'ALIENVAULT OTX • TEHDİT İSTİHBARATI',curses.A_BOLD|curses.color_pair(3))
            oh=state(db,'otx_health',{}) or {}; all_otx=rows(db,'otx',500)
            blocked=[x for x in all_otx if x.get('decision')=='blocked']
            last=blocked[0] if blocked else (all_otx[0] if all_otx else {})
            tlsok=bool(oh.get('tls_verified'))
            info=[('Durum',str(oh.get('status','YAPILANDIRILMADI')).upper()),('OTX tarafından bloklanan IP',len(blocked)),
                  ('Son IP',last.get('ip','-')),('Satsuma OTX Risk Skoru',last.get('satsuma_otx_risk_score','-')),
                  ('Pulse eşleşmesi',last.get('pulse_count','-')),('Karar',str(last.get('decision','-')).upper()),
                  ('Engelleme nedeni',last.get('reason','-')),('TLS aktarımı','DOĞRULANDI' if tlsok else 'DOĞRULANMADI'),
                  ('TLS sürümü',oh.get('tls_version','-')),('Şifre takımı',oh.get('cipher','-')),('Sertifika ana bilgisayarı',oh.get('host','-'))]
            for i,(a,b) in enumerate(info[:h-y0-8]):
                put(y0+2+i,4,f'{a:<28}',curses.A_BOLD|curses.color_pair(5),28);put(y0+2+i,34,_fit(b,w-40),curses.color_pair(2 if (a!='TLS aktarımı' or tlsok) else 4),w-40)
            put(h-5,4,'API anahtarı: sudo satsuma-core-otx set-key',curses.color_pair(3),w-8)
            put(h-4,4,'TLS sertifika doğrulaması kapatılamaz; başarısız doğrulamada OTX sorgusu reddedilir.',curses.color_pair(1),w-8)
        elif kind=='policy':
            box(y0,2,h-y0-3,w-4,'GÜVENLİK AYARLARI');eff=state(db,'policy_effective',{}) or {};data=[('Revizyon',policy.get('revision',eff.get('revision','-'))),('Durum',policy.get('status','-'))]+policy_lines(eff)
            for i,(a,b) in enumerate(data[:h-y0-7]):put(y0+2+i,4,_fit(f'{a}: {b}',w-8),0,w-8)
        elif kind=='file_security':
            box(y0,2,h-y0-3,w-4,'DOSYA GÜVENLİĞİ')
            put(y0+2,4,'ClamAV dosya bulguları ve kanıt kayıtları',curses.A_BOLD|curses.color_pair(1))
            put(y0+6,4,'V61 bu sürümde kurulmaz, çağrılmaz veya yeniden etkinleştirilmez.',curses.color_pair(2),w-8)
        else:
            dbkind='events' if kind=='events' else 'errors';box(y0,2,h-y0-3,w-4,MODULES[tab][2]);data=rows(db,dbkind,12);yy=y0+2
            for item in data:
                for a,b in readable(dbkind,item):put(yy,4,_fit(f'{a}: {b}',w-8),curses.color_pair(4) if a=='Hata' else 0,w-8);yy+=1
                yy+=1
                if yy>=h-5:break
        put(h-2,2,message or '1-9 bölüm   R yenile   Q çıkış',curses.A_BOLD);s.refresh();key=s.getch()
        if key in (ord('q'),ord('Q')):return
        if key in [ord(x[0]) for x in MODULES]:tab=next(i for i,x in enumerate(MODULES) if ord(x[0])==key);message=''
        elif key in (ord('r'),ord('R')):message='Veriler yenilendi'
