"""Connected-peer surveillance and explicit, expiring operator decisions."""
import concurrent.futures
import ipaddress
import json
import re
import signal
import subprocess
import uuid
import time
import uuid
from .store import Store
from .config import load_with_policy
from .response import ResponseWorker
from .response_policy import authorize_destructive, denied_action_record


def setup(db):
    db.execute('CREATE TABLE IF NOT EXISTS sentinel_requests(id TEXT PRIMARY KEY, created REAL, body TEXT, status TEXT)')
    db.commit()


def peers():
    from .subnet_protection import connection_counts
    return set(connection_counts())


def ptr(ip):
    try:
        r=subprocess.run(['dig','-x',ip,'+time=1','+tries=1','+noall','+comments','+answer'],capture_output=True,text=True,timeout=2)
        m=re.search(r'status: (\w+)',r.stdout)
        if r.returncode or not m or m[1] not in ('NOERROR','NXDOMAIN'): return 'error'
        return 'present' if re.search(r'\sIN\s+PTR\s',r.stdout) else 'absent'
    except (OSError,subprocess.TimeoutExpired): return 'error'


class Monitor:
    def __init__(self,store,response):
        self.store,self.response=store,response
        setup(store.db)
        store.db.execute("UPDATE sentinel_requests SET status='expired' WHERE status IN ('pending','yes','no','block','running')")
        store.db.commit()
        self.watches={}
        self.subnet_streaks=store.get('sentinel_subnet_streaks',{}) or {}

    def _handle_approval(self, ident, req, status, now):
        """kind='approval' onay sonucunu isle.

        - 'yes' (Evet, bana ait): islem mesru kabul edilir; ticket kapatilir.
        - 'no'  (Hayir, bana ait degil): ilgili PID dogrulanip sonlandirilir.
        - 'allow'/'block' bu akista kullanilmaz.
        """
        # 'pending' -> kullanici henuz karar vermedi; popup beklemede.
        # Bu durumda hicbir sey yapma, aksi halde istek popup gosterilmeden
        # kapanir.
        if status == 'pending':
            return
        pid = req.get('pid')
        cmd = req.get('cmd') or ''
        rule_id = req.get('rule_id')
        self.store.add('sentinel_decisions', {
            'timestamp': now,
            'kind': 'approval',
            'rule_id': rule_id,
            'pid': pid,
            'cmd': cmd,
            'decision': status,
            'request_id': ident,
        })
        if status == 'yes':
            # Kullanici islemin kendisine ait oldugunu onayladi -> mesru.
            self.store.db.execute(
                "UPDATE sentinel_requests SET status='done' WHERE id=?",
                (ident,),
            )
            self.store.db.commit()
            return
        if status == 'no':
            # Kullanici islemin kendisine ait olmadigini bildirdi -> sonlandir.
            if pid:
                evidence = {
                    'pid': pid,
                    'cmd': cmd,
                    'starttime': req.get('starttime'),
                    'start_seconds': req.get('start_seconds'),
                    'exe': req.get('exe'),
                }
                operator_finding = {
                    'classification': 'confirmed',
                    'policy_allowed': True,
                    'multi_source_verified': True,
                    'source': ['operator_confirmation', 'smart_rule'],
                    'type': 'operator_confirmed_process_kill',
                    'rule_id': str(rule_id),
                    'event': evidence,
                    'corroborating_findings': req.get('corroborating_findings', []),
                }
                auth = authorize_destructive(
                    'process_kill', operator_finding, self.response.config,
                    context={'pid': pid, 'manual': True}, evidence_store=self.store,
                )
                if auth.allowed:
                    result = self.response.kill_process_tree(
                        pid,
                        f'user-confirmed approval {ident}',
                        evidence=evidence, context={'rule_id':str(rule_id),'finding':operator_finding},
                    )
                    self.store.add('actions', {
                        'timestamp': now,
                        'status': result.get('status', 'kill_attempted'),
                        'ticket_id': None,
                        'pid': pid,
                        'reason': 'Kullanici dogrulamasi: bana ait degil',
                        'request_id': ident,
                    })
                else:
                    self.store.add('actions', {
                        **denied_action_record(auth, operator_finding),
                        'pid': pid,
                        'request_id': ident,
                    })
            self.store.db.execute(
                "UPDATE sentinel_requests SET status='done' WHERE id=?",
                (ident,),
            )
            self.store.db.commit()
            return
        # Diger durumlar (expired/invalid): istek kapatilir, aksiyon yok.
        self.store.db.execute(
            "UPDATE sentinel_requests SET status='done' WHERE id=?",
            (ident,),
        )
        self.store.db.commit()

    def step(self,records,now=None):
        now=time.time() if now is None else now
        groups={}
        for ip,state in records.items():
            addr=ipaddress.ip_address(ip)
            if not addr.is_global or addr.is_multicast: continue
            net=str(ipaddress.ip_network(f'{addr}/{24 if addr.version==4 else 64}',strict=False))
            groups.setdefault(net,{})[ip]=state
        # ``allow`` is the third dialog button.  It must be consumed here;
        # leaving it out causes the same PTR prompt to return every cycle.
        for ident,created,body,status in self.store.db.execute("SELECT * FROM sentinel_requests WHERE status IN ('pending','yes','no','allow','block')").fetchall():
            req=json.loads(body)
            # kind='approval' (yetki yukseltme onayi) ayri islenir.
            if req.get('kind') == 'approval':
                self._handle_approval(ident, req, status, now)
                continue
            net=req['subnet']; watch=self.watches.get(net)
            if now-created>120:
                self.store.db.execute("UPDATE sentinel_requests SET status='expired' WHERE id=?",(ident,))
                if watch: watch['pending']=False
                continue
            if status=='pending': continue
            self.store.db.execute("UPDATE sentinel_requests SET status='running' WHERE id=?",(ident,));self.store.db.commit()
            current=groups.get(net,{})
            if watch:
                watch.update(pending=False, baseline=sum(v=='absent' for v in current.values()),mode='watch' if req['kind']=='block' or status in ('yes','block') else 'dismissed')
            self.store.add('sentinel_decisions',dict(timestamp=now,subnet=net,ips=req['ips'],decision=status,request_id=ident))
            if status=='allow':
                allowed=set(self.store.get('sentinel_allowlist',[]))
                allowed.update(req['ips'])
                self.store.set('sentinel_allowlist',sorted(allowed))
            if status=='block' or (req['kind']=='block' and status=='yes'):
                for ip in req['ips']:
                    if current.get(ip)!='absent': continue
                    operator_finding = {
                        'classification': 'confirmed',
                        'policy_allowed': True,
                        'multi_source_verified': True,
                        'source': ['sentinel_operator', 'ss_peer_observation'],
                        'type': 'sentinel_operator_block',
                        'rule_id': 'sentinel:' + str(ident),
                    }
                    auth = authorize_destructive(
                        'network_isolate', operator_finding, self.response.config,
                        context={'target_ip': ip, 'manual': True},
                    )
                    if not auth.allowed:
                        self.store.add('actions', denied_action_record(auth, operator_finding))
                        self.store.db.execute("UPDATE sentinel_requests SET status='done' WHERE id=?", (ident,))
                        self.store.db.commit()
                        continue
                    result=self.response.block(ip,'Sentinel: operator explicitly approved listed IP',manual=True)
                    family=self.response.config['nft_family'];table=self.response.config['nft_table']
                    name=self.response.config.get('nft_set_v6','blocked_ips_v6') if ipaddress.ip_address(ip).version==6 else self.response.config['nft_set']
                    probe=subprocess.run(['nft','list','set',family,table,name],capture_output=True,text=True,timeout=5)
                    code,output=probe.returncode,probe.stdout
                    result['nft_set_output']=output if code==0 else 'Set okunamadı'
                    result['drop_rule_verification']='Doğrulanmadı; set üyeliği trafik düşürme kanıtı değildir'
                    self.store.add('sentinel',dict(result,request_id=ident))
            self.store.db.execute("UPDATE sentinel_requests SET status='done' WHERE id=?",(ident,))
        self.store.db.commit()
        # The sentinel only keeps the streak and writes a review signal for the
        # dashboard. Blocking a no-PTR peer is the guard's fixed rule
        # (satsuma.peer_watch: a 6th connection in one visit), not decided here.
        # Sentinel yalnızca seriyi tutar ve panele inceleme sinyali yazar. PTR'siz
        # ucun engellenmesi bekçinin sabit kuralıdır (satsuma.peer_watch: bir
        # ziyarette 6. bağlantı); burada karar verilmez.
        active=set(groups)
        for net, members in groups.items():
            absent_ips=sorted(ip for ip,state in members.items() if state=='absent')
            self.subnet_streaks[net]=(int(self.subnet_streaks.get(net,0))+1) if absent_ips else 0
            if absent_ips and self.subnet_streaks[net] == 4:
                self.store.add('sentinel', {
                    'timestamp': now,
                    'subnet': net,
                    'targets': absent_ips,
                    'decision': 'review',
                    'classification': 'indicator',
                    'confidence': 'low',
                    'reason': 'PTR yok + 4 ardışık gözlem; inceleme önerildi. Engelleme bekçinin sabit kuralıdır (bir ziyarette 6. bağlantı)',
                    'source': 'PTR+4',
                })
        for net in list(self.subnet_streaks):
            if net not in active:
                self.subnet_streaks[net]=0
        self.store.set('sentinel_subnet_streaks',self.subnet_streaks)
        present=sum(state=='present' for state in records.values())
        absent=sum(state=='absent' for state in records.values())
        errors=sum(state=='error' for state in records.values())
        self.store.set('sentinel_health',dict(status='running',updated_at=now,peers=len(records),subnets=len(groups),
                                              ptr_present=present,ptr_absent=absent,ptr_error=errors,
                                              ptr_policy='sentinel_reviews_only_guard_blocks_no_ptr_peer_on_sixth_connection'))
        self.store.db.execute("DELETE FROM sentinel_requests WHERE created < ?",(now-86400,));self.store.db.commit()


def run():
    store=Store();config,_,_=load_with_policy();monitor=Monitor(store,ResponseWorker(store,config))
    running=True
    def stop(*args):
        nonlocal running
        running=False
    signal.signal(signal.SIGTERM,stop)
    offset=0
    try:
        while running:
            start=time.monotonic()
            try:
                ips=sorted(peers()); n=len(ips); offset=offset%n if n else 0
                chosen=(ips[offset:]+ips[:offset])[:128];offset+=128
                with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                    records=dict(zip(chosen,pool.map(ptr,chosen)))
                monitor.step(records)
            except Exception as exc:
                store.set('sentinel_health',dict(status='error',updated_at=time.time(),error=str(exc)[:300]))
            while running and time.monotonic()-start<15: time.sleep(.25)
    finally: store.close()


class DialogController:
    """Poll desktop prompts without blocking the dashboard or its SQLite thread."""
    def __init__(self):
        self.process = None
        self.active = None
        self.started = 0
        self.output = None

    def close(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
            self.process = None

    def tick(self, db):
        setup(db)

        # Açık bir Zenity işlemi varsa önce sonucunu işle.
        if self.process is not None:
            code = self.process.poll()

            if code is None and time.monotonic() - self.started < 115:
                return

            if code is None:
                self.close()
                code = 5
                choice = ''
            else:
                if self.output is not None:
                    try:
                        choice = self.output.read().decode(
                            'utf-8',
                            'replace'
                        ).strip()
                    except OSError:
                        choice = ''
                else:
                    choice = ''

                self.process = None

            kind, ident, request_kind = self.active

            if kind == 'result':
                db.execute(
                    "INSERT OR REPLACE INTO state VALUES('sentinel_shown',?)",
                    (json.dumps(ident),)
                )
            elif request_kind == 'approval':
                # Yetki yukseltme onayi: zenity --question
                #   code 0 = "Evet, bana ait"  -> yes (mesru)
                #   code 1 = "Hayir, bana ait degil" -> no (kill)
                #   code 5 = timeout/pencere kapatma -> islem yok
                if code == 0:
                    status = 'yes'
                elif code == 1:
                    status = 'no'
                else:
                    status = 'expired'
                db.execute(
                    """
                    UPDATE sentinel_requests
                    SET status=?
                    WHERE id=?
                      AND status='pending'
                      AND created>?
                    """,
                    (status, ident, time.time() - 120)
                )
            else:
                # Yalnız açık kullanıcı kararı aksiyon verir.
                # Pencere kapatma / timeout / hata bloklama yapmaz.
                status = (
                    'allow'
                    if choice == 'İzin ver'
                    else 'block'
                    if code == 0
                    else 'yes'
                    if code == 1
                    else 'no'
                )

                db.execute(
                    """
                    UPDATE sentinel_requests
                    SET status=?
                    WHERE id=?
                      AND status='pending'
                      AND created>?
                    """,
                    (status, ident, time.time() - 120)
                )

            db.commit()
            self.active = None
            self.output = None
            return

        # Otomatik records.kind='sentinel' sonuçları burada özellikle
        # Zenity popup'a çevrilmez. PTR+4 gibi otomatik policy sonuçları
        # kayıt/dashboard üzerinden izlenir.

        # Yalnız gerçek kullanıcı kararı gerektiren pending istekler popup üretir.
        row = db.execute(
            """
            SELECT id,created,body
            FROM sentinel_requests
            WHERE status='pending'
              AND created>?
            ORDER BY created
            LIMIT 1
            """,
            (time.time() - 120,)
        ).fetchone()

        if not row:
            return

        ident, created, body = row

        try:
            req = json.loads(body)
        except (TypeError, ValueError, json.JSONDecodeError):
            db.execute(
                """
                UPDATE sentinel_requests
                SET status='invalid'
                WHERE id=?
                  AND status='pending'
                """,
                (ident,)
            )
            db.commit()
            return

        kind = req.get('kind', 'review')

        if kind == 'approval':
            # Yetki yukseltme / supheli islem onayi. Kullaniciya islemin
            # kendisine ait olup olmadigi sorulur.
            pid = req.get('pid', '?')
            cmd = req.get('cmd', '?')
            uid = req.get('uid', '?')
            rule_name = req.get('rule_name') or req.get('rule_id') or '?'
            severity = req.get('severity', '?')
            summary = req.get('summary') or ''
            text = (
                "YETKİ YÜKSELTME / ŞÜPHELİ İŞLEM TESPİTİ\n\n"
                f"Kural: {rule_name}\n"
                f"Önem: {severity}\n"
                f"PID: {pid}\n"
                f"Komut: {cmd}\n"
                f"UID: {uid}\n"
            )
            if summary:
                text += f"\nAçıklama: {summary}\n"
            text += (
                "\nBu işlem sizin tarafınızdan mı başlatıldı?\n\n"
                "Evet derseniz işlem meşru kabul edilir.\n"
                "Hayır derseniz ilgili PID (ve doğrulanmış alt süreçleri) "
                "sonlandırılır."
            )
            args = [
                'zenity',
                '--no-markup',
                '--width=700',
                '--timeout=110',
                '--question',
                '--title=Satsuma Güvenlik Uyarısı',
                '--ok-label=Evet, bana ait',
                '--cancel-label=Hayır, bana ait değil',
                '--text=' + text
            ]
        else:
            subnet = req.get('subnet', '-')
            ips = req.get('ips', [])

            if not isinstance(ips, list):
                ips = []

            total = req.get('total', len(ips))
            delta = req.get('delta', 0)

            text = (
                "Bağlantı / güvenlik değerlendirmesi\n\n"
                f"Alt ağ: {subnet}\n"
                f"Bağlı IP sayısı: {total}\n"
            )

            if ips:
                text += "\nIP adresleri:\n"
                text += '\n'.join(str(ip) for ip in ips[:100])

            reason = req.get('reason')
            if reason:
                text += f"\n\nNeden: {reason}"

            if kind == 'block':
                text += (
                    f"\n\nŞüpheli havuz değişimi: +{delta}"
                    "\n\nBu işlem kullanıcı onayı gerektiriyor."
                )
            else:
                text += "\n\nBu olay kullanıcı değerlendirmesi bekliyor."

            args = [
                'zenity',
                '--no-markup',
                '--width=700',
                '--timeout=110',
                '--question',
                '--title=Satsuma Core — Kullanıcı kararı',
                '--text=' + text
            ]

        try:
            self.output = open('/var/lib/satsuma-core/sentinel-ui-'+uuid.uuid4().hex+'.log','x+b')

            self.process = subprocess.Popen(
                args,
                stdout=self.output,
                stderr=subprocess.DEVNULL
            )

            self.started = time.monotonic()
            self.active = ('request', ident, kind)

        except (OSError, subprocess.SubprocessError):
            self.process = None
            self.output = None
            self.active = None
            return
