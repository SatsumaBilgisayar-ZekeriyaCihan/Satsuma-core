import unittest,json,sqlite3,os,time
from pathlib import Path
from unittest.mock import patch
from support import EvidenceDirectory
from network_fixture import table_json
from satsuma.store import Store
from satsuma.host_store import HostStore
from satsuma.worker_audit_bridge import WorkerAuditBridge
from satsuma.response import ResponseWorker
from satsuma.network_control import validate_layout
from satsuma.auto_network import respond
from satsuma.teams.base import BaseTeamLead
from satsuma.correlation_manager import CorrelationManager
from satsuma.pipeline import Pipeline
from satsuma.reader import Reader
from satsuma.config import validate
from installer import admin_auth,integrity

class ReleaseTests(unittest.TestCase):
    def test_response_defaults_are_full_protection_and_use_managed_table(self):
        cfg = validate({})
        self.assertTrue(cfg['response_enabled'])
        self.assertTrue(cfg['destructive_response_enabled'])
        self.assertEqual(cfg['destructive_allowed_actions'], ['network_isolate', 'process_kill', 'file_quarantine', 'user_disable'])
        self.assertEqual(cfg['nft_table'], 'satsuma_core')
        self.assertTrue(cfg['sudo_autoblock_enabled'])

    def test_admin_password_correct_wrong(self):
        salt='01'*32;record={'salt':salt,'digest':admin_auth.digest('example-test-password',salt)}
        self.assertTrue(admin_auth.valid('example-test-password',record))
        self.assertFalse(admin_auth.valid('incorrect',record))
    def test_installed_inventory_detects_tamper(self):
        with EvidenceDirectory() as td:
            r=Path(td)/'code';r.mkdir();p=r/'a.py';p.write_text('x=1')
            m=Path(td)/'hashes.json';integrity.build(r,m)
            self.assertEqual(integrity.verify(r,m,False),2)
            p.write_text('x=2')
            with self.assertRaises(RuntimeError):integrity.verify(r,m,False)
    def test_audit_failed_ingest_retries(self):
        with EvidenceDirectory() as td:
            h=HostStore(Path(td)/'host',test=True);h.add('audit',{'timestamp':time.time(),'syscall':'59','pid':'123'})
            s=Store(Path(td)/'core',test=True);b=WorkerAuditBridge(s,{'audit_host_db_path':str(h.root/'host.db')})
            class Broken:
                def ingest_audit(self,e):raise RuntimeError('injected failure')
            self.assertFalse(b.tick(Broken())['ok']);self.assertEqual(s.get(b.cursor_key),0)
            class Good:
                def ingest_audit(self,e):pass
            self.assertTrue(b.tick(Good())['ok']);self.assertGreater(s.get(b.cursor_key),0)
            h.close();s.close()
    def test_eve_existing_lines_read_and_failed_line_retried(self):
        with EvidenceDirectory() as td:
            s=Store(Path(td)/'core',test=True);p=Path(td)/'eve';p.write_text('{"event_type":"dns"}\n')
            class P:
                errors=0
                def ingest(self,r):raise RuntimeError('disk unavailable')
            reader=Reader(p,s,P(),opener=lambda p,u:open(p,'rb'))
            with self.assertRaises(RuntimeError):reader.poll()
            self.assertEqual(s.get('checkpoint')['offset'],0)
            events=[];reader.pipeline.ingest=lambda r:events.append(r);reader.poll()
            self.assertEqual(len(events),1);reader.close();s.close()
    def test_team_and_manager_health_reflect_worker_failure(self):
        with EvidenceDirectory() as td:
            s=Store(td,test=True)
            class W:
                name='broken'
                def __init__(self,*a):pass
                def tick(self,**k):return {'ok':False}
            class T(BaseTeamLead):workers=[W];rules=[]
            team=T(s);self.assertFalse(team.tick()['ok'])
            m=CorrelationManager(s);m.register_team(team);self.assertFalse(m.tick()['ok']);s.close()
    def test_window_over_2000_has_no_fixed_cutoff(self):
        with EvidenceDirectory() as td:
            s=Store(td,test=True);p=Pipeline(s,validate({}),replay=True)
            for i in range(2001):p.ingest_host({'action':'file_access','timestamp':time.time(),'path':'/home/test'})
            self.assertEqual(len(BaseTeamLead(s)._read_normalized()),2001);s.close()
    def test_nft_missing_drop_rule_denied(self):
        d=json.loads(table_json());d['nftables']=[x for x in d['nftables'] if not ('rule'in x and x['rule']['chain']=='output')]
        self.assertFalse(validate_layout(d))
    def test_ipv6_readback_and_allowlist_pause(self):
        with EvidenceDirectory() as td:
            s=Store(td,test=True);calls=[]
            def runner(cmd):calls.append(cmd);return {'returncode':0,'stdout':table_json() if '-j'in cmd else ''}
            cfg={**validate({}),'response_enabled':True,'nft_table':'satsuma_core'}
            w=ResponseWorker(s,cfg,runner=runner)
            self.assertEqual(w.block_ip('2606:4700:4700::1111','test',manual=True)['status'],'set_membership_confirmed')
            self.assertTrue(any('blocked_ips_v6'in x and 'add'in x for x in calls))
            s.set('operator_allow_ips',['8.8.8.8']);calls.clear()
            self.assertEqual(w.block_ip('8.8.8.8','test')['status'],'operator_allowlisted');self.assertEqual(calls,[])
            s.close()
    def test_auto_policy_denies_weak_signal_and_rejects_old(self):
        with EvidenceDirectory() as td:
            calls=[]
            s=Store(td,test=True);cfg={**validate({}),'response_enabled':True,'destructive_response_enabled':True,'destructive_allowed_actions':['network_isolate'],'nft_table':'satsuma_core'}
            w=ResponseWorker(s,cfg,runner=lambda cmd:(calls.append(cmd) or {'returncode':0,'stdout':table_json() if '-j'in cmd else ''}))
            f={'classification':'likely','timestamp':time.time()}
            self.assertEqual(respond(w,f,'8.8.8.8','test')['status'],'set_membership_confirmed');self.assertEqual(f['classification'],'likely')
            calls.clear()
            self.assertEqual(respond(w,{**f,'timestamp':1},'8.8.8.8','test')['status'],'historical_review_only')
            self.assertEqual(respond(w,{**f,'classification':'indicator'},'8.8.8.8','test')['status'],'policy_denied');s.close()

    def test_auto_policy_requires_confirmed_multi_source_admin_authorization(self):
        with EvidenceDirectory() as td:
            calls=[]
            s=Store(td,test=True);cfg={**validate({}),'response_enabled':True,'destructive_response_enabled':True,'destructive_allowed_actions':['network_isolate'],'nft_table':'satsuma_core'}
            w=ResponseWorker(s,cfg,runner=lambda cmd:(calls.append(cmd) or {'returncode':0,'stdout':table_json() if '-j'in cmd else ''}))
            finding={'classification':'confirmed','timestamp':time.time(),'sources':['audit','suricata']}
            def incoming(worker,ip,*args):
                calls.append(['incoming_original_only',ip])
                return {'status':'set_membership_confirmed','drop_rule_linked':True,'scope':'incoming_original_only'}
            with patch('satsuma.incoming_response.block',side_effect=incoming):
                result=respond(w,finding,'8.8.8.8','test',context={'admin_session_valid':True,'multi_source_verified':True})
            self.assertEqual(result['status'],'set_membership_confirmed')
            self.assertTrue(result['drop_rule_linked']);self.assertTrue(calls)
            s.close()
    def test_brain_failure_preserves_cursor(self):
        import run_satsuma_teams as brain
        with EvidenceDirectory() as td:
            s=Store(td,test=True);p=Pipeline(s,validate({}),replay=True);p.ingest_host({'action':'execve','timestamp':time.time()})
            class Bad:
                def match(self,e):raise RuntimeError('injected')
            _,report=brain._run_smart_rules(s,Bad(),0)
            self.assertEqual(report['event_errors'],1);self.assertEqual(s.get(brain.SMART_CURSOR_KEY),0);s.close()
if __name__=='__main__':unittest.main()
