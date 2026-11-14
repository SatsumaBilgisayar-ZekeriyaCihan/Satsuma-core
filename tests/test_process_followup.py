"""Follow-up must survive restarts without inventing guilt or termination.

Takip servis yeniden başlamasında korunmalı; suçluluk/sonlandırma uydurmamalı.
"""
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace
import tempfile
import time
import unittest
from unittest.mock import patch,Mock
from satsuma.store import Store
from satsuma import process_followup as followup
PROCESS_READER=followup._process


class FollowupTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.directory=Path(self.tmp.name)
        self.store=Store(self.directory/'data',test=True)
        self.proc=self.directory/'proc';self.proc.mkdir();(self.proc/'uptime').write_text('1 1')
        self.root={'pid':501,'starttime':50,'exe':'/fixture/app','uid':1000,'device':1,'inode':2,
                   'ppid':1,'state':'RUNNING'}
        self.patches=[patch.object(followup,'ROOT',self.proc),patch.object(followup,'_boot',return_value='boot-a'),
                      patch.object(followup,'_boot_time',return_value=0),patch.object(followup,'_process',return_value=self.root)]
        for p in self.patches:p.start()
        self.finding={'finding_id':'ram-case','rule_id':'SATSUMA-RAM-106','classification':'suspicious',
                      'event':{'pid':501,'starttime':50,'exe':'/fixture/app','timestamp':time.time()}}

    def tearDown(self):
        self.store.close()
        for p in reversed(self.patches):p.stop()
        self.tmp.cleanup()

    def register(self):
        self.store.add('events',{'event':{'category':'finding'},'metadata':{'finding':self.finding}})

    def observe(self,rows,boot='boot-a',complete=True,probe=None):
        def missing(pid):raise FileNotFoundError(pid)
        followup.tick(self.store,observe=lambda:{'rows':{r['pid']:r for r in rows},'boot_id':boot,
                                                'complete':complete,'errors':int(not complete)},
                      probe=probe or missing)
        return followup.read(self.store.db,'ram-case',details=True)

    def test_pending_decision_is_visible_immediately_and_registration_is_idempotent(self):
        self.register();self.register()
        case=followup.read(self.store.db,'ram-case',details=True)
        self.assertEqual(case['decision']['status'],'NOT_EVALUATED')
        self.assertEqual(case['timeline_count'],1)

    def test_running_then_missing_is_not_claimed_as_satsuma_termination(self):
        self.register();self.assertEqual(self.observe([self.root])['state'],'RUNNING')
        case=self.observe([])
        self.assertEqual(case['state'],'GONE')
        self.assertIn('nedeni bilinmiyor',case['summary'])
        self.assertFalse(case['decision']['exit_verified'])

    def test_pid_reuse_is_not_the_original_process(self):
        self.register();case=self.observe([{**self.root,'starttime':9999}])
        self.assertEqual(case['state'],'PID_REUSED')
        self.assertEqual(case['members'][0]['starttime'],50)

    def test_permission_error_and_incomplete_enumeration_are_unknown_not_gone(self):
        self.register()
        def denied(pid):raise PermissionError(pid)
        self.assertEqual(self.observe([],complete=False,probe=denied)['state'],'UNKNOWN')

    def test_children_and_new_same_executable_are_linked_without_new_verdict(self):
        self.register()
        child={**self.root,'pid':502,'ppid':501,'starttime':150,'exe':'/fixture/child','inode':3}
        restart={**self.root,'pid':503,'ppid':1,'starttime':5000}
        old_peer={**self.root,'pid':504,'starttime':60}
        another_uid={**restart,'pid':505,'uid':1001}
        case=self.observe([self.root,child,restart,old_peer,another_uid])
        relations={r['pid']:r['relation'] for r in case['members']}
        self.assertEqual(relations[502],'CHILD_OBSERVED')
        self.assertEqual(relations[503],'SAME_EXECUTABLE_CANDIDATE')
        self.assertNotIn(504,relations);self.assertNotIn(505,relations)
        self.assertEqual(case['decision']['status'],'NOT_EVALUATED')

    def test_reused_parent_does_not_link_unrelated_child(self):
        self.register()
        parent={**self.root,'starttime':9000,'exe':'/fixture/different','inode':99}
        child={**parent,'pid':502,'ppid':501,'starttime':9100}
        case=self.observe([parent,child])
        self.assertEqual(len(case['members']),1)

    def test_boot_change_closes_watch_without_matching_new_process(self):
        self.register();case=self.observe([self.root],boot='boot-b')
        self.assertEqual(case['state'],'BOOT_CHANGED');self.assertTrue(case['closed'])

    def test_decision_and_timeline_survive_store_reopen_and_reader_is_read_only(self):
        self.register()
        followup.decision(self.store,self.finding,{'status':'policy_denied','signal_sent':False,
                          'reasons':['ram_signature_revalidation_failed']})
        self.store.close();self.store=Store(self.directory/'data',test=True)
        db=sqlite3.connect('file:'+str(self.store.path)+'?mode=ro',uri=True);db.execute('PRAGMA query_only=ON')
        try:
            case=followup.read(db,'ram-case',details=True)
            self.assertEqual(case['decision']['reasons'],['ram_signature_revalidation_failed'])
            self.assertEqual(case['timeline'][-1]['kind'],'RESPONSE_DECISION')
            with self.assertRaises(sqlite3.OperationalError):db.execute('DELETE FROM process_followup')
        finally:db.close()

    def test_finding_and_followup_rollback_together(self):
        with self.assertRaises(RuntimeError):
            with self.store.atomic():
                self.register();raise RuntimeError('simulate ingest failure')
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM records').fetchone()[0],0)
        self.assertEqual(followup.read(self.store.db,'ram-case')['state'],'NOT_RECORDED')

    def test_missing_identity_and_preboot_evidence_are_never_rebound_to_live_pid(self):
        self.finding['event'].pop('starttime');self.register()
        self.assertEqual(followup.read(self.store.db,'ram-case')['state'],'IDENTITY_INCOMPLETE')

    def test_explicit_other_boot_identity_is_not_attached(self):
        self.finding['event']['boot_id']='boot-before';self.register()
        self.assertEqual(followup.read(self.store.db,'ram-case')['state'],'IDENTITY_INCOMPLETE')

    def test_process_reader_detects_exec_race_and_reads_real_uid(self):
        directory=self.proc/'501';directory.mkdir()
        (directory/'stat').write_text('501 (fixture) '+' '.join(['S','1']+['0']*17+['50']))
        (directory/'status').write_text('Uid:\t1000\t0\t0\t0\n')
        exe=self.directory/'app';exe.write_text('fixture')
        (directory/'exe').symlink_to(exe)
        self.assertEqual(PROCESS_READER(501)['uid'],1000)
        with patch.object(followup.os,'readlink',side_effect=[str(exe),'/changed/exe']):
            with self.assertRaisesRegex(ValueError,'identity changed'):PROCESS_READER(501)

    def test_duplicate_without_recorded_outcome_is_explicit_and_never_retried(self):
        self.register();followup.duplicate(self.store,self.finding)
        case=followup.read(self.store.db,'ram-case')
        self.assertEqual(case['decision']['status'],'duplicate_without_result')
        self.assertIsNone(case['decision']['signal_sent'])

    def test_lightweight_sqlite_adapter_is_not_migrated_by_response(self):
        db=sqlite3.connect(':memory:')
        try:
            adapter=SimpleNamespace(db=db)
            followup.register(adapter,self.finding)
            followup.decision(adapter,self.finding,{'status':'policy_denied'})
            self.assertEqual(db.execute('SELECT count(*) FROM sqlite_master').fetchone()[0],0)
        finally:db.close()

    def test_confirmed_response_is_distinct_from_unattributed_exit(self):
        self.register()
        followup.decision(self.store,self.finding,{'status':'terminated','signal_sent':True,'exit_verified':True})
        self.assertIn('Satsuma sinyal gönderdi',self.observe([])['decision_summary'])

    def test_decision_arriving_during_snapshot_is_not_overwritten(self):
        self.register()
        def observe():
            followup.decision(self.store,self.finding,{'status':'terminated','signal_sent':True,'exit_verified':True})
            return {'rows':{501:self.root},'boot_id':'boot-a','complete':True}
        followup.tick(self.store,observe=observe)
        self.assertEqual(followup.read(self.store.db,'ram-case')['decision']['status'],'terminated')

    def test_old_record_signature_is_readable_without_inventing_lifecycle(self):
        from satsuma import dashboard_api as api
        self.finding['event']['metadata']={'extensions':{'host.ram_v2':{'signature':'Historical.Fixture'}}}
        self.register()
        # Model a record predating this feature, not a production cleanup.
        self.store.db.execute('DELETE FROM process_followup');self.store.db.commit()
        with patch.object(api,'DB_PATH',str(self.store.path)),patch.object(api,'HOST_DB_PATH',str(self.directory/'absent.db')):
            detail=api.m_finding('ram-case')
        self.assertEqual(detail['process_followup']['state'],'NOT_RECORDED')
        self.assertEqual(detail['process_followup']['evidence_summary']['signature'],'Historical.Fixture')

    def test_reader_exposes_case_link_and_related_members_without_control_writes(self):
        from satsuma import dashboard_api as api
        self.register();self.observe([self.root,{**self.root,'pid':502,'ppid':501,'starttime':150}])
        host_path=self.directory/'host.db'
        host=sqlite3.connect(host_path);host.execute('CREATE TABLE findings(finding_id TEXT,last_seen REAL,body TEXT)');host.commit();host.close()
        with patch.object(api,'DB_PATH',str(self.store.path)),patch.object(api,'HOST_DB_PATH',str(host_path)):
            result=api.m_memory_defense()
            row=next(r for r in result['items'] if r['finding_id']=='ram-case')
            self.assertEqual(row['related_processes'],1)
            self.assertIn('Müdahale kararı',row['process_decision'])
            detail=api.m_finding('ram-case',record_key=row['record_key'])
            self.assertEqual(len(detail['process_followup']['members']),2)
            self.assertGreater(detail['process_followup']['timeline_count'],1)

    def test_retired_ram_finding_denied_before_old_revalidation(self):
        """Historical RAM-ClamAV findings remain auditable, never executable."""
        from satsuma import auto_process
        self.register()
        self.finding['event']['action'] = 'ram_signature_match_v2'
        response = Mock()
        with patch.object(auto_process, 'verify_process_identity',
                          side_effect=AssertionError('retired identity check invoked')):
            result = auto_process.respond(self.store, {}, self.finding, response)
        response.terminate_process.assert_not_called()
        self.assertEqual(result['status'], 'policy_denied')
        self.assertFalse(result['signal_sent'])
        self.assertEqual(result['reasons'], ['ram_clamav_retired'])
        case = followup.read(self.store.db, 'ram-case')
        self.assertEqual(case['decision']['status'], 'policy_denied')
        self.assertEqual(case['decision']['reasons'], ['ram_clamav_retired'])
        self.assertEqual(self.store.get('rule_intervention_latest')['SATSUMA-RAM-106']['finding_id'], 'ram-case')
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM records WHERE kind='actions'").fetchone()[0], 1)

    def test_retired_ram_cannot_claim_service_exemption(self):
        """The retired engine cannot re-enter enforcement via named exemptions."""
        from satsuma import auto_process, enforcement
        self.finding['event']['action'] = 'ram_signature_match_v2'
        self.finding['event']['metadata'] = {'extensions': {'host.ram_v2': {'signature': 'Fixture.Only'}}}
        self.register()
        response = Mock()
        with patch.object(enforcement, 'exempt',
                          side_effect=AssertionError('retired path reached exemption')):
            result = auto_process.respond(self.store, {'user_enforcement': True}, self.finding, response)
        response.terminate_process.assert_not_called()
        case = followup.read(self.store.db, 'ram-case')
        self.assertEqual(result['status'], 'policy_denied')
        self.assertEqual(result['reasons'], ['ram_clamav_retired'])
        self.assertEqual(case['evidence_summary']['signature'], 'Fixture.Only')
        self.assertFalse(case['decision']['signal_sent'])


class LiveFollowupTests(unittest.TestCase):
    def test_real_own_child_exit_has_no_fabricated_response(self):
        child=subprocess.Popen(['/bin/sleep','10'])
        try:
            if not (Path('/proc')/str(child.pid)/'stat').is_file():
                self.skipTest('Executor does not expose its child PID namespace through /proc; Fedora CI runs this test')
            with tempfile.TemporaryDirectory() as directory:
                store=Store(directory,test=True)
                try:
                    identity=followup._process(child.pid)
                    finding={'finding_id':'live-own-child','rule_id':'SATSUMA-TEST-TRACK',
                             'classification':'suspicious','event':{**identity,'timestamp':time.time()}}
                    store.add('findings',finding)
                    followup.tick(store)
                    self.assertEqual(followup.read(store.db,'live-own-child')['state'],'RUNNING')
                    child.terminate();child.wait(timeout=3)
                    followup.tick(store)
                    case=followup.read(store.db,'live-own-child')
                    self.assertEqual(case['state'],'GONE')
                    self.assertEqual(case['decision']['status'],'NOT_EVALUATED')
                    self.assertFalse(case['decision']['signal_sent'])
                    if os.environ.get('SATSUMA_FOLLOWUP_EVIDENCE_DIR'):
                        path=Path(os.environ['SATSUMA_FOLLOWUP_EVIDENCE_DIR'])
                        path.mkdir(parents=True,exist_ok=True)
                        (path/'live-process-followup.json').write_text(json.dumps({
                            'target':'only_test_created_child','observed_running':True,
                            'observed_gone_after_test_cleanup_signal':True,
                            'no_fabricated_satsuma_termination':True},indent=2)+'\n')
                finally:store.close()
        finally:
            if child.poll() is None:child.terminate();child.wait(timeout=3)


class FollowupPanelTests(unittest.TestCase):
    def test_selected_ram_record_fetches_linked_details_with_keyword_parameters(self):
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            self.skipTest('Qt is exercised in the Fedora build container')
        from satsuma.dashboard_qt.panels.defense_sections import MemoryDefensePanel
        application=QApplication.instance() or QApplication([])
        calls=[]
        class Backend:
            def call(self,method,**params):
                calls.append((method,params))
                return {'process_followup':{'summary':'Aynı süreç çalışıyor',
                    'decision_summary':'Korunan program: suricata',
                    'evidence_summary':{'exe':'/usr/bin/suricata','signature':'Fixture.Only'},
                    'members':[{'pid':502,'exe':'/fixture/child','relation_label':'Çocuk süreç',
                                'state_label':'Aynı süreç çalışıyor','first_seen':time.time()}]}}
        panel=MemoryDefensePanel(Backend())
        try:
            row={'finding_id':'ram-case','record_key':'["core","events",1]',
                 'rule_id':'SATSUMA-RAM-106','title':'Fixture','pid':501}
            panel._render_data({'items':[row],'data_state':'OK'})
            panel.table.selectRow(0);application.processEvents();panel._show_details()
            self.assertEqual(calls[-1],('finding',{'finding_id':'ram-case','record_key':row['record_key']}))
            self.assertIn('Korunan program: suricata',panel.details.toPlainText())
            self.assertIn('Fixture.Only',panel.details.toPlainText())
            self.assertIn('Çocuk süreç',panel.details.toPlainText())
        finally:panel.close();panel.deleteLater();application.processEvents()
