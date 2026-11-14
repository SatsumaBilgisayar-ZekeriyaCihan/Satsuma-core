"""Process freshness and network target separation, without signaling real processes."""
import sqlite3
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from satsuma.auto_process import respond,event_time_evidence
from satsuma.auto_action import AutoActionEngine

class Store:
    def __init__(self):self.data={};self.actions=[];self.db=sqlite3.connect(':memory:')
    def get(self,k,d=None):return self.data.get(k,d)
    def set(self,k,v):self.data[k]=v
    def add(self,k,v):self.actions.append((k,v))

class DecisionTests(unittest.TestCase):
    def finding(self,stamp,ordinary=False):
        return {'finding_id':'fixture','rule_id':'SATSUMA-DISC-002' if ordinary else 'fixture-confirmed',
                'classification':'indicator' if ordinary else 'confirmed','severity':'low' if ordinary else 'high',
                'event':{'timestamp':stamp,'pid':424242,'source':'sys_proc','exe':'/fixture'}}
    def test_old_discovery_is_report_only_with_original_time_and_no_signal(self):
        store=Store();response=Mock();stamp=time.time()-1000
        with patch('satsuma.auto_process.authorize_destructive',return_value=SimpleNamespace(reasons=['activity_indicator_reports_only'])):
            result=respond(store,{'auto_action_process_enabled':True},self.finding(stamp,True),response)
        self.assertEqual(result['status'],'report_only')
        self.assertEqual(result['event_time']['event_timestamp'],stamp)
        self.assertEqual(result['event_time']['state'],'EXPIRED')
        self.assertIn('historical_or_future_event',result['reasons'])
        self.assertFalse(result['signal_sent']);response.terminate_process.assert_not_called()
    def test_eligible_fresh_process_decision_does_not_require_network_target(self):
        store=Store();response=Mock();response.terminate_process.return_value={'status':'terminated','signal_sent':True,'exit_verified':True}
        with patch('satsuma.auto_process.authorize_destructive',return_value=SimpleNamespace(reasons=[])):
            result=respond(store,{'auto_action_process_enabled':True},self.finding(time.time()),response)
        response.terminate_process.assert_called_once()
        self.assertEqual(result['status'],'terminated')
        self.assertEqual(result['event_time']['state'],'FRESH')
    def test_stale_or_future_confirmed_event_still_cannot_terminate(self):
        for delta in (-1000,1000):
            response=Mock()
            with patch('satsuma.auto_process.authorize_destructive',return_value=SimpleNamespace(reasons=[])):
                result=respond(Store(),{'auto_action_process_enabled':True},self.finding(time.time()+delta),response)
            self.assertEqual(result['status'],'policy_denied');response.terminate_process.assert_not_called()
    def test_ambiguous_or_nonfinite_time_fails_closed(self):
        for value in (True,None,float('nan'),float('inf'),'2026-11-03T03:00:00'):
            self.assertEqual(event_time_evidence({'timestamp':value},time.time())['state'],'INVALID')
        self.assertEqual(event_time_evidence({'timestamp':'2026-11-03T03:00:00+03:00'},1793664000)['state'],'FRESH')
    def test_screen_outcome_separates_process_decision_from_network_target(self):
        from satsuma.presentation import action_outcome,REASONS
        text=action_outcome({'status':'evidence_recorded','target':None,
                             'process_response':{'status':'report_only','signal_sent':False}})
        self.assertIn('yalnızca bildirildi',text)
        self.assertIn('Ağ hedefi: belirlenmedi',text)
        self.assertIn('ileri tarihli',REASONS['historical_or_future_event'])
    def test_top_level_network_message_is_not_a_process_denial(self):
        store=Store();engine=AutoActionEngine(store,response=Mock())
        try:
            with patch('satsuma.auto_process.respond',return_value={'status':'report_only','signal_sent':False}):
                result=engine.process(self.finding(time.time(),True))
            self.assertFalse(result['network_evaluation']['required_for_process_termination'])
            self.assertEqual(result['network_evaluation']['status'],'NO_NETWORK_TARGET')
            self.assertNotIn('Hedefli ağ kanıtı yok',result['reason'])
        finally:store.db.close()
