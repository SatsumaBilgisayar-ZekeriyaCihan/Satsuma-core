"""Run all relevant isolated checks, retaining historical artifact failures.

No live process-termination tests, Fedora services, firewall writes or API
calls are run. All new security tests are included without deselection.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
TEST_FILES='''test_rule_response_evidence test_memory_scope_bounded test_deepseek_secure_workflow
 test_deepseek_transport test_deepseek_operator_socket test_deepseek_qt test_security_desktop_ui test_smart_rules test_response
 test_privd test_memory_worker_status test_memory_status test_memory_access test_ai_package_payload
 test_guard_stream_evidence test_network_response_panel test_incoming_direction_contract
 test_reader_findings_pagination test_reader_sqlite_qt test_reader_channel test_g4_rules_dir
 test_authorization_contract test_candidate19_gui test_candidate19_runtime test_candidate20_1_3
 test_network_single_signal_2016 test_suricata_otx_guard test_network_features test_strict_network
 test_suricata_outcomes test_engine test_chain test_sqlite_closing test_k1_redos test_k4_k6_audit
 test_k5_wrappers test_k7_lowering_protection test_rpm_runtime_payload test_rpm_upgrade_contract
 test_release_script'''.split()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--results',type=Path,default=ROOT.parent/'artifacts')
    args=parser.parse_args();args.results.mkdir(parents=True,exist_ok=True)
    env={**os.environ,'PYTHONPATH':str(ROOT),'QT_QPA_PLATFORM':'offscreen'}
    regression=subprocess.run([sys.executable,'tools/audit_rule_behavior.py'],cwd=ROOT,env=env)
    xml=args.results/'integrated-tests.xml'
    command=[sys.executable,'-m','pytest','-q',*[f'tests/{name}.py' for name in TEST_FILES],f'--junitxml={xml}']
    result=subprocess.run(command,cwd=ROOT,env=env)
    if xml.exists():
        tree=ET.parse(xml).getroot();cases=tree.findall('.//testcase');failures=[];blocked=[]
        for case in cases:
            fail=case.find('failure')
            if fail is None:continue
            node=case.get('classname','')+'::'+case.get('name','')
            if ('test_release_script' in node and 'test_published_digest_matches_the_package_everywhere[2.2.12]' in node
                    and 'FileNotFoundError' in (fail.text or '')):
                blocked.append({'test':node,'status':'BLOCKED — missing historical artifact'})
            else:failures.append(node)
        total_xml=sum(int(suite.get('tests','0')) for suite in tree.findall('testsuite'))
        skipped=sum(case.find('skipped') is not None for case in cases)
        errors=sum(case.find('error') is not None for case in cases)
        summary={'tested_code_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'case_count':len(cases),'passed_cases':len(cases)-len(failures)-len(blocked)-skipped-errors,
            'failed_cases':len(failures)+len(blocked),'unexpected_failures':failures,'errors':errors,'skipped_cases':skipped,
            'passed_subtests':max(0,total_xml-len(cases)),'blocked':blocked,
            'pytest_exit_code':result.returncode,'regression_exit_code':regression.returncode,
            'new_security_tests_excluded':False,'fedora_validation':False,'live_api_called':False}
        (args.results/'integrated-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2)+'\n')
        print(json.dumps(summary,ensure_ascii=False))
    return result.returncode or regression.returncode

if __name__=='__main__':raise SystemExit(main())
