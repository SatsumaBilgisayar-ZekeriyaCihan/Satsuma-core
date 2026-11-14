"""Create a per-rule review inventory without editing rules or active policy."""
import csv
import io
import json
from pathlib import Path
from satsuma.smart_rules import SmartRuleEngine
from satsuma.enforcement import eligible, automatic_allowed
from satsuma.ai_rule_package import digest

ROOT=Path(__file__).resolve().parents[1]


def build():
    engine=SmartRuleEngine(ROOT/'rules')
    if engine.load_errors:raise RuntimeError(engine.load_errors)
    inventory=[]
    for compiled in engine.rules:
        rule={k:v for k,v in compiled.items() if not k.startswith('_')}
        source=rule['base_match'].get('source')
        actor=source in ('sys_proc','audit','memory')
        comparison=source=='memory' and rule['base_match'].get('action')=='executable_code_mismatch'
        gaps=['Live Fedora identity/evidence availability has not been measured.']
        if source=='audit':gaps.append('Audit event must contain the original process starttime; PID/exe alone cannot satisfy multi-source identity.')
        if source=='memory':gaps.append('ACCESS_DENIED/partial/JIT/memfd observations are not clean results or automatic stop authority.')
        if not actor:gaps.append('Inventory telemetry does not identify an executable process target; no automatic stop proposed.')
        requirements=['operator-controlled action policy','fresh original target identity',
                      'protected process/target exemptions','pause/replay guards','pre-action identity revalidation']
        if comparison:requirements+=['live byte-difference revalidation','debugger/authorized patch checks']
        inventory.append({'schema_version':1,'rule_id':rule['id'],'name':rule['name'],
            'detection_sha256':digest(rule),'source':source,'match':rule['base_match'],
            'current_actions':rule['actions'],'current_automatic_eligibility':{
                'enforcement_eligible':eligible(compiled),'automatic_allowed':automatic_allowed(compiled),
                'conditional_on_existing_policy':True,'requires_real_target_checks':True},
            'logging':{'enabled':True,'required_actions':['record','evidence'],'existing_actions_preserved':True},
            'proposed_response':{'requested_action':'process_kill_evaluation' if actor else 'operator_triage_only',
                'additional_network_or_file_action':'not proposed without independently verified target evidence',
                'minimum_sources':1 if comparison else 2,'freshness_seconds':60,
                'identity':'same PID + kernel starttime jiffies + executable' if actor else 'no verified process target',
                'requirements':requirements,'required_source_families':['process','audit','memory'] if actor else [],
                'selection_basis':'Existing actor telemetry and identity-verification code path; byte-difference revalidation is a distinct supported check.' if comparison else
                    'Detection match does not by itself prove attack intent; propose independent same-target evidence, not severity/name-derived execution.',
                'applied':False,'review_state':'per_rule_operator_review_required'},
            'false_positive_risks':rule.get('false_positives') or ['Legitimate administration/development can satisfy a data matcher; investigate context.'],
            'capability_gaps':gaps,
            'rollback':{'process':'Termination is irreversible; restart/recovery must be planned before authorization.',
                        'network':'Existing authenticated unblock workflow; not executed here.',
                        'file':'Existing quarantine rollback workflow; protected OS paths remain exempt.',
                        'policy':'Restore only this rule’s prior requirement with authenticated operator approval.'}})
    if not inventory or len({r['rule_id'] for r in inventory})!=len(inventory):raise RuntimeError('empty or duplicate baseline rules')
    return {'catalog_version':1,'scope':f'{len(inventory)} baseline rules; proposals only, no policy activation', 'rules':inventory}


def main():
    catalog=build()
    (ROOT/'schemas/rule-response-catalog-v1.json').write_text(json.dumps(catalog,ensure_ascii=False,indent=2)+'\n')
    path=ROOT/'docs/RULE-RESPONSE-INVENTORY-2026.csv'
    with path.open('w',newline='') as stream:
        names=['rule_id','name','source','match','current_actions','current_automatic_eligibility','proposed_response','false_positive_risks','capability_gaps','rollback','detection_sha256']
        writer=csv.DictWriter(stream,fieldnames=names);writer.writeheader()
        for item in catalog['rules']:
            writer.writerow({k:json.dumps(item[k],ensure_ascii=False) if isinstance(item[k],(dict,list)) else item[k] for k in names})
    print(f"{len(catalog['rules'])} rules inventoried; 0 baseline policies changed")

if __name__=='__main__':main()
