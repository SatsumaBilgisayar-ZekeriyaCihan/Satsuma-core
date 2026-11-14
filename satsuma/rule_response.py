"""Per-rule additive evidence requirements; legacy single-signal defaults stay.

Only a root/operator policy may require more evidence. Findings/AI booleans
cannot relax that policy or manufacture an authoritative evidence verdict.
"""
import ipaddress
import hashlib
import json
import math
import time
from datetime import datetime
from pathlib import Path
from .process_identity import evidence_pid,evidence_starttime,evidence_exe

POLICY_KEY='rule_response_requirements'
CATALOG_PATH=Path(__file__).resolve().parents[1]/'schemas/rule-response-catalog-v1.json'
SOURCE_FAMILIES={'sys_proc':'process','audit':'audit','memory':'memory',
                 'suricata':'suricata','network':'network'}


def current_requirements(store,config):
    result=dict(config.get(POLICY_KEY) or {})
    saved=store.get(POLICY_KEY,{}) if store is not None else {}
    if not isinstance(saved,dict):raise ValueError('invalid_saved_evidence_policy')
    for rule_id,requirement in saved.items():
        previous=result.get(rule_id,{})
        if not isinstance(requirement,dict) or not isinstance(previous,dict):raise ValueError('invalid_evidence_policy')
        result[rule_id]=requirement if requirement.get('minimum_sources',0)>=previous.get('minimum_sources',0) else previous
    return result


def requirement_for(finding,config,store=None):
    policies=current_requirements(store,config)
    ids={str(finding.get('rule_id') or ''),*(str(v) for v in finding.get('matched_rules',[]) or [])}
    values=[dict(policies[i],rule_id=i) for i in ids if i in policies and isinstance(policies[i],dict)]
    if any(i in policies and not isinstance(policies[i],dict) for i in ids):raise ValueError('invalid_evidence_policy')
    if not values:return None
    for value in values:
        if not isinstance(value,dict) or type(value.get('minimum_sources')) is not int or not 1<=value['minimum_sources']<=3:
            raise ValueError('invalid_evidence_policy')
    return max(values,key=lambda value:value['minimum_sources'])


def _stamp(event):
    value=event.get('timestamp')
    try:
        parsed=float(value) if isinstance(value,(int,float)) else datetime.fromisoformat(str(value).replace('Z','+00:00')).timestamp()
        return parsed if math.isfinite(parsed) else None
    except (ValueError,TypeError):return None


def _identity(event,action,context):
    if action=='process_kill':
        pid,start,exe=evidence_pid(event),evidence_starttime(event),evidence_exe(event)
        if not pid or pid<=1 or not start or start[1]!='jiffies' or not exe:return None
        return ('process',pid,str(start[0]),exe)
    if action=='network_isolate':
        # A DNS lookup or a list of source names is not network attack evidence.
        if event.get('source') not in ('suricata','network'):return None
        try:return ('network',str(ipaddress.ip_address(event['target_ip'])))
        except (KeyError,ValueError,TypeError):return None
    if action=='file_quarantine':
        path=event.get('file_path');sha=event.get('file_sha256')
        if not isinstance(path,str) or not path.startswith('/') or not isinstance(sha,str) or len(sha)!=64:return None
        return ('file',path,sha)
    return None


def evidence_report(store,finding,action,requirement,context=None):
    context=context or {};minimum=requirement['minimum_sources']
    report={'required':minimum,'verified':0,'missing':[], 'record_ids':[],
            'source_families':[], 'scope':'trusted_normalized_records', 'passed':False}
    if store is None:
        report['missing']=['trusted_evidence_store_unavailable'];return report
    expected=_identity(finding.get('event') or {},action,context)
    if expected is None:
        report['missing']=['target_identity_missing'];return report
    if action=='process_kill' and context.get('pid') is not None and context['pid']!=expected[1]:
        report['missing']=['process_target_mismatch'];return report
    if requirement.get('detection_sha256'):
        bound=(finding.get('matched_rule_hashes') or {}).get(requirement.get('rule_id'))
        if finding.get('rule_id')==requirement.get('rule_id'):bound=finding.get('rule_content_hash')
        if bound!=requirement['detection_sha256']:
            report['missing']=['rule_content_binding_mismatch'];return report
    if action=='network_isolate' and context.get('target_ip')!=expected[1]:
        report['missing']=['network_target_mismatch'];return report
    # Only references are taken from the finding. The event bodies are reread
    # from the privileged ingestion store and reconstructed by the real mapper.
    signals=[finding,*(finding.get('corroborating_findings') or [])]
    ids=set()
    for signal in signals:
        event=signal.get('event') if isinstance(signal,dict) else None
        rid=event.get('id') if isinstance(event,dict) else None
        if (type(rid) is int and rid>0) or (isinstance(rid,str) and rid.startswith('flow-')):ids.add(rid)
    from run_satsuma_teams import _smart_event
    from . import flow as flow_module
    families=set();raw_ids=set();fingerprints=set()
    for rid in sorted(ids,key=str)[:64]:
        try:
            if isinstance(rid,str):
                # 2.2.32: stream events live in the rule engine's own memory
                # (received on the root:satsuma-core socket), never in the database.
                # 2.2.32: akış olayları veritabanında değil, kural motorunun belleğindedir.
                body=flow_module.ACTIVE.get(rid) if flow_module.ACTIVE is not None else None
                if not body or not isinstance(body.get('raw'),dict) or not isinstance(body.get('event'),dict):continue
                raw_id=rid;raw=body['raw']
                if raw_id in raw_ids:continue
                event=_smart_event(rid,json.dumps({'raw_id':rid,'event':body['event']},default=str))
            else:
                row=store.db.execute("SELECT body FROM records WHERE id=? AND kind='normalized'",(rid,)).fetchone()
                if not row:continue
                outer=json.loads(row[0]);raw_id=outer.get('raw_id')
                if type(raw_id) is not int or raw_id in raw_ids:continue
                original=store.db.execute("SELECT body FROM records WHERE id=? AND kind='events'",(raw_id,)).fetchone()
                if not original:continue
                raw=json.loads(original[0])
                event=_smart_event(rid,row[0])
            raw_source=raw.get('source') or ('suricata' if raw.get('event_type') else None)
            if SOURCE_FAMILIES.get(raw_source)!=SOURCE_FAMILIES.get(event.get('source')):continue
            # Relabeling/re-storing one event never creates independent proof.
            material={k:v for k,v in raw.items() if k not in ('source','collector_id','sensor_name','source_name')}
            fingerprint=hashlib.sha256(json.dumps(material,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            if fingerprint in fingerprints:continue
        except (ValueError,TypeError,KeyError):continue
        stamp=_stamp(event)
        if stamp is None or not 0<=time.time()-stamp<=min(60,requirement.get('freshness_seconds',60)):continue
        if _identity(event,action,context)!=expected:continue
        family=SOURCE_FAMILIES.get(event.get('source'))
        if family in set(requirement.get('ignore_families') or ()):continue
        if family and family not in families:
            families.add(family);raw_ids.add(raw_id);fingerprints.add(fingerprint);report['record_ids'].append(rid)
    report['verified']=len(families);report['source_families']=sorted(families)
    required_families={SOURCE_FAMILIES.get(source) for source in requirement.get('required_sources',[])}
    source_requirements_ok=None not in required_families and required_families <= families
    report['passed']=len(families)>=minimum and source_requirements_ok
    if not source_requirements_ok:report['missing'].append('required_sensor_family_not_verified')
    if not report['passed']:report['missing'].append('insufficient_independent_fresh_same_target_evidence')
    if hasattr(store, 'set'):
        latest=store.get('rule_response_verdicts',{}) or {}
        latest[str(finding.get('rule_id') or '')]={**report,'checked_at':time.time(),'policy_decision':'evidence_passed' if report['passed'] else 'denied'}
        store.set('rule_response_verdicts',latest)
    return report


def set_requirement(store,rule_id,minimum_sources,actor,*,expected_hash,required_sources=None):
    catalog=json.loads(CATALOG_PATH.read_text())['rules']
    plan=next((r for r in catalog if r['rule_id']==rule_id),None)
    if not plan or plan['detection_sha256']!=expected_hash:raise ValueError('rule_catalog_binding_mismatch')
    if type(minimum_sources) is not int or not 1<=minimum_sources<=3:raise ValueError('minimum_sources_1_to_3_required')
    required_sources=required_sources or []
    if (not isinstance(required_sources,list) or len(required_sources)>minimum_sources
            or any(source not in SOURCE_FAMILIES for source in required_sources)
            or len(set(required_sources))!=len(required_sources)):
        raise ValueError('invalid_required_sources')
    policies=store.get(POLICY_KEY,{}) or {}
    before=policies.get(rule_id)
    policies[rule_id]={'minimum_sources':minimum_sources,'required_sources':required_sources,'freshness_seconds':60,
                       'detection_sha256':expected_hash,'operator_uid':actor,'updated_at':time.time()}
    store.set(POLICY_KEY,policies)
    store.add('protection_changes',{'method':'rule_response_set_requirement','rule_id':rule_id,
               'operator_uid':actor,'previous':before,'new':policies[rule_id], 'timestamp':time.time()})
    return {'ok':True,'rule_id':rule_id,'requirement':policies[rule_id],'intervention_executed':False}
