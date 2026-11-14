"""Bulgu zenginleştirme, skorlama ve normalize bulgu üretimi."""
from __future__ import annotations
from typing import Any, Iterable
from . import ENGINE_NAME,__version__
from .errors import Issue
from .mitre import enrich as enrich_mitre
from .rule_model import Rule
from .schema_store import validate_instance
from .util import as_list,epoch_to_iso,iso,missing_sentinel,parse_timestamp,sha256_hex,truncate
FINDING_SCHEMA="findings/v1"; SEVERITY_ORDER=["info","low","medium","high","critical"]
def severity_rank(severity):
    try:return SEVERITY_ORDER.index(severity)
    except ValueError:return 0
def host_of(event):
    value=event.get("event",{}).get("host")
    if isinstance(value,dict):return str(value.get("name") or value.get("ip") or "unknown")
    if value:return str(value)
    metadata=event.get("metadata") or {}
    if isinstance(metadata,dict):
        for key in ("host","hostname","host.name","agent.hostname"):
            if key in metadata:return str(metadata[key])
    for key in ("host","hostname"):
        if key in event:return str(event[key])
    return "unknown"
def event_timestamp(event):
    raw=(event.get("event") or {}).get("timestamp"); raw=raw if raw is not None else event.get("timestamp"); epoch=parse_timestamp(raw)
    if epoch is None:return None,iso()
    return epoch,epoch_to_iso(epoch) or iso()
def event_source(event):
    value=event.get("event",{}).get("source") or event.get("source")
    if isinstance(value,dict):return str(value.get("type") or value.get("collector_id") or value.get("name") or "unknown")
    return str(value or "unknown")
def event_fingerprint(event,index=None):
    event_id=event.get("id") or (event.get("event") or {}).get("event_id")
    if event_id is not None:return sha256_hex("event",event_id,length=16)
    parts=[event_timestamp(event)[1],host_of(event),(event.get("event") or {}).get("action"),(event.get("event") or {}).get("cmd"),(event.get("event") or {}).get("path")]
    return sha256_hex("event",*parts,index,length=16)
def extract_entity(rule,event):
    from .util import deep_get
    for path in rule.dedup_key_fields:
        value=deep_get(event,path,None)
        if value not in (None,""):return path,truncate(value,200)
    kind=(event.get("event") or {}).get("kind") or (event.get("event") or {}).get("action") or "event"
    return str(kind),event_fingerprint(event)
def build_evidence(rule,event,matched_values,extra=()):
    evidence=[]
    for field,value in matched_values.items():evidence.append({"type":"field","field":field,"value":value if isinstance(value,(str,int,float,bool)) or value is None else truncate(value),"detail":f"Kural koşulunda kullanıldı: {rule.id}"})
    evidence.append({"type":"event","event_fingerprint":event_fingerprint(event),"detail":"Tetikleyen olay"}); evidence.extend(extra); return evidence
def collect_matched_values(rule,event):
    from .util import deep_get
    values={}
    for field in rule.matched_fields():
        value=deep_get(event,field,missing_sentinel())
        if value is missing_sentinel():continue
        values[field]=value if isinstance(value,(str,int,float,bool)) else truncate(value,200)
    return values
def compute_score(rule,event):
    base=rule.base_score; modifiers=[]; total=base
    from .conditions import CompiledLogic
    for index,modifier in enumerate(rule.score_modifiers):
        condition=modifier.get("if"); compiled=condition if isinstance(condition,CompiledLogic) else CompiledLogic.compile(condition,f"scoring[{index}]")
        if compiled.evaluate(event):
            delta=int(modifier.get("delta",0)); total+=delta; modifiers.append({"reason":modifier.get("comment") or f"scoring[{index}] koşulu sağlandı","delta":delta})
    low,high=rule.score_bounds; total=max(low,min(high,total)); return total,{"base":base,"modifiers":modifiers,"total":total}
def enrich_finding(rule,event,event_index=None,extra_evidence=(),ruleset_hash=""):
    epoch,stamp=event_timestamp(event); score,breakdown=compute_score(rule,event); matched=collect_matched_values(rule,event); entity_kind,entity_value=extract_entity(rule,event)
    finding={"schema":FINDING_SCHEMA,"finding_id":"F-"+sha256_hex(rule.id,entity_value,stamp,length=16),"dedup_key":"","event_fingerprint":event_fingerprint(event,event_index),"rule_id":rule.id,"rule_title":rule.title,"title":f"{rule.title} [{host_of(event)}]","description":rule.description,"severity":rule.severity,"classification":rule.classification,"confidence":rule.confidence,"category":rule.category,"tags":rule.tags,"score":score,"score_breakdown":breakdown,"host":host_of(event),"timestamp":stamp,"mitre":rule.mitre,"entity":{"kind":entity_kind,"value":entity_value},"evidence":build_evidence(rule,event,matched,extra_evidence),"observations":{"first_seen":stamp,"last_seen":stamp,"occurrences":1},"actions":rule.actions or ["log_only"],"status":"open","source":{"rule_file":rule.source_file,"ruleset_hash":ruleset_hash,"engine":ENGINE_NAME,"engine_version":__version__,"raw_event":event}}
    if epoch is not None:finding["timestamp_epoch"]=epoch
    return finding
def validate_finding(finding):return validate_instance("finding",finding,finding.get("finding_id","finding"))
def severity_label(severity):return {"info":"Bilgi","low":"Düşük","medium":"Orta","high":"Yüksek","critical":"Kritik"}.get(severity,severity)
def priority_of(finding):
    score=int(finding.get("score",0)); classification=finding.get("classification","suspicious")
    if classification=="indicator":return "low"
    if classification=="confirmed" or score>=90:return "critical"
    if score>=70:return "high"
    if score>=35:return "medium"
    return "low"
def to_display_row(finding):return {"finding_id":finding.get("finding_id"),"rule_id":finding.get("rule_id"),"severity":finding.get("severity"),"score":finding.get("score"),"priority":priority_of(finding),"classification":finding.get("classification"),"host":finding.get("host"),"timestamp":finding.get("timestamp"),"occurrences":(finding.get("observations") or {}).get("occurrences",1),"title":finding.get("title")}
def mitre_summary(findings):
    counts={}
    for finding in findings:
        for entry in enrich_mitre(finding.get("mitre")):
            technique=entry["technique"]; record=counts.setdefault(technique,{"technique":technique,"tactic":entry.get("tactic",""),"name":entry.get("name",""),"count":0,"rules":set()}); record["count"]+=1; record["rules"].add(finding.get("rule_id",""))
    rows=[]
    for record in counts.values():record["rules"]=sorted(r for r in record["rules"] if r); rows.append(record)
    return sorted(rows,key=lambda r:(-r["count"],r["technique"]))
