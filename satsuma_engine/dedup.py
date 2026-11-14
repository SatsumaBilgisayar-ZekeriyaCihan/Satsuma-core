"""Tekilleştirme (dedup): varlık + zaman penceresi tabanlı bulgu birleştirme."""
from __future__ import annotations
from dataclasses import dataclass, field as dc_field
from typing import Any
from .findings import SEVERITY_ORDER, severity_rank
from .rule_model import Rule
from .util import sha256_hex, truncate
MAX_EVIDENCE=25
CLASSIFICATION_ORDER=["indicator","suspicious","likely","confirmed"]
@dataclass
class DedupConfig:
    default_window_seconds:int=3600
    max_evidence_per_finding:int=MAX_EVIDENCE
@dataclass
class FindingRecord:
    finding:dict[str,Any]; group:str; window_seconds:int; first_seen_epoch:float|None; last_seen_epoch:float|None
    occurrences:int=1; event_fingerprints:list[str]=dc_field(default_factory=list); suppressed:bool=False
    suppression_id:str|None=None; suppression_reason:str|None=None; dedup_events:int=0
    @property
    def finding_id(self)->str:return str(self.finding.get("finding_id"))
    def merge_evidence(self,incoming:dict[str,Any],limit:int)->None:
        existing=self.finding.setdefault("evidence",[]); seen={(i.get("type"),i.get("field"),str(i.get("value")),i.get("event_fingerprint")) for i in existing}
        for item in incoming.get("evidence",[]):
            marker=(item.get("type"),item.get("field"),str(item.get("value")),item.get("event_fingerprint"))
            if marker in seen: continue
            if len(existing)>=limit: break
            seen.add(marker); existing.append(item)
    def raise_severity(self,severity:str)->None:
        if severity_rank(severity)>severity_rank(str(self.finding.get("severity","info"))): self.finding["severity"]=severity
    def raise_classification(self,classification:str)->None:
        current=str(self.finding.get("classification","indicator"))
        try:
            if CLASSIFICATION_ORDER.index(classification)>CLASSIFICATION_ORDER.index(current): self.finding["classification"]=classification
        except ValueError: return
class Deduplicator:
    def __init__(self,config:DedupConfig|None=None):
        self.config=config or DedupConfig(); self._records={}; self.records=[]; self.merged_count=0
    def add(self,rule:Rule,finding:dict[str,Any],epoch:float|None):
        window=rule.dedup_window_seconds or self.config.default_window_seconds; entity=(finding.get("entity") or {}).get("value",""); key=(rule.dedup_group,str(entity)); existing=self._records.get(key)
        if existing is not None and self._in_window(existing,epoch,window): self._merge(existing,finding,epoch); self.merged_count+=1; return existing,True
        record=FindingRecord(finding=finding,group=rule.dedup_group,window_seconds=window,first_seen_epoch=epoch,last_seen_epoch=epoch,occurrences=1,event_fingerprints=[str(finding.get("event_fingerprint",""))])
        finding["dedup_key"]=sha256_hex(rule.dedup_group,str(entity),self._bucket(epoch,window),length=24); self._records[key]=record; self.records.append(record); return record,False
    def _in_window(self,record,epoch,window):
        if epoch is None or record.last_seen_epoch is None:return True
        return (record.last_seen_epoch-epoch)<window and (epoch-record.last_seen_epoch)<window
    @staticmethod
    def _bucket(epoch,window):
        if epoch is None or window<=0:return 0
        return int(epoch//window)
    def _merge(self,record,incoming,epoch):
        record.occurrences+=1; record.dedup_events+=1
        if epoch is not None: record.last_seen_epoch=max(record.last_seen_epoch or epoch,epoch); record.first_seen_epoch=min(record.first_seen_epoch or epoch,epoch)
        observations=record.finding.setdefault("observations",{}); observations["occurrences"]=record.occurrences; stamp=incoming.get("timestamp")
        if stamp: observations["last_seen"]=stamp; observations.setdefault("first_seen",stamp)
        fingerprint=str(incoming.get("event_fingerprint",""))
        if fingerprint and fingerprint not in record.event_fingerprints: record.event_fingerprints.append(fingerprint)
        record.merge_evidence(incoming,self.config.max_evidence_per_finding); record.raise_severity(str(incoming.get("severity","info"))); record.raise_classification(str(incoming.get("classification","indicator")))
        incoming_score=int(incoming.get("score",0) or 0)
        if incoming_score>int(record.finding.get("score",0) or 0): record.finding["score"]=incoming_score; record.finding["score_breakdown"]=incoming.get("score_breakdown")
        breakdown=record.finding.get("score_breakdown") or {}; breakdown.setdefault("modifiers",[]).append({"reason":f"Aynı varlık için tekrar eden tespit ({record.occurrences}. olay)","delta":0}); record.finding["score_breakdown"]=breakdown
    @property
    def new_count(self):return len(self.records)
    def summary(self):return {"unique_findings":len(self.records),"merged_events":self.merged_count,"suppressed_findings":sum(1 for r in self.records if r.suppressed),"window_default_seconds":self.config.default_window_seconds}
    @staticmethod
    def describe_entity(finding):
        entity=finding.get("entity") or {}; return f"{entity.get('kind','event')}={truncate(entity.get('value',''),60)}"
