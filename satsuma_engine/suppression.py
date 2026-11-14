"""Bastırma / allowlist katmanı."""
from __future__ import annotations
import fnmatch
from dataclasses import dataclass, field as dc_field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from . import RULE_API_VERSION
from .conditions import CompiledLogic
from .errors import Issue,SatsumaEngineError,SuppressionError
from .findings import severity_rank
from .schema_store import validate_instance
from .util import as_list,load_structured,parse_timestamp
@dataclass
class SuppressionEntry:
    data:dict[str,Any]; logic:CompiledLogic|None=None; hits:int=0; limit_reached:bool=False
    @property
    def id(self):return str(self.data["id"])
    @property
    def reason(self):return str(self.data["reason"])
    @property
    def enabled(self):return bool(self.data.get("enabled",True))
    @property
    def expires_epoch(self):
        if self.data.get("expires_at"):return parse_timestamp(self.data["expires_at"])
        if self.data.get("expires_in_seconds"):
            created=parse_timestamp(self.data.get("created_at")) or datetime.now(timezone.utc).timestamp(); return created+float(self.data["expires_in_seconds"])
        return None
    def expired(self,reference=None):
        expires=self.expires_epoch
        if expires is None:return False
        return expires <= (reference if reference is not None else datetime.now(timezone.utc).timestamp())
    @property
    def max_suppressed(self):
        value=self.data.get("max_suppressed"); return int(value) if value else None
    def matches(self,finding,reference=None):
        if not self.enabled:return False,"devre dışı"
        if self.expired(reference):return False,"süresi dolmuş"
        if self.limit_reached:return False,"bastırma üst sınırı aşıldı"
        rule_ids=as_list(self.data.get("rule_ids"));
        if rule_ids and not any(fnmatch.fnmatch(str(finding.get("rule_id","")),pattern) for pattern in rule_ids):return False,"rule_ids uyuşmadı"
        finding_ids=as_list(self.data.get("finding_ids"));
        if finding_ids and str(finding.get("finding_id")) not in {str(i) for i in finding_ids}:return False,"finding_ids uyuşmadı"
        hosts=as_list(self.data.get("hosts"));
        if hosts and not any(fnmatch.fnmatch(str(finding.get("host","")),pattern) for pattern in hosts):return False,"hosts uyuşmadı"
        categories=as_list(self.data.get("categories"));
        if categories and str(finding.get("category","")) not in {str(c) for c in categories}:return False,"categories uyuşmadı"
        entity_kinds=as_list(self.data.get("entity_kinds"));
        if entity_kinds and str((finding.get("entity") or {}).get("kind","")) not in {str(k) for k in entity_kinds}:return False,"entity_kinds uyuşmadı"
        at_most=self.data.get("severity_at_most")
        if at_most and severity_rank(str(finding.get("severity","info")))>severity_rank(str(at_most)):return False,"severity_at_most üstünde"
        if self.logic is not None and not self.logic.evaluate(finding):return False,"match koşulu sağlanmadı"
        return True,"eşleşti"
    def register_hit(self):
        self.hits+=1; limit=self.max_suppressed
        if limit is not None and self.hits>=limit:self.limit_reached=True
    def to_dict(self):return {"id":self.id,"reason":self.reason,"enabled":self.enabled,"hits":self.hits,"limit_reached":self.limit_reached,"expires_at":self.data.get("expires_at"),"expired":self.expired()}
@dataclass
class SuppressionDecision:entry:SuppressionEntry; reason:str
@dataclass
class SuppressionList:
    entries:list[SuppressionEntry]=dc_field(default_factory=list); warnings:list[Issue]=dc_field(default_factory=list); source:Path|None=None; defaults:dict[str,Any]=dc_field(default_factory=dict)
    @classmethod
    def load(cls,path):
        if path is None:return cls()
        if not path.exists():raise SuppressionError(f"Bastırma dosyası bulunamadı: {path}")
        try:payload=load_structured(path)
        except Exception as exc:raise SuppressionError(f"Bastırma dosyası okunamadı ({path}): {exc}") from exc
        if payload is None:return cls(source=path)
        candidate=dict(payload) if isinstance(payload,dict) else {"suppressions":payload}; candidate.setdefault("schema",RULE_API_VERSION); issues=validate_instance("suppression",candidate,path.name)
        if issues:raise SatsumaEngineError("Bastırma dosyası doğrulaması başarısız:\n"+"\n".join(f"  - {i.format()}" for i in issues))
        defaults=candidate.get("defaults") or {}; entries=[]; warnings=[]
        for index,item in enumerate(candidate.get("suppressions") or []):
            data=dict(item)
            if data.get("expires_in_seconds") is None and defaults.get("duration_seconds"):data["expires_in_seconds"]=defaults["duration_seconds"]
            if data.get("max_suppressed") is None and defaults.get("max_suppressed"):data["max_suppressed"]=defaults["max_suppressed"]
            if data.get("created_by") is None and defaults.get("created_by"):data["created_by"]=defaults["created_by"]
            logic=None
            if data.get("match"):
                logic=CompiledLogic.compile(data["match"],f"{path.name}.suppressions[{index}].match"); warnings.extend(logic.issues)
            entry=SuppressionEntry(data=data,logic=logic)
            if entry.expired():warnings.append(Issue("suppression.expired",f"Bastırma kaydının süresi dolmuş: {entry.id}",f"{path.name}:{entry.id}",severity="warning",hint="Kaydı silin veya `expires_at` alanını güncelleyin."))
            entries.append(entry)
        return cls(entries=entries,warnings=warnings,source=path,defaults=defaults)
    def evaluate(self,finding,reference=None):
        for entry in self.entries:
            matched,_=entry.matches(finding,reference)
            if matched:entry.register_hit(); return SuppressionDecision(entry,entry.reason)
        return None
    def check_rule_references(self,known_rule_ids):
        issues=[]
        for entry in self.entries:
            for pattern in as_list(entry.data.get("rule_ids")):
                if "*" in str(pattern) or "?" in str(pattern):
                    if not any(fnmatch.fnmatch(rule_id,str(pattern)) for rule_id in known_rule_ids):issues.append(Issue("suppression.unused_pattern",f"Bastırma `{entry.id}` içindeki desen hiçbir kurala uymuyor: {pattern}",f"{self.source.name if self.source else 'suppressions'}:{entry.id}",severity="warning"))
                elif str(pattern) not in known_rule_ids:issues.append(Issue("suppression.unknown_rule",f"Bastırma `{entry.id}` var olmayan kuralı hedefliyor: {pattern}",f"{self.source.name if self.source else 'suppressions'}:{entry.id}",severity="warning"))
        return issues
    def summary(self):return {"source":str(self.source) if self.source else None,"entries":len(self.entries),"active":sum(1 for e in self.entries if e.enabled and not e.expired() and not e.limit_reached),"hits":{e.id:e.hits for e in self.entries if e.hits},"warnings":[i.format() for i in self.warnings]}
