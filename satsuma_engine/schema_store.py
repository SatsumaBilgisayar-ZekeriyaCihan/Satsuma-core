"""JSON Schema yükleyici ve doğrulayıcı."""
from __future__ import annotations
import json
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable
from jsonschema import Draft202012Validator
from .errors import Issue, SatsumaEngineError
SCHEMA_DIR = Path(__file__).resolve().parent / "schemas"
SCHEMA_FILES = {"rule":"rule.schema.json","finding":"finding.schema.json","suppression":"suppression.schema.json","event":"event.schema.json"}
def schema_path(kind:str)->Path:
    try:return SCHEMA_DIR/SCHEMA_FILES[kind]
    except KeyError as exc: raise SatsumaEngineError(f"Bilinmeyen şema türü: {kind!r}. Geçerli türler: {', '.join(sorted(SCHEMA_FILES))}") from exc
@lru_cache(maxsize=None)
def load_schema(kind:str)->dict[str,Any]:
    path=schema_path(kind)
    if not path.exists(): raise SatsumaEngineError(f"Şema dosyası bulunamadı: {path}")
    return json.loads(path.read_text(encoding="utf-8"))
@lru_cache(maxsize=None)
def _validator(kind:str)->Draft202012Validator:return Draft202012Validator(load_schema(kind))
def _format_path(path_parts:Iterable[Any])->str:
    text=""
    for part in path_parts:
        text += f"[{part}]" if isinstance(part,int) else (("." if text else "")+str(part))
    return text or "(kök)"
def _hint_for(error:Any)->str:
    v=error.validator
    if v=="required":
        missing=[p for p in error.validator_value if p not in (error.instance or {})]
        return f"Zorunlu alan(lar) eksik: {', '.join(missing)}"
    if v=="additionalProperties": return "Tanınmayan alan. Yeni/genişletilmiş alanlar için `extensions` bloğunu veya `x-` önekini kullanın."
    if v=="enum": return f"İzin verilen değerler: {', '.join(map(str,error.validator_value))}"
    if v=="pattern": return f"Değer şu kalıba uymalı: {error.validator_value}"
    if v=="oneOf": return "Bu blok ya basit bir koşul (field + operatör) ya da all/any/none grubu olmalı."
    if v=="const": return f"Sabit değer bekleniyor: {error.validator_value!r}"
    if v=="type": return f"Beklenen tip: {error.validator_value}"
    return ""
def validate_instance(kind:str,instance:Any,location:str="")->list[Issue]:
    issues=[]
    for error in sorted(_validator(kind).iter_errors(instance),key=lambda e:list(e.absolute_path)):
        path=_format_path(error.absolute_path); where=f"{location}:{path}" if location else path
        issues.append(Issue(code=f"schema.{error.validator}",message=error.message,location=where,severity="error",hint=_hint_for(error)))
    return issues
def is_valid(kind:str,instance:Any)->bool:return not any(i.severity=="error" for i in validate_instance(kind,instance))
