"""
Satsuma Core — SatsumaEvent Model
Görev: Unified Event Schema v1.0 (Pydantic).
Yapmaz: Validation, mapping, karar.
"""

from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field


SCHEMA_VERSION = "1.0"


class EventCategory(str, Enum):
    NETWORK = "network"
    HOST = "host"
    USER = "user"
    APP = "app"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SourceType(str, Enum):
    SURICATA = "suricata"
    FIREWALL = "firewall"
    DNS = "dns"
    WEB = "web"
    LINUX = "linux"
    FILE = "file"


class RawFormat(str, Enum):
    JSON = "json"
    EVE = "eve"
    SYSLOG = "syslog"
    CEF = "cef"
    LEEF = "leef"
    PLAIN = "plain"


class Severity(BaseModel):
    level: SeverityLevel
    source: str


class EventBlock(BaseModel):
    id: str
    timestamp: str
    ingested_at: str
    schema_version: str
    category: EventCategory
    action: str
    outcome: Optional[EventOutcome] = None
    severity: Optional[Severity] = None


class SourceBlock(BaseModel):
    type: SourceType
    host: str
    collector_id: str
    raw_ref: str
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class NetworkBlock(BaseModel):
    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    proto: Optional[str] = None
    direction: Optional[str] = None
    vlan: Optional[int] = None


class HostBlock(BaseModel):
    name: Optional[str] = None
    os: Optional[str] = None
    zone: Optional[str] = None


class UserBlock(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None


class AppBlock(BaseModel):
    protocol: Optional[str] = None
    name: Optional[str] = None
    http: Optional[Dict[str, Any]] = None


class PayloadBlock(BaseModel):
    signature: Optional[str] = None
    summary: Optional[str] = None
    hash: Optional[str] = None


class RawBlock(BaseModel):
    format: RawFormat
    data: Union[Dict[str, Any], str]


class MetadataBlock(BaseModel):
    tags: List[str] = Field(default_factory=list)
    labels: Dict[str, str] = Field(default_factory=dict)
    extensions: Dict[str, Any] = Field(default_factory=dict)


class SatsumaEvent(BaseModel):
    event: EventBlock
    source: SourceBlock
    raw: RawBlock
    network: Optional[NetworkBlock] = None
    host: Optional[HostBlock] = None
    user: Optional[UserBlock] = None
    app: Optional[AppBlock] = None
    payload: Optional[PayloadBlock] = None
    metadata: MetadataBlock = Field(default_factory=MetadataBlock)
