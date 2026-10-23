from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, HttpUrl

class Category(str, Enum):
    vuln = "vuln"
    weak_config = "weak_config"
    tamper = "tamper"
    malware = "malware"
    leak = "leak"
    bad_link = "bad_link"

class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"

class Status(str, Enum):
    active = "active"
    confirmed = "confirmed"
    false_positive = "false_positive"
    fixed = "fixed"

class Evidence(BaseModel):
    request_sample: Optional[str] = None
    response_sample: Optional[str] = None
    screenshot_ref: Optional[str] = None
    matched_context: Optional[str] = None

class RiskRecord(BaseModel):
    asset_url: str
    category: Category
    severity: Severity
    title: str
    description: Optional[str] = None
    evidence: Evidence = Field(default_factory=Evidence)
    raw_output: Optional[str] = None
    tool: Optional[str] = None
    template: Optional[str] = None
    first_seen: datetime
    last_seen: datetime
    status: Status = Status.active
    signature: str

class Asset(BaseModel):
    url: str
    host: str
    fingerprint: dict[str, Any] = Field(default_factory=dict)
    status_code: Optional[int] = None
    page_hash: Optional[str] = None
    title: Optional[str] = None

class ScanConfig(BaseModel):
    rate_limit_qps: int = 5
    non_destructive: bool = True
    timeout_sec: int = 30

class ScanRequest(BaseModel):
    assets: list[Asset] = Field(default_factory=list)
    config: ScanConfig = Field(default_factory=ScanConfig)

class ScanResponse(BaseModel):
    job_id: str
    risks: list[RiskRecord] = Field(default_factory=list)

class DiscoveryResponse(BaseModel):
    assets: list[Asset] = Field(default_factory=list)