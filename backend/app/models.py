from enum import Enum
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

class RiskLabel(str, Enum):
    LOW_RISK = "Low Risk"
    SUSPICIOUS = "Suspicious"
    HIGH_RISK = "High Risk"
    CONFIRMED_MALICIOUS = "Confirmed Malicious"
    INCONCLUSIVE = "Inconclusive"

class FindingCategory(str, Enum):
    IMPERSONATION = "IMPERSONATION"
    STRUCTURE = "STRUCTURE"
    DOMAIN = "DOMAIN"
    REDIRECT = "REDIRECT"
    TLS = "TLS"
    INTEL = "INTEL"
    HEADERS = "HEADERS"
    CONTENT = "CONTENT"

class Severity(str, Enum):
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ScanRequest(BaseModel):
    type: Literal["url", "message"]
    value: str = Field(..., max_length=5000)
    use_cached: Optional[bool] = False

class Finding(BaseModel):
    id: str  # e.g. "F-01"
    signal_id: str  # e.g. "IMP-01"
    category: FindingCategory
    title: str
    description: str
    severity: Severity
    points: int
    technical_evidence: Dict[str, Any] = Field(default_factory=dict)
    source: str
    potential_impact: str
    recommendation: str
    limitation: str

class CheckRecord(BaseModel):
    check_id: str
    status: Literal["passed", "flagged", "unavailable", "skipped"]
    duration_ms: int = 0
    short_note: str = ""

class RedirectHop(BaseModel):
    url: str  # defanged
    status_code: int
    registrable_domain: str
    same_site: bool

class TLSReport(BaseModel):
    subject: str = ""
    san_list: List[str] = Field(default_factory=list)
    issuer: str = ""
    validity_start: str = ""
    validity_end: str = ""
    days_remaining: int = 0
    public_key_algorithm: str = ""
    public_key_size: int = 0
    signature_algorithm: str = ""
    certificate_sha256: str = ""
    spki_sha256: str = ""
    chain_list: List[str] = Field(default_factory=list)
    trust_result: Literal["trusted", "self_signed", "unknown_issuer", "incomplete_chain", "distrusted"] = "trusted"
    ct_summary: Dict[str, Any] = Field(default_factory=dict)
    tls_verdict: Literal["Valid configuration", "Configuration problems", "Suspicious", "Potentially compromised trust"] = "Valid configuration"
    https_note: str = "A valid HTTPS certificate only means the connection is encrypted and the certificate matches the domain. It does not mean the website is trustworthy."

class SecurityHeaderResult(BaseModel):
    header_name: str
    present: bool
    observed_value: Optional[str] = None
    severity: Severity = Severity.INFO

class ThreatIntelMatch(BaseModel):
    source_name: str
    listing_status: str  # online, offline, listed
    listing_date: Optional[str] = None
    threat_type: Optional[str] = None
    reference_url: Optional[str] = None

class ThreatIntelSummary(BaseModel):
    feeds_queried: List[str] = Field(default_factory=list)
    feeds_answered: List[str] = Field(default_factory=list)
    feeds_unavailable: List[str] = Field(default_factory=list)
    matches: List[ThreatIntelMatch] = Field(default_factory=list)

class CampaignInfo(BaseModel):
    linked: bool = False
    strength: Optional[Literal["strong", "possible"]] = None
    matched_indicators: List[str] = Field(default_factory=list)
    related_report_count: int = 0
    first_seen: Optional[str] = None
    cluster_size: int = 0
    ai_summary: Optional[str] = None

class MessageAnalysis(BaseModel):
    extracted_urls: List[str] = Field(default_factory=list)
    emails: List[str] = Field(default_factory=list)
    phone_numbers: List[str] = Field(default_factory=list)  # hashed in indicators
    upi_ids: List[str] = Field(default_factory=list)
    crypto_addresses: List[str] = Field(default_factory=list)
    signals_triggered: List[str] = Field(default_factory=list)
    per_url_labels: Dict[str, str] = Field(default_factory=dict)
    what_message_says: List[str] = Field(default_factory=list)
    what_checks_found: List[str] = Field(default_factory=list)
    redaction_applied: bool = False

class AIEvidencePoint(BaseModel):
    finding_id: str
    explanation: str

class AIExplanation(BaseModel):
    summary: str
    evidence_points: List[AIEvidencePoint] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    limitations_note: str
    model_name: str
    generated_by: Literal["llm", "fallback_template"]

class EvidenceCoverage(BaseModel):
    percent: int
    completed_groups: List[str] = Field(default_factory=list)
    unavailable_groups: List[str] = Field(default_factory=list)

class Web3Info(BaseModel):
    status: Literal["not_committed", "pending", "committed"] = "not_committed"
    report_hash: str = ""
    tx_hash: str = ""
    block_number: int = 0
    network: str = ""
    chain_id: int = 0
    contract_address: str = ""
    committed_at: str = ""
    revision: int = 1

class Report(BaseModel):
    report_id: str
    schema_version: int = 1
    created_at: str
    input_type: Literal["url", "message"]
    input_display: str
    normalized_url: str = ""
    registrable_domain: str = ""
    final_url: str = ""
    final_domain: str = ""
    resolved_ips: List[str] = Field(default_factory=list)
    risk_label: RiskLabel
    risk_score: int
    evidence_coverage: EvidenceCoverage
    findings: List[Finding] = Field(default_factory=list)
    checks: List[CheckRecord] = Field(default_factory=list)
    redirect_chain: List[RedirectHop] = Field(default_factory=list)
    tls: Optional[TLSReport] = None
    security_headers: List[SecurityHeaderResult] = Field(default_factory=list)
    threat_intel: ThreatIntelSummary = Field(default_factory=ThreatIntelSummary)
    campaign: CampaignInfo = Field(default_factory=CampaignInfo)
    message_analysis: Optional[MessageAnalysis] = None
    ai_explanation: AIExplanation
    recommended_actions: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    disclaimer: str = (
        "No automated tool can guarantee a website is completely safe. "
        "This assessment reflects only the checks that were available at the time of analysis."
    )
    analysis_duration_ms: int = 0
    is_cached_sample: bool = False
    
    # Excluded from canonical hash (Section 8.3)
    web3: Optional[Web3Info] = None
    report_hash: Optional[str] = None
