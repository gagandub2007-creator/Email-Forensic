from datetime import datetime
from typing import List, Optional, Any
from pydantic import BaseModel, EmailStr

# Auth Schemas
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: str
    username: str
    role: str

# Case Schemas
class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    case_number: Optional[str] = None
    severity: Optional[str] = "High"
    status: Optional[str] = "Open"
    assigned_analyst: Optional[str] = "Marcus K. (SOC L2 Analyst)"

class CaseUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None # Open, Investigating, Resolved, Closed
    severity: Optional[str] = None # Low, Medium, High, Critical
    assigned_analyst: Optional[str] = None

class CaseNoteCreate(BaseModel):
    text: str
    author: Optional[str] = "Marcus K. (SOC L2 Analyst)"

class CaseNoteOut(BaseModel):
    id: str
    author: str
    text: str
    timestamp: str

class CaseOut(BaseModel):
    id: str
    case_number: str
    title: str
    description: Optional[str] = None
    severity: str = "High"
    status: str = "Open"
    assigned_analyst: str = "Marcus K. (SOC L2 Analyst)"
    investigation_count: int = 0
    notes: List[CaseNoteOut] = []
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class CreateCaseFromInvestigationIn(BaseModel):
    email_id: str
    title: Optional[str] = None
    severity: Optional[str] = "High"
    status: Optional[str] = "Open"
    assigned_analyst: Optional[str] = "Marcus K. (SOC L2 Analyst)"


# Email Analysis Schemas
class HopOut(BaseModel):
    hop_number: int
    timestamp: Optional[datetime] = None
    receiving_server: Optional[str] = None
    sending_server: Optional[str] = None
    ip_address: str
    reverse_dns: Optional[str] = None
    country: str
    city: str
    latitude: float
    longitude: float
    isp: str
    asn: str
    delay_seconds: int
    is_vpn_proxy_tor: bool
    raw_header_reference: Optional[str] = None
    infrastructure_intel: Optional[Any] = None

    class Config:
        from_attributes = True

class AttachmentOut(BaseModel):
    id: str
    filename: str
    mime_type: Optional[str] = None
    file_size_bytes: int
    sha256_hash: str
    is_malicious: bool
    threat_description: Optional[str] = None

    class Config:
        from_attributes = True

class URLOut(BaseModel):
    id: str
    url: str
    domain: str
    is_suspicious: bool
    is_typosquatted: bool
    reputation_score: float
    url_details: Optional[Any] = None
    domain_intel: Optional[Any] = None
    lookalike_intel: Optional[Any] = None

    class Config:
        from_attributes = True

class AIAnalysisOut(BaseModel):
    classification: str
    confidence: float
    signals: Optional[List[str]] = []
    model_info: Optional[str] = None

    class Config:
        from_attributes = True

class BlockchainOut(BaseModel):
    transaction_hash: str
    block_number: int
    contract_address: str
    merkle_root: str
    status: str
    anchored_at: datetime

    class Config:
        from_attributes = True

class SPFDetailsOut(BaseModel):
    status: str
    domain: Optional[str] = None
    explanation: Optional[str] = None

class DKIMDetailsOut(BaseModel):
    status: str
    domain: Optional[str] = None
    selector: Optional[str] = None
    explanation: Optional[str] = None

class DMARCDetailsOut(BaseModel):
    status: str
    policy: Optional[str] = None
    aligned_domain: Optional[str] = None
    explanation: Optional[str] = None

class EmailRecordOut(BaseModel):
    id: str
    case_id: Optional[str] = None
    message_id: Optional[str] = None
    subject: Optional[str] = None
    sender_address: Optional[str] = None
    sender_name: Optional[str] = None
    recipient_address: Optional[str] = None
    cc: Optional[str] = None
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    email_date: Optional[datetime] = None
    spf_status: str
    spf_details: Optional[SPFDetailsOut] = None
    dkim_status: str
    dkim_details: Optional[DKIMDetailsOut] = None
    dmarc_status: str
    dmarc_details: Optional[DMARCDetailsOut] = None
    auth_caveat: str
    sha256_hash: str
    overall_threat_score: float
    threat_level: str
    contributing_factors: Optional[List[str]] = []
    originating_ip: Optional[str] = None
    originating_country: Optional[str] = None
    earliest_external_source: Optional[str] = None
    x_headers: Optional[Any] = None
    domains: Optional[List[str]] = []
    ipv4_addresses: Optional[List[str]] = []
    ipv6_addresses: Optional[List[str]] = []
    ip_intelligence: Optional[Any] = None
    analyzed_at: datetime
    hops: List[HopOut] = []
    attachments: List[AttachmentOut] = []
    urls: List[URLOut] = []
    ai_analysis: Optional[AIAnalysisOut] = None
    blockchain_log: Optional[BlockchainOut] = None

    class Config:
        from_attributes = True

# Threat Graph Schemas
class GraphNode(BaseModel):
    id: str
    label: str
    properties: Any

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship: str
    properties: Optional[Any] = {}

class GraphResponse(BaseModel):
    provider_mode: str  # "NEO4J_LIVE" or "DEMO_FALLBACK"
    is_neo4j_connected: bool
    note: Optional[str] = None
    nodes: List[GraphNode]
    edges: List[GraphEdge]

class GraphStatusResponse(BaseModel):
    is_neo4j_connected: bool
    provider_mode: str
    neo4j_uri: str
    neo4j_database: str

# Historical Threat Correlation Schemas
class RelatedInvestigationItem(BaseModel):
    email_id: str
    case_id: Optional[str] = None
    case_number: str
    case_title: str
    subject_summary: str
    sender_address: Optional[str] = None
    threat_level: Optional[str] = None
    analyzed_at: Optional[str] = None
    matched_artifacts: List[str]

class SharedInfrastructureOut(BaseModel):
    shared_ips: List[str]
    shared_asns: List[str]
    shared_isps: List[str]
    shared_countries: List[str]

class PotentialCampaignOut(BaseModel):
    has_potential_campaign: bool
    confidence_score: float
    campaign_name: str
    description: str
    observed_indicators: List[str]
    cautious_language_disclaimer: str

class SharedAttachmentOut(BaseModel):
    hash: str
    filename: str

class CorrelationResponse(BaseModel):
    target_email_id: str
    correlation_status: str
    previous_occurrences_count: int
    related_investigations: List[RelatedInvestigationItem]
    shared_infrastructure: SharedInfrastructureOut
    shared_domains: List[str]
    shared_urls: List[str]
    shared_ips: List[str]
    shared_attachments: List[SharedAttachmentOut] = []
    potential_campaign: PotentialCampaignOut

# Attribution Support Schemas
class AttributionSupportResponse(BaseModel):
    email_id: str
    probable_source_infrastructure: str
    confidence_score: float
    confidence_percentage: str
    supporting_evidence: List[str]
    alternative_explanations: List[str]
    limitations: str

# Evidence Preservation & Chain of Custody Schemas
class CustodyLogEvent(BaseModel):
    timestamp: str
    user: str
    action: str  # Evidence collected, Analysis performed, Evidence viewed, Evidence exported, Report generated
    evidence_id: str

class EvidenceRecordOut(BaseModel):
    id: str
    case_id: Optional[str] = None
    investigation_id: str
    sha256_hash: str
    file_name: str
    file_size_bytes: int
    file_path: str
    collected_by: str
    integrity_status: str  # Verified, Integrity mismatch
    chain_of_custody_logs: List[CustodyLogEvent] = []
    created_at: datetime

    class Config:
        from_attributes = True

class IntegrityCheckResult(BaseModel):
    status: str  # Verified or Integrity mismatch
    stored_hash: str
    recalculated_hash: str
    file_name: str
    evidence_id: str
    error: Optional[str] = None

class LogCustodyActionIn(BaseModel):
    user: str = "SOC Analyst"
    action: str  # Evidence collected, Analysis performed, Evidence viewed, Evidence exported, Report generated



