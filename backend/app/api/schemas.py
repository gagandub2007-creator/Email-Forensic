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

class CaseOut(BaseModel):
    id: str
    case_number: str
    title: str
    description: Optional[str] = None
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

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
    evidence_record: Optional["EvidenceRecordOut"] = None

    class Config:
        from_attributes = True

# Evidence Preservation Schemas (Step 16)
class CustodyEventOut(BaseModel):
    id: str
    evidence_id: str
    timestamp: datetime
    user: str
    action: str

    class Config:
        from_attributes = True

class CustodyEventCreate(BaseModel):
    user: str
    action: str
class EvidenceLedgerEntryOut(BaseModel):
    id: str
    evidence_id: str
    ledger_tx_id: str
    evidence_hash: str
    case_reference: Optional[str] = None
    block_number: int
    prev_block_hash: Optional[str] = None
    merkle_root: Optional[str] = None
    contract_address: Optional[str] = None
    registered_at: datetime
    verification_status: str
    ledger_status: str

    class Config:
        from_attributes = True

class LedgerVerifyOut(BaseModel):
    evidence_id: str
    verified: bool
    status: str
    recorded_hash: Optional[str] = None
    submitted_hash: str
    block_number: Optional[int] = None
    timestamp: Optional[str] = None
    contract_address: Optional[str] = None

class EvidenceRecordOut(BaseModel):
    id: str
    email_id: str
    case_id: Optional[str] = None
    investigation_id: Optional[str] = None
    sha256_hash: str
    filename: str
    file_size_bytes: int
    created_at: datetime
    collected_by: str
    integrity_status: str
    custody_events: List[CustodyEventOut] = []
    ledger_entry: Optional[EvidenceLedgerEntryOut] = None

    class Config:
        from_attributes = True

class EvidenceVerifyOut(BaseModel):
    evidence_id: str
    status: str
    stored_hash: str
    recalculated_hash: str
    verified_at: str
    match: bool
