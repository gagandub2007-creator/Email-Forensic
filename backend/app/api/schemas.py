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

    class Config:
        from_attributes = True

class AIAnalysisOut(BaseModel):
    phishing_probability: float
    bec_probability: float
    scam_probability: float
    header_anomaly_score: float
    detected_keywords: Optional[List[str]] = []
    key_phrases: Optional[List[str]] = []

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

class EmailRecordOut(BaseModel):
    id: str
    case_id: Optional[str] = None
    message_id: Optional[str] = None
    subject: Optional[str] = None
    sender_address: Optional[str] = None
    sender_name: Optional[str] = None
    recipient_address: Optional[str] = None
    email_date: Optional[datetime] = None
    spf_status: str
    dkim_status: str
    dmarc_status: str
    sha256_hash: str
    overall_threat_score: float
    threat_level: str
    originating_ip: Optional[str] = None
    originating_country: Optional[str] = None
    analyzed_at: datetime
    hops: List[HopOut] = []
    attachments: List[AttachmentOut] = []
    urls: List[URLOut] = []
    ai_analysis: Optional[AIAnalysisOut] = None
    blockchain_log: Optional[BlockchainOut] = None

    class Config:
        from_attributes = True
