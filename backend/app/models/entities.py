import uuid
from datetime import datetime
from sqlalchemy import Column, String, Integer, Float, Boolean, Text, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.models.database import Base

def generate_uuid():
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="INVESTIGATOR")
    created_at = Column(DateTime, default=datetime.utcnow)

    cases = relationship("Case", back_populates="investigator")

class Case(Base):
    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_number = Column(String(50), unique=True, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(50), default="OPEN") # OPEN, IN_PROGRESS, CLOSED, ARCHIVED
    user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    investigator = relationship("User", back_populates="cases")
    emails = relationship("EmailRecord", back_populates="case", cascade="all, delete-orphan")

class EmailRecord(Base):
    __tablename__ = "emails"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=True)
    message_id = Column(String(255), nullable=True, index=True)
    subject = Column(Text, nullable=True)
    sender_address = Column(String(255), nullable=True)
    sender_name = Column(String(255), nullable=True)
    recipient_address = Column(String(255), nullable=True)
    cc = Column(String(255), nullable=True)
    reply_to = Column(String(255), nullable=True)
    return_path = Column(String(255), nullable=True)
    email_date = Column(DateTime, nullable=True)
    
    spf_status = Column(String(50), default="UNKNOWN")
    spf_details = Column(JSON, nullable=True)
    dkim_status = Column(String(50), default="UNKNOWN")
    dkim_details = Column(JSON, nullable=True)
    dmarc_status = Column(String(50), default="UNKNOWN")
    dmarc_details = Column(JSON, nullable=True)
    
    auth_caveat = Column(Text, default="Note: These are reported authentication results from headers, not independently verified cryptographic results.")
    
    raw_headers = Column(Text, nullable=True)
    x_headers = Column(JSON, nullable=True)
    body_plain = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    
    sha256_hash = Column(String(64), unique=True, nullable=False, index=True)
    overall_threat_score = Column(Float, default=0.0)
    threat_level = Column(String(50), default="Low") # Low, Medium, High, Critical
    contributing_factors = Column(JSON, nullable=True)
    
    originating_ip = Column(String(45), nullable=True)
    originating_country = Column(String(100), nullable=True)
    earliest_external_source = Column(String(255), nullable=True)
    
    domains = Column(JSON, nullable=True)
    ipv4_addresses = Column(JSON, nullable=True)
    ipv6_addresses = Column(JSON, nullable=True)
    ip_intelligence = Column(JSON, nullable=True)
    
    analyzed_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="emails")
    hops = relationship("EmailHop", back_populates="email", cascade="all, delete-orphan", order_by="EmailHop.hop_number")
    attachments = relationship("AttachmentRecord", back_populates="email", cascade="all, delete-orphan")
    urls = relationship("ExtractedURL", back_populates="email", cascade="all, delete-orphan")
    ai_analysis = relationship("AIAnalysis", back_populates="email", uselist=False, cascade="all, delete-orphan")
    blockchain_log = relationship("BlockchainLog", back_populates="email", uselist=False, cascade="all, delete-orphan")
    evidence_record = relationship("EvidenceRecord", back_populates="email", uselist=False, cascade="all, delete-orphan")

class EmailHop(Base):
    __tablename__ = "email_hops"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    hop_number = Column(Integer, nullable=False)
    timestamp = Column(DateTime, nullable=True)
    receiving_server = Column(String(255), nullable=True)
    sending_server = Column(String(255), nullable=True)
    ip_address = Column(String(45), nullable=False)
    reverse_dns = Column(String(255), nullable=True)
    country = Column(String(100), default="Unknown")
    city = Column(String(100), default="Unknown")
    latitude = Column(Float, default=0.0)
    longitude = Column(Float, default=0.0)
    isp = Column(String(255), default="Unknown Provider")
    asn = Column(String(100), default="Unknown ASN")
    delay_seconds = Column(Integer, default=0)
    is_vpn_proxy_tor = Column(Boolean, default=False)
    raw_received_header = Column(Text, nullable=True)
    infrastructure_intel = Column(JSON, nullable=True)

    email = relationship("EmailRecord", back_populates="hops")

class AttachmentRecord(Base):
    __tablename__ = "attachments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    filename = Column(String(255), nullable=False)
    mime_type = Column(String(100), nullable=True)
    file_size_bytes = Column(Integer, default=0)
    sha256_hash = Column(String(64), nullable=False)
    is_malicious = Column(Boolean, default=False)
    threat_description = Column(String(255), nullable=True)

    email = relationship("EmailRecord", back_populates="attachments")

class ExtractedURL(Base):
    __tablename__ = "extracted_urls"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String(255), nullable=False)
    is_suspicious = Column(Boolean, default=False)
    is_typosquatted = Column(Boolean, default=False)
    reputation_score = Column(Float, default=100.0) # 100 safe, 0 malicious
    
    url_details = Column(JSON, nullable=True)
    domain_intel = Column(JSON, nullable=True)
    lookalike_intel = Column(JSON, nullable=True)

    email = relationship("EmailRecord", back_populates="urls")

class AIAnalysis(Base):
    __tablename__ = "ai_analysis"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    classification = Column(String(100), default="Legitimate")
    confidence = Column(Float, default=1.0)
    signals = Column(JSON, nullable=True)
    model_info = Column(String(255), nullable=True)

    email = relationship("EmailRecord", back_populates="ai_analysis")

class BlockchainLog(Base):
    __tablename__ = "blockchain_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    transaction_hash = Column(String(66), nullable=False)
    block_number = Column(Integer, default=1)
    contract_address = Column(String(42), nullable=False)
    merkle_root = Column(String(64), nullable=False)
    status = Column(String(50), default="CONFIRMED")
    anchored_at = Column(DateTime, default=datetime.utcnow)

    email = relationship("EmailRecord", back_populates="blockchain_log")

class EvidenceRecord(Base):
    """Immutable metadata for a piece of forensic evidence.

    Stores the SHA-256 computed at collection time so that integrity
    can be re-verified later without touching the original bytes.
    """
    __tablename__ = "evidence_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    case_id = Column(String(36), ForeignKey("cases.id"), nullable=True)
    investigation_id = Column(String(100), nullable=True)
    sha256_hash = Column(String(64), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    file_size_bytes = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    collected_by = Column(String(255), nullable=False)
    integrity_status = Column(String(50), default="Verified")  # Verified | Integrity mismatch

    email = relationship("EmailRecord", back_populates="evidence_record")
    custody_events = relationship(
        "CustodyEvent", back_populates="evidence",
        cascade="all, delete-orphan", order_by="CustodyEvent.timestamp"
    )
    ledger_entry = relationship(
        "EvidenceLedgerEntry", back_populates="evidence",
        uselist=False, cascade="all, delete-orphan"
    )

class CustodyEvent(Base):
    """Single entry on the chain-of-custody timeline for evidence."""
    __tablename__ = "custody_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_id = Column(String(36), ForeignKey("evidence_records.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    user = Column(String(255), nullable=False)
    action = Column(String(100), nullable=False)

    evidence = relationship("EvidenceRecord", back_populates="custody_events")

class EvidenceLedgerEntry(Base):
    """On-ledger registration for a piece of evidence.

    PRIVACY: Only the evidence hash, evidence ID, timestamp, and case
    reference are stored.  NO raw email content, attachments, or PII.
    """
    __tablename__ = "evidence_ledger_entries"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_id = Column(String(36), ForeignKey("evidence_records.id"), nullable=False)
    ledger_tx_id = Column(String(66), nullable=False, index=True)
    evidence_hash = Column(String(64), nullable=False)
    case_reference = Column(String(100), nullable=True)
    block_number = Column(Integer, default=1)
    prev_block_hash = Column(String(64), nullable=True)
    merkle_root = Column(String(64), nullable=True)
    contract_address = Column(String(42), nullable=True)
    registered_at = Column(DateTime, default=datetime.utcnow)
    verification_status = Column(String(50), default="Verified")  # Verified | Integrity mismatch | Unverified
    ledger_status = Column(String(50), default="CONFIRMED")       # CONFIRMED | PENDING | FAILED

    evidence = relationship("EvidenceRecord", back_populates="ledger_entry")


class AuditLog(Base):
    """Audit log for recording security-sensitive platform actions."""
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    user_id = Column(String(255), nullable=False)
    user_role = Column(String(50), nullable=False)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(255), nullable=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(50), nullable=True)
    status = Column(String(50), default="SUCCESS")


