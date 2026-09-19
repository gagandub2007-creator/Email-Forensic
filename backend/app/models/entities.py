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
    email_date = Column(DateTime, nullable=True)
    
    spf_status = Column(String(50), default="UNKNOWN")
    dkim_status = Column(String(50), default="UNKNOWN")
    dmarc_status = Column(String(50), default="UNKNOWN")
    
    raw_headers = Column(Text, nullable=True)
    body_plain = Column(Text, nullable=True)
    body_html = Column(Text, nullable=True)
    
    sha256_hash = Column(String(64), unique=True, nullable=False, index=True)
    overall_threat_score = Column(Float, default=0.0)
    threat_level = Column(String(50), default="CLEAN") # CLEAN, SUSPICIOUS, HIGH_RISK, CRITICAL
    
    originating_ip = Column(String(45), nullable=True)
    originating_country = Column(String(100), nullable=True)
    
    analyzed_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("Case", back_populates="emails")
    hops = relationship("EmailHop", back_populates="email", cascade="all, delete-orphan", order_by="EmailHop.hop_number")
    attachments = relationship("AttachmentRecord", back_populates="email", cascade="all, delete-orphan")
    urls = relationship("ExtractedURL", back_populates="email", cascade="all, delete-orphan")
    ai_analysis = relationship("AIAnalysis", back_populates="email", uselist=False, cascade="all, delete-orphan")
    blockchain_log = relationship("BlockchainLog", back_populates="email", uselist=False, cascade="all, delete-orphan")

class EmailHop(Base):
    __tablename__ = "email_hops"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    hop_number = Column(Integer, nullable=False)
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

    email = relationship("EmailRecord", back_populates="urls")

class AIAnalysis(Base):
    __tablename__ = "ai_analysis"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email_id = Column(String(36), ForeignKey("emails.id"), nullable=False)
    phishing_probability = Column(Float, default=0.0)
    bec_probability = Column(Float, default=0.0)
    scam_probability = Column(Float, default=0.0)
    header_anomaly_score = Column(Float, default=0.0)
    detected_keywords = Column(JSON, nullable=True)
    key_phrases = Column(JSON, nullable=True)

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
