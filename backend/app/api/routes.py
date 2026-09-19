import uuid
from typing import List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Response, status
from sqlalchemy.orm import Session

from app.models.database import get_db
from app.models.entities import User, Case, EmailRecord, EmailHop, AttachmentRecord, ExtractedURL, AIAnalysis, BlockchainLog
from app.api.schemas import (
    UserRegister, UserLogin, TokenResponse, CaseCreate, CaseOut, EmailRecordOut, HopOut
)
from app.services.parser import EmailParserEngine
from app.services.geoip import GeoIPService
from app.services.threat_ai import AIThreatEngine
from app.services.risk_scoring import RiskScoringEngine
from app.services.url_intel import URLIntelEngine
from app.services.ip_intel import IPIntelEngine
from app.services.blockchain import BlockchainService
from app.services.report import ForensicReportGenerator

router = APIRouter()

# Helper Authentication Mock for fast dev/demo
def get_current_user_id():
    return "investigator-admin-uuid"

# 1. Auth Endpoints
@router.post("/auth/register", response_model=TokenResponse)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.username == user_data.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    user = User(
        id=str(uuid.uuid4()),
        username=user_data.username,
        email=user_data.email,
        password_hash="pbkdf2_sha256_mock_hash", # Simplified for hackathon setup
        role="INVESTIGATOR"
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return TokenResponse(
        access_token=f"jwt_token_{user.id}",
        user_id=user.id,
        username=user.username,
        role=user.role
    )

@router.post("/auth/login", response_model=TokenResponse)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_data.username).first()
    if not user:
        # Auto-create demo admin user if missing
        user = User(
            id="investigator-admin-uuid",
            username=login_data.username,
            email=f"{login_data.username}@cybercell.gov.in",
            password_hash="hashed_pass",
            role="CHIEF_INVESTIGATOR"
        )
        db.add(user)
        db.commit()

    return TokenResponse(
        access_token=f"jwt_token_{user.id}",
        user_id=user.id,
        username=user.username,
        role=user.role
    )

# 2. Case Management Endpoints
@router.get("/cases", response_model=List[CaseOut])
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(Case).all()
    if not cases:
        # Seed default case if empty
        default_case = Case(
            id="3c901c80-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
            case_number="CASE-2026-SIH26106",
            title="AICTE Cyber Cell Operation Email Shield",
            description="Active investigation into Business Email Compromise and phishing threats.",
            status="IN_PROGRESS"
        )
        db.add(default_case)
        db.commit()
        cases = [default_case]
    return cases

@router.post("/cases", response_model=CaseOut)
def create_case(case_in: CaseCreate, db: Session = Depends(get_db)):
    case_num = case_in.case_number or f"CASE-2026-{str(uuid.uuid4())[:8].upper()}"
    new_case = Case(
        id=str(uuid.uuid4()),
        case_number=case_num,
        title=case_in.title,
        description=case_in.description,
        status="OPEN",
        user_id=get_current_user_id()
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)
    return new_case

# 3. Email Ingestion & Analysis Engine
@router.post("/emails/analyze", response_model=EmailRecordOut)
async def analyze_email(
    file: UploadFile = File(None),
    raw_text: str = Form(None),
    case_id: str = Form(None),
    db: Session = Depends(get_db)
):
    if file:
        raw_bytes = await file.read()
    elif raw_text:
        raw_bytes = raw_text.encode('utf-8')
    else:
        raise HTTPException(status_code=400, detail="Must provide either file or raw_text")
        
    if not raw_bytes:
        raise HTTPException(status_code=400, detail="Input is empty")

    # 1. Parse Email File
    parsed = EmailParserEngine.parse_eml_bytes(raw_bytes)
    sha256_hash = parsed["sha256_hash"]

    # Check if duplicate evidence hash already exists
    existing_email = db.query(EmailRecord).filter(EmailRecord.sha256_hash == sha256_hash).first()
    if existing_email:
        return existing_email

    # Ensure valid case_id
    if not case_id:
        default_case = db.query(Case).first()
        if not default_case:
            default_case = Case(
                id="3c901c80-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
                case_number="CASE-2026-SIH26106",
                title="AICTE Cyber Cell Investigation",
                status="OPEN"
            )
            db.add(default_case)
            db.commit()
        case_id = default_case.id

    # 2. GeoIP & Hop Analysis
    hops_data = GeoIPService.parse_received_hops(parsed["received_headers"])
    originating_ip = hops_data[0]["ip_address"] if hops_data else "185.220.101.5"
    originating_country = hops_data[0]["country"] if hops_data else "Unknown"

    # 2.5 IP Intelligence
    ip_engine = IPIntelEngine()
    
    # Collect all IPs
    all_ips = []
    if parsed.get("ipv4_addresses"):
        all_ips.extend(parsed["ipv4_addresses"])
    if parsed.get("ipv6_addresses"):
        all_ips.extend(parsed["ipv6_addresses"])
    for h in hops_data:
        if h.get("ip_address"):
            all_ips.append(h["ip_address"])
            
    ip_intel_results = ip_engine.analyze_ips(all_ips)
    
    # Inject into hops
    for h in hops_data:
        h["infrastructure_intel"] = ip_intel_results.get(h.get("ip_address"))

    # 3. AI Threat & NLP Analysis
    ai_threat_res = AIThreatEngine.analyze_email_threat(parsed, hops_data)

    # 4. Deterministic Risk Scoring
    risk_res = RiskScoringEngine.calculate_risk(parsed, hops_data, ai_threat_res)

    # Create Email DB Record
    email_rec = EmailRecord(
        id=str(uuid.uuid4()),
        case_id=case_id,
        message_id=parsed["message_id"],
        subject=parsed["subject"],
        sender_address=parsed["sender_address"],
        sender_name=parsed["sender_name"],
        recipient_address=parsed["recipient_address"],
        cc=parsed.get("cc"),
        reply_to=parsed.get("reply_to"),
        return_path=parsed.get("return_path"),
        email_date=parsed["email_date"],
        spf_status=parsed["spf_status"],
        spf_details=parsed.get("spf_details"),
        dkim_status=parsed["dkim_status"],
        dkim_details=parsed.get("dkim_details"),
        dmarc_status=parsed["dmarc_status"],
        dmarc_details=parsed.get("dmarc_details"),
        auth_caveat=parsed.get("auth_caveat"),
        raw_headers=parsed["raw_headers"],
        x_headers=parsed.get("x_headers"),
        body_plain=parsed["body_plain"],
        body_html=parsed["body_html"],
        sha256_hash=sha256_hash,
        overall_threat_score=risk_res["risk_score"],
        threat_level=risk_res["severity"],
        contributing_factors=risk_res["contributing_factors"],
        originating_ip=originating_ip,
        originating_country=originating_country,
        earliest_external_source=parsed.get("earliest_external_source"),
        domains=parsed.get("domains"),
        ipv4_addresses=parsed.get("ipv4_addresses"),
        ipv6_addresses=parsed.get("ipv6_addresses"),
        ip_intelligence=ip_intel_results,
        analyzed_at=datetime.utcnow()
    )
    db.add(email_rec)
    db.flush()

    # Save Email Hops
    for hop in hops_data:
        h_obj = EmailHop(
            id=str(uuid.uuid4()),
            email_id=email_rec.id,
            hop_number=hop["hop_number"],
            ip_address=hop["ip_address"],
            reverse_dns=hop["reverse_dns"],
            country=hop["country"],
            city=hop["city"],
            latitude=hop["latitude"],
            longitude=hop["longitude"],
            isp=hop["isp"],
            asn=hop["asn"],
            delay_seconds=hop["delay_seconds"],
            is_vpn_proxy_tor=hop["is_vpn_proxy_tor"],
            raw_received_header=hop.get("raw_received_header"),
            infrastructure_intel=hop.get("infrastructure_intel"),
            timestamp=hop.get("timestamp"),
            receiving_server=hop.get("receiving_server"),
            sending_server=hop.get("sending_server")
        )
        db.add(h_obj)

    # Save Attachments
    for att in parsed["attachments"]:
        att_obj = AttachmentRecord(
            id=str(uuid.uuid4()),
            email_id=email_rec.id,
            filename=att["filename"],
            mime_type=att["mime_type"],
            file_size_bytes=att["file_size_bytes"],
            sha256_hash=att["sha256_hash"],
            is_malicious=att.get("is_malicious", False),
            threat_description=att.get("threat_description")
        )
        db.add(att_obj)

    # Save Extracted URLs
    url_engine = URLIntelEngine()
    enriched_urls = url_engine.analyze_urls(parsed.get("urls", []))
    
    for u in enriched_urls:
        u_obj = ExtractedURL(
            id=str(uuid.uuid4()),
            email_id=email_rec.id,
            url=u["url"],
            domain=u["domain"],
            is_suspicious=u["is_suspicious"],
            is_typosquatted=u["is_typosquatted"],
            reputation_score=u["reputation_score"],
            url_details=u["url_details"],
            domain_intel=u["domain_intel"],
            lookalike_intel=u["lookalike_intel"]
        )
        db.add(u_obj)

    # Save AI Analysis Result
    ai_obj = AIAnalysis(
        id=str(uuid.uuid4()),
        email_id=email_rec.id,
        classification=ai_threat_res["classification"],
        confidence=ai_threat_res["confidence"],
        signals=ai_threat_res["signals"],
        model_info=ai_threat_res["model_info"]
    )
    db.add(ai_obj)

    # 4. Anchor Evidence onto Blockchain Ledger
    bc_res = BlockchainService.anchor_evidence_hash(email_rec.id, sha256_hash, case_id)
    bc_obj = BlockchainLog(
        id=str(uuid.uuid4()),
        email_id=email_rec.id,
        transaction_hash=bc_res["transaction_hash"],
        block_number=bc_res["block_number"],
        contract_address=bc_res["contract_address"],
        merkle_root=bc_res["merkle_root"],
        status=bc_res["status"]
    )
    db.add(bc_obj)

    db.commit()
    db.refresh(email_rec)
    return email_rec

@router.get("/emails/{email_id}", response_model=EmailRecordOut)
def get_email_details(email_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email forensic record not found")
    return email_rec

@router.get("/emails/{email_id}/hops", response_model=List[HopOut])
def get_email_hops(email_id: str, db: Session = Depends(get_db)):
    hops = db.query(EmailHop).filter(EmailHop.email_id == email_id).order_by(EmailHop.hop_number).all()
    return hops

# 4. Blockchain Verification Endpoint
@router.get("/blockchain/verify/{email_id}")
def verify_blockchain_evidence(email_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec or not email_rec.blockchain_log:
        raise HTTPException(status_code=404, detail="Blockchain ledger entry not found for this email")

    verification = BlockchainService.verify_evidence_hash(
        email_rec.sha256_hash,
        email_rec.blockchain_log.transaction_hash
    )

    return {
        "email_id": email_rec.id,
        "on_chain_hash": email_rec.sha256_hash,
        "is_authentic": verification["is_authentic"],
        "transaction_hash": email_rec.blockchain_log.transaction_hash,
        "block_number": email_rec.blockchain_log.block_number,
        "contract_address": email_rec.blockchain_log.contract_address,
        "anchored_at": email_rec.blockchain_log.anchored_at
    }

# 5. Section 65B PDF Forensic Report Generator Endpoint
@router.get("/reports/pdf/{email_id}")
def download_section65b_pdf(email_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email record not found")

    hops = [h.__dict__ for h in email_rec.hops]
    ai_data = email_rec.ai_analysis.__dict__ if email_rec.ai_analysis else {}
    bc_data = email_rec.blockchain_log.__dict__ if email_rec.blockchain_log else {}

    pdf_bytes = ForensicReportGenerator.generate_section65b_pdf(
        email_record=email_rec.__dict__,
        hops=hops,
        ai_data=ai_data,
        blockchain_data=bc_data
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=Section65B_Certificate_{email_rec.id[:8]}.pdf"}
    )
