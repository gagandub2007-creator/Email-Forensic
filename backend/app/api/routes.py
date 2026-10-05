import uuid
from typing import List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Response, status
from sqlalchemy.orm import Session

from app.models.database import get_db
from app.models.entities import (
    User, Case, EmailRecord, EmailHop, AttachmentRecord,
    ExtractedURL, AIAnalysis, BlockchainLog,
    EvidenceRecord, CustodyEvent, EvidenceLedgerEntry, AuditLog,
)
from app.api.schemas import (
    UserRegister, UserLogin, TokenResponse, CaseCreate, CaseOut,
    EmailRecordOut, HopOut,
    EvidenceRecordOut, EvidenceVerifyOut, CustodyEventOut, CustodyEventCreate,
    EvidenceLedgerEntryOut, LedgerVerifyOut,
)
from app.core.auth import Permission, UserRole, require_permission, get_current_user_context
from app.services.security import SecurityValidator, AuditLogger
from app.services.parser import EmailParserEngine
from app.services.geoip import GeoIPService
from app.services.threat_ai import AIThreatEngine
from app.services.risk_scoring import RiskScoringEngine
from app.services.url_intel import URLIntelEngine
from app.services.ip_intel import IPIntelEngine
from app.services.blockchain import BlockchainService
from app.services.report import ForensicReportGenerator
from app.services.evidence_preservation import (
    compute_sha256, verify_integrity, build_evidence_record, build_custody_event,
)
from app.services.evidence_ledger import get_ledger
from app.services.demo_dataset import DemoDatasetManager, DEMO_DISCLAIMER

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
        filename = file.filename or "uploaded.eml"
        raw_bytes = await file.read()
        try:
            SecurityValidator.validate_file_upload(filename, len(raw_bytes))
        except ValueError as val_err:
            raise HTTPException(status_code=400, detail=str(val_err))
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

    # 5. Evidence Preservation — create evidence record & first custody event
    ev_meta = build_evidence_record(
        evidence_data=raw_bytes,
        case_id=case_id,
        investigation_id=case_id,
        filename=file.filename if file else "raw_text_input.eml",
        collected_by=get_current_user_id(),
    )
    ev_obj = EvidenceRecord(
        id=ev_meta["id"],
        email_id=email_rec.id,
        case_id=ev_meta["case_id"],
        investigation_id=ev_meta["investigation_id"],
        sha256_hash=ev_meta["sha256_hash"],
        filename=ev_meta["filename"],
        file_size_bytes=ev_meta["file_size_bytes"],
        collected_by=ev_meta["collected_by"],
        integrity_status=ev_meta["integrity_status"],
    )
    db.add(ev_obj)
    db.flush()

    custody_evt = build_custody_event(
        evidence_id=ev_obj.id,
        user=get_current_user_id(),
        action="Evidence collected",
    )
    db.add(CustodyEvent(
        id=custody_evt["id"],
        evidence_id=custody_evt["evidence_id"],
        timestamp=custody_evt["timestamp"],
        user=custody_evt["user"],
        action=custody_evt["action"],
    ))

    # 6. Register evidence hash on tamper-evident ledger (Step 17)
    #    Only the hash, evidence ID, and case reference are sent — never raw content.
    ledger = get_ledger()
    ledger_rec = ledger.register(
        evidence_id=ev_obj.id,
        evidence_hash=ev_meta["sha256_hash"],
        case_reference=case_id,
    )
    ledger_obj = EvidenceLedgerEntry(
        id=str(uuid.uuid4()),
        evidence_id=ev_obj.id,
        ledger_tx_id=ledger_rec["ledger_tx_id"],
        evidence_hash=ledger_rec["evidence_hash"],
        case_reference=ledger_rec["case_reference"],
        block_number=ledger_rec["block_number"],
        prev_block_hash=ledger_rec.get("prev_block_hash"),
        merkle_root=ledger_rec.get("merkle_root"),
        contract_address=ledger_rec.get("contract_address"),
        verification_status="Verified",
        ledger_status=ledger_rec["status"],
    )
    db.add(ledger_obj)

    db.commit()
    db.refresh(email_rec)

    AuditLogger.log_action(
        db,
        user_id=get_current_user_id(),
        user_role="INVESTIGATOR",
        action="Analyze Email",
        resource_type="EmailRecord",
        resource_id=email_rec.id,
        details=f"Analyzed email '{email_rec.subject}' with threat score {email_rec.overall_threat_score}",
    )

    return email_rec

@router.get("/emails/{email_id}", response_model=EmailRecordOut)
def get_email_details(email_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email forensic record not found")
    
    # Sanitize HTML body for XSS safety
    if email_rec.body_html:
        email_rec.body_html = SecurityValidator.sanitize_email_html(email_rec.body_html)

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

    ev_rec = db.query(EvidenceRecord).filter(EvidenceRecord.email_id == email_id).first()
    evidence_dict = ev_rec.__dict__ if ev_rec else None
    custody_events = [c.__dict__ for c in ev_rec.custody_events] if ev_rec else []
    ledger_entry = ev_rec.ledger_entry.__dict__ if ev_rec and ev_rec.ledger_entry else None
    urls = [u.__dict__ for u in email_rec.urls]
    attachments = [a.__dict__ for a in email_rec.attachments]

    pdf_bytes = ForensicReportGenerator.generate_full_report_pdf(
        email_record=email_rec.__dict__,
        hops=hops,
        ai_data=ai_data,
        blockchain_data=bc_data,
        evidence_record=evidence_dict,
        custody_events=custody_events,
        ledger_entry=ledger_entry,
        urls=urls,
        attachments=attachments,
        case_id=email_rec.case_id or "CASE-2026-DEFAULT",
        investigation_id=email_rec.case_id or "",
    )

    # Record custody event: Report generated
    if ev_rec:
        try:
            rpt_evt = build_custody_event(
                evidence_id=ev_rec.id,
                user=get_current_user_id(),
                action="Report generated",
            )
            db.add(CustodyEvent(
                id=rpt_evt["id"],
                evidence_id=rpt_evt["evidence_id"],
                timestamp=rpt_evt["timestamp"],
                user=rpt_evt["user"],
                action=rpt_evt["action"],
            ))
            db.commit()
        except Exception:
            db.rollback()

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"inline; filename=Forensic_Report_{email_id[:8]}.pdf"},
    )


@router.get("/reports/preview/{email_id}")
def get_report_preview(email_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email record not found")

    ev_rec = db.query(EvidenceRecord).filter(EvidenceRecord.email_id == email_id).first()
    ai_data = email_rec.ai_analysis.__dict__ if email_rec.ai_analysis else {}
    ledger_entry = ev_rec.ledger_entry if ev_rec else None

    return {
        "email_id": email_rec.id,
        "case_id": email_rec.case_id,
        "subject": email_rec.subject,
        "sender_address": email_rec.sender_address,
        "recipient_address": email_rec.recipient_address,
        "threat_level": email_rec.threat_level,
        "overall_threat_score": email_rec.overall_threat_score,
        "ai_classification": ai_data.get("classification", "N/A"),
        "ai_confidence": ai_data.get("confidence", 0),
        "evidence_id": ev_rec.id if ev_rec else None,
        "sha256_hash": ev_rec.sha256_hash if ev_rec else email_rec.sha256_hash,
        "integrity_status": ev_rec.integrity_status if ev_rec else "Unverified",
        "ledger_tx_id": ledger_entry.ledger_tx_id if ledger_entry else None,
        "ledger_status": ledger_entry.ledger_status if ledger_entry else "N/A",
        "custody_event_count": len(ev_rec.custody_events) if ev_rec else 0,
        "sections": [
            "1. Case Information",
            "2. Executive Summary",
            "3. Email Details",
            "4. Threat Classification",
            "5. Risk Assessment",
            "6. Header Analysis",
            "7. SPF/DKIM/DMARC",
            "8. URLs and Domains",
            "9. IP and Infrastructure Intelligence",
            "10. Relay Path",
            "11. Historical Correlation",
            "12. Threat Graph Summary",
            "13. Attribution Support",
            "14. Evidence Integrity",
            "15. Chain of Custody",
            "16. Blockchain/Ledger Verification",
            "17. Limitations"
        ]
    }

# ---------------------------------------------------------------
#  6. Evidence Preservation Endpoints (Step 16)
# ---------------------------------------------------------------

@router.get("/evidence/{email_id}", response_model=EvidenceRecordOut)
def get_evidence_for_email(email_id: str, db: Session = Depends(get_db)):
    """Retrieve the evidence record associated with an analyzed email."""
    ev = db.query(EvidenceRecord).filter(EvidenceRecord.email_id == email_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence record not found for this email")

    # Record custody event: Evidence viewed
    view_evt = build_custody_event(
        evidence_id=ev.id,
        user=get_current_user_id(),
        action="Evidence viewed",
    )
    db.add(CustodyEvent(
        id=view_evt["id"],
        evidence_id=view_evt["evidence_id"],
        timestamp=view_evt["timestamp"],
        user=view_evt["user"],
        action=view_evt["action"],
    ))
    db.commit()
    db.refresh(ev)
    return ev


@router.get("/evidence/{evidence_id}/verify", response_model=EvidenceVerifyOut)
def verify_evidence_integrity(
    evidence_id: str,
    db: Session = Depends(get_db),
):
    """Recalculate SHA-256 from the stored email body and compare with the
    stored hash.  Returns ``Verified`` or ``Integrity mismatch``."""
    ev = db.query(EvidenceRecord).filter(EvidenceRecord.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence record not found")

    email_rec = db.query(EmailRecord).filter(EmailRecord.id == ev.email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Associated email record not found")

    # Reconstruct raw bytes from stored body (plain or html fallback)
    body = email_rec.body_plain or email_rec.body_html or ""
    raw_bytes = body.encode("utf-8")

    # Verify against the *email-level* sha256 stored on the evidence record
    result = verify_integrity(raw_bytes, ev.sha256_hash)

    # Update integrity_status on the evidence record
    ev.integrity_status = result["status"]
    db.commit()

    return EvidenceVerifyOut(
        evidence_id=ev.id,
        status=result["status"],
        stored_hash=result["stored_hash"],
        recalculated_hash=result["recalculated_hash"],
        verified_at=result["verified_at"],
        match=result["match"],
    )


@router.get("/evidence/{evidence_id}/custody", response_model=List[CustodyEventOut])
def get_custody_timeline(evidence_id: str, db: Session = Depends(get_db)):
    """Return the full chain-of-custody timeline for a piece of evidence."""
    events = (
        db.query(CustodyEvent)
        .filter(CustodyEvent.evidence_id == evidence_id)
        .order_by(CustodyEvent.timestamp)
        .all()
    )
    return events


@router.post("/evidence/{evidence_id}/custody", response_model=CustodyEventOut, status_code=201)
def add_custody_event(
    evidence_id: str,
    body: CustodyEventCreate,
    db: Session = Depends(get_db),
):
    """Append a new event to the chain-of-custody timeline."""
    ev = db.query(EvidenceRecord).filter(EvidenceRecord.id == evidence_id).first()
    if not ev:
        raise HTTPException(status_code=404, detail="Evidence record not found")

    try:
        evt = build_custody_event(
            evidence_id=evidence_id,
            user=body.user,
            action=body.action,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    obj = CustodyEvent(
        id=evt["id"],
        evidence_id=evt["evidence_id"],
        timestamp=evt["timestamp"],
        user=evt["user"],
        action=evt["action"],
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.get("/evidence", response_model=List[EvidenceRecordOut])
def list_all_evidence(db: Session = Depends(get_db)):
    """List all evidence records."""
    return db.query(EvidenceRecord).order_by(EvidenceRecord.created_at.desc()).all()


# ---------------------------------------------------------------
#  7. Blockchain / Tamper-Evident Ledger Endpoints (Step 17)
# ---------------------------------------------------------------

@router.get("/ledger/{evidence_id}/verify", response_model=LedgerVerifyOut)
def verify_evidence_on_ledger(evidence_id: str, db: Session = Depends(get_db)):
    """Verify an evidence hash against its tamper-evident ledger record.

    Only the hash is checked — no raw content is ever sent to the ledger.
    """
    le = db.query(EvidenceLedgerEntry).filter(
        EvidenceLedgerEntry.evidence_id == evidence_id
    ).first()
    if not le:
        raise HTTPException(status_code=404, detail="Ledger entry not found for this evidence")

    ledger = get_ledger()
    result = ledger.verify(
        evidence_hash=le.evidence_hash,
        ledger_tx_id=le.ledger_tx_id,
    )

    # Persist verification result
    le.verification_status = result["status"]
    db.commit()

    return LedgerVerifyOut(
        evidence_id=evidence_id,
        verified=result["verified"],
        status=result["status"],
        recorded_hash=result["recorded_hash"],
        submitted_hash=result["submitted_hash"],
        block_number=result["block_number"],
        timestamp=result["timestamp"],
        contract_address=result["contract_address"],
    )


@router.get("/ledger/{evidence_id}", response_model=EvidenceLedgerEntryOut)
def get_ledger_entry(evidence_id: str, db: Session = Depends(get_db)):
    """Get the ledger entry for a specific evidence record."""
    le = db.query(EvidenceLedgerEntry).filter(
        EvidenceLedgerEntry.evidence_id == evidence_id
    ).first()
    if not le:
        raise HTTPException(status_code=404, detail="Ledger entry not found")
    return le


@router.get("/ledger", response_model=List[EvidenceLedgerEntryOut])
def list_ledger_entries(db: Session = Depends(get_db)):
    """List all ledger entries."""
    return db.query(EvidenceLedgerEntry).order_by(
        EvidenceLedgerEntry.registered_at.desc()
    ).all()


# ---------------------------------------------------------------
#  8. Application Security & Audit Logs (Step 19)
# ---------------------------------------------------------------

@router.get("/audit-logs")
def list_audit_logs(
    db: Session = Depends(get_db),
    user: dict = Depends(require_permission(Permission.VIEW_AUDIT_LOGS))
):
    """Retrieve system audit logs for security oversight."""
    logs = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
    return [
        {
            "id": l.id,
            "timestamp": l.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC') if l.timestamp else "N/A",
            "user_id": l.user_id,
            "user_role": l.user_role,
            "action": l.action,
            "resource_type": l.resource_type,
            "resource_id": l.resource_id,
            "details": l.details,
            "ip_address": l.ip_address,
            "status": l.status,
        }
        for l in logs
    ]


# ---------------------------------------------------------------
#  9. Forensic Demonstration Dataset Endpoints (Step 20)
# ---------------------------------------------------------------

@router.post("/demo/seed")
def seed_demo_data(db: Session = Depends(get_db)):
    """Seed or reset the 5 realistic forensic demo emails."""
    seeded = DemoDatasetManager.seed_demo_dataset(db)
    return {
        "status": "success",
        "message": "Demo dataset populated with 5 forensic threat scenarios",
        "disclaimer": DEMO_DISCLAIMER,
        "count": len(seeded),
        "demo_email_ids": [e.id for e in seeded],
    }


@router.get("/demo/dataset")
def get_demo_dataset(db: Session = Depends(get_db)):
    """Retrieve the demonstration dataset for quick investigation loading."""
    DemoDatasetManager.seed_demo_dataset(db)
    demo_records = db.query(EmailRecord).filter(
        EmailRecord.id.like("demo-email-%")
    ).all()
    
    return {
        "disclaimer": DEMO_DISCLAIMER,
        "is_demo_data": True,
        "count": len(demo_records),
        "items": [
            {
                "id": r.id,
                "subject": r.subject,
                "sender_address": r.sender_address,
                "recipient_address": r.recipient_address,
                "threat_level": r.threat_level,
                "overall_threat_score": r.overall_threat_score,
                "ai_classification": r.ai_analysis.classification if r.ai_analysis else "N/A",
                "sha256_hash": r.sha256_hash,
                "originating_country": r.originating_country,
                "analyzed_at": r.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC') if r.analyzed_at else "N/A",
            }
            for r in demo_records
        ]
    }
