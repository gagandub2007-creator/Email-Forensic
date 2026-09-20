import uuid
from typing import List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Response, status
from sqlalchemy.orm import Session

from app.models.database import get_db
from app.models.entities import User, Case, EmailRecord, EmailHop, AttachmentRecord, ExtractedURL, AIAnalysis, BlockchainLog
from app.api.schemas import (
    UserRegister, UserLogin, TokenResponse, CaseCreate, CaseUpdate, CaseNoteCreate, CaseOut, EmailRecordOut, HopOut,
    GraphResponse, GraphStatusResponse, CorrelationResponse, AttributionSupportResponse, CreateCaseFromInvestigationIn,
    EvidenceRecordOut, IntegrityCheckResult, LogCustodyActionIn
)
from app.core.config import settings
from app.services.parser import EmailParserEngine
from app.services.geoip import GeoIPService
from app.services.threat_ai import AIThreatEngine
from app.services.risk_scoring import RiskScoringEngine
from app.services.url_intel import URLIntelEngine
from app.services.ip_intel import IPIntelEngine
from app.services.blockchain import BlockchainService
from app.services.report import ForensicReportGenerator
from app.services.graph_service import Neo4jGraphService
from app.services.demo_graph_provider import DemoGraphProvider
from app.services.correlation_service import HistoricalCorrelationEngine
from app.services.attribution_service import AttributionSupportEngine
from app.services.evidence_service import EvidencePreservationService

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

# Helper function to format Case response object
def build_case_out(c: Case) -> dict:
    notes_list = c.notes if isinstance(c.notes, list) else []
    return {
        "id": c.id,
        "case_number": c.case_number,
        "title": c.title,
        "description": c.description,
        "severity": c.severity or "High",
        "status": c.status if c.status in ["Open", "Investigating", "Resolved", "Closed"] else "Open",
        "assigned_analyst": c.assigned_analyst or "Marcus K. (SOC L2 Analyst)",
        "investigation_count": len(c.emails) if c.emails else 0,
        "notes": notes_list,
        "created_at": c.created_at,
        "updated_at": c.updated_at or c.created_at
    }

# 2. Case Management Endpoints
@router.get("/cases", response_model=List[CaseOut])
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(Case).order_by(Case.created_at.desc()).all()
    if not cases:
        # Seed default case if empty
        default_case = Case(
            id="3c901c80-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
            case_number="CASE-2026-SIH26106",
            title="AICTE Cyber Cell Operation Email Shield",
            description="Active investigation into Business Email Compromise and phishing threats.",
            severity="Critical",
            status="Investigating",
            assigned_analyst="Marcus K. (SOC L2 Analyst)",
            notes=[{
                "id": str(uuid.uuid4()),
                "author": "Marcus K. (SOC L2 Analyst)",
                "text": "Initial case opened for multi-vector BEC investigation.",
                "timestamp": datetime.utcnow().isoformat() + "Z"
            }]
        )
        db.add(default_case)
        db.commit()
        cases = [default_case]
    return [build_case_out(c) for c in cases]

@router.post("/cases", response_model=CaseOut)
def create_case(case_in: CaseCreate, db: Session = Depends(get_db)):
    case_num = case_in.case_number or f"CASE-2026-{str(uuid.uuid4())[:8].upper()}"
    new_case = Case(
        id=str(uuid.uuid4()),
        case_number=case_num,
        title=case_in.title,
        description=case_in.description,
        severity=case_in.severity or "High",
        status=case_in.status if case_in.status in ["Open", "Investigating", "Resolved", "Closed"] else "Open",
        assigned_analyst=case_in.assigned_analyst or "Marcus K. (SOC L2 Analyst)",
        user_id=get_current_user_id(),
        notes=[]
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)
    return build_case_out(new_case)

@router.get("/cases/{case_id}", response_model=CaseOut)
def get_case(case_id: str, db: Session = Depends(get_db)):
    case_obj = db.query(Case).filter(Case.id == case_id).first()
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")
    return build_case_out(case_obj)

@router.patch("/cases/{case_id}", response_model=CaseOut)
def update_case(case_id: str, case_update: CaseUpdate, db: Session = Depends(get_db)):
    case_obj = db.query(Case).filter(Case.id == case_id).first()
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")

    if case_update.title is not None:
        case_obj.title = case_update.title
    if case_update.description is not None:
        case_obj.description = case_update.description
    if case_update.status is not None:
        if case_update.status not in ["Open", "Investigating", "Resolved", "Closed"]:
            raise HTTPException(status_code=400, detail="Invalid status. Must be Open, Investigating, Resolved, or Closed")
        case_obj.status = case_update.status
    if case_update.severity is not None:
        if case_update.severity not in ["Low", "Medium", "High", "Critical"]:
            raise HTTPException(status_code=400, detail="Invalid severity. Must be Low, Medium, High, or Critical")
        case_obj.severity = case_update.severity
    if case_update.assigned_analyst is not None:
        case_obj.assigned_analyst = case_update.assigned_analyst

    case_obj.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(case_obj)
    return build_case_out(case_obj)

@router.post("/cases/{case_id}/notes", response_model=CaseOut)
def add_case_note(case_id: str, note_in: CaseNoteCreate, db: Session = Depends(get_db)):
    case_obj = db.query(Case).filter(Case.id == case_id).first()
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")

    existing_notes = case_obj.notes if isinstance(case_obj.notes, list) else []
    new_note = {
        "id": str(uuid.uuid4()),
        "author": note_in.author or "Marcus K. (SOC L2 Analyst)",
        "text": note_in.text,
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }
    updated_notes = existing_notes + [new_note]
    case_obj.notes = updated_notes
    case_obj.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(case_obj)
    return build_case_out(case_obj)

@router.post("/cases/create-from-investigation", response_model=CaseOut)
def create_case_from_investigation(req: CreateCaseFromInvestigationIn, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == req.email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email investigation not found")

    title = req.title or f"Investigation: {email_rec.subject[:80] if email_rec.subject else 'Email Threat'}"
    case_num = f"CASE-2026-{str(uuid.uuid4())[:8].upper()}"

    new_case = Case(
        id=str(uuid.uuid4()),
        case_number=case_num,
        title=title,
        description=f"Case initialized from email investigation '{email_rec.subject}'. Threat Level: {email_rec.threat_level}.",
        severity=req.severity or email_rec.threat_level or "High",
        status=req.status if req.status in ["Open", "Investigating", "Resolved", "Closed"] else "Open",
        assigned_analyst=req.assigned_analyst or "Marcus K. (SOC L2 Analyst)",
        notes=[{
            "id": str(uuid.uuid4()),
            "author": req.assigned_analyst or "Marcus K. (SOC L2 Analyst)",
            "text": f"Case created from investigation {email_rec.id[:8]} with Threat Score {email_rec.overall_threat_score}/100.",
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }]
    )
    db.add(new_case)
    db.flush()

    email_rec.case_id = new_case.id
    db.commit()
    db.refresh(new_case)
    return build_case_out(new_case)

@router.post("/cases/{case_id}/assign-email/{email_id}", response_model=CaseOut)
def assign_email_to_case(case_id: str, email_id: str, db: Session = Depends(get_db)):
    case_obj = db.query(Case).filter(Case.id == case_id).first()
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")

    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email record not found")

    email_rec.case_id = case_obj.id
    case_obj.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(case_obj)
    return build_case_out(case_obj)

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

    # 4.5 Store raw evidence in read-only evidence vault & log chain of custody
    try:
        evidence_filename = file.filename if (file and file.filename) else f"email_{email_rec.id[:8]}.eml"
        EvidencePreservationService.store_raw_evidence(
            db=db,
            email_id=email_rec.id,
            case_id=email_rec.case_id,
            file_name=evidence_filename,
            raw_content=raw_bytes,
            collected_by="SOC Lead Investigator"
        )
    except Exception as e:
        # Avoid crashing email analysis if vault write has minor error
        pass

    # 5. Sync to Neo4j Threat Relationship Graph (if available)
    try:
        graph_service = Neo4jGraphService()
        if graph_service.is_available():
            email_dict = email_rec.__dict__
            hops_dicts = [h.__dict__ for h in email_rec.hops]
            urls_dicts = [u.__dict__ for u in email_rec.urls]
            case_dict = email_rec.case.__dict__ if email_rec.case else None
            graph_service.sync_email_graph(
                email_record=email_dict,
                hops=hops_dicts,
                urls=urls_dicts,
                case_data=case_dict
            )
    except Exception as e:
        # Non-blocking graph sync attempt
        pass

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

# 6. Neo4j Threat Relationship Graph Endpoints
@router.get("/graph/status", response_model=GraphStatusResponse)
def get_graph_status():
    graph_service = Neo4jGraphService()
    is_connected = graph_service.is_available()
    return GraphStatusResponse(
        is_neo4j_connected=is_connected,
        provider_mode="NEO4J_LIVE" if is_connected else "DEMO_FALLBACK",
        neo4j_uri=settings.NEO4J_URI,
        neo4j_database=settings.NEO4J_DATABASE
    )

@router.get("/graph/email/{email_id}", response_model=GraphResponse)
def get_email_threat_graph(email_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email record not found")

    graph_service = Neo4jGraphService()
    # Try fetching from live Neo4j first
    if graph_service.is_available():
        live_graph = graph_service.get_email_graph(email_id)
        if live_graph:
            return live_graph

    # Fallback to Demo Graph Provider
    email_dict = email_rec.__dict__
    hops = [h.__dict__ for h in email_rec.hops]
    urls = [u.__dict__ for u in email_rec.urls]
    case_dict = email_rec.case.__dict__ if email_rec.case else None

    demo_graph = DemoGraphProvider.generate_graph_from_email_data(
        email_dict=email_dict,
        hops=hops,
        urls=urls,
        case_dict=case_dict
    )
    return demo_graph

@router.get("/graph/case/{case_id}", response_model=GraphResponse)
def get_case_threat_graph(case_id: str, db: Session = Depends(get_db)):
    case_obj = db.query(Case).filter(Case.id == case_id).first()
    if not case_obj:
        raise HTTPException(status_code=404, detail="Case not found")

    emails = db.query(EmailRecord).filter(EmailRecord.case_id == case_id).all()
    if not emails:
        raise HTTPException(status_code=404, detail="No emails found for this case")

    # Combine nodes & edges across all emails in the case
    all_nodes = []
    all_edges = []
    seen_nodes = set()
    seen_edges = set()

    for email_rec in emails:
        email_dict = email_rec.__dict__
        hops = [h.__dict__ for h in email_rec.hops]
        urls = [u.__dict__ for u in email_rec.urls]
        sub_graph = DemoGraphProvider.generate_graph_from_email_data(
            email_dict=email_dict,
            hops=hops,
            urls=urls,
            case_dict=case_obj.__dict__
        )
        for n in sub_graph["nodes"]:
            if n["id"] not in seen_nodes:
                seen_nodes.add(n["id"])
                all_nodes.append(n)
        for e in sub_graph["edges"]:
            if e["id"] not in seen_edges:
                seen_edges.add(e["id"])
                all_edges.append(e)

    graph_service = Neo4jGraphService()
    is_connected = graph_service.is_available()

    return GraphResponse(
        provider_mode="NEO4J_LIVE" if is_connected else "DEMO_FALLBACK",
        is_neo4j_connected=is_connected,
        note="Case Multi-Email Threat Graph",
        nodes=all_nodes,
        edges=all_edges
    )

@router.post("/graph/sync/{email_id}")
def sync_email_to_neo4j(email_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email record not found")

    graph_service = Neo4jGraphService()
    if not graph_service.is_available():
        return {
            "success": False,
            "provider_mode": "DEMO_FALLBACK",
            "message": "Neo4j is not connected. Data remains available via Demo Graph Provider."
        }

    email_dict = email_rec.__dict__
    hops = [h.__dict__ for h in email_rec.hops]
    urls = [u.__dict__ for u in email_rec.urls]
    case_dict = email_rec.case.__dict__ if email_rec.case else None

    synced = graph_service.sync_email_graph(
        email_record=email_dict,
        hops=hops,
        urls=urls,
        case_data=case_dict
    )
    return {
        "success": synced,
        "provider_mode": "NEO4J_LIVE" if synced else "DEMO_FALLBACK",
        "message": "Successfully synced email entities to Neo4j graph" if synced else "Failed to sync to Neo4j"
    }

# 7. Historical Threat Correlation Endpoint
@router.get("/emails/{email_id}/correlations", response_model=CorrelationResponse)
def get_email_historical_correlations(email_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email record not found")

    correlation_res = HistoricalCorrelationEngine.correlate_email(email_id=email_id, db=db)
    return correlation_res

# 8. Attribution-Support Analysis Endpoint
@router.get("/emails/{email_id}/attribution-support", response_model=AttributionSupportResponse)
def get_email_attribution_support(email_id: str, db: Session = Depends(get_db)):
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
    if not email_rec:
        raise HTTPException(status_code=404, detail="Email record not found")

    hops = [h.__dict__ for h in email_rec.hops]
    attribution_res = AttributionSupportEngine.analyze_attribution_support(
        email_record=email_rec.__dict__,
        hops=hops
    )
    return attribution_res

# 9. Evidence Preservation & Chain of Custody Endpoints
@router.get("/emails/{email_id}/evidence", response_model=EvidenceRecordOut)
def get_evidence_by_email(email_id: str, db: Session = Depends(get_db)):
    record = EvidencePreservationService.get_evidence_by_email(db, email_id)
    if not record:
        # Auto-create fallback evidence record if raw email missing in vault
        email_rec = db.query(EmailRecord).filter(EmailRecord.id == email_id).first()
        if not email_rec:
            raise HTTPException(status_code=404, detail="Email investigation not found")
        fallback_bytes = (email_rec.raw_headers or "").encode("utf-8") + b"\n\n" + (email_rec.body_plain or "").encode("utf-8")
        record = EvidencePreservationService.store_raw_evidence(
            db=db,
            email_id=email_rec.id,
            case_id=email_rec.case_id,
            file_name=f"investigation_{email_rec.id[:8]}.eml",
            raw_content=fallback_bytes,
            collected_by="SOC Lead Investigator"
        )
    return record

@router.get("/evidence/{evidence_id}", response_model=EvidenceRecordOut)
def get_evidence(evidence_id: str, db: Session = Depends(get_db)):
    record = EvidencePreservationService.get_evidence_by_id(db, evidence_id)
    if not record:
        raise HTTPException(status_code=404, detail="Evidence record not found")
    return record

@router.post("/evidence/verify/{evidence_id}", response_model=IntegrityCheckResult)
def verify_evidence_integrity(evidence_id: str, db: Session = Depends(get_db)):
    res = EvidencePreservationService.verify_evidence_integrity(db, evidence_id, user="SOC Investigator")
    return res

@router.post("/evidence/{evidence_id}/log-action", response_model=EvidenceRecordOut)
def log_custody_action(evidence_id: str, payload: LogCustodyActionIn, db: Session = Depends(get_db)):
    record = EvidencePreservationService.log_custody_action(
        db=db,
        evidence_id=evidence_id,
        user=payload.user,
        action=payload.action
    )
    if not record:
        raise HTTPException(status_code=404, detail="Evidence record not found")
    return record




