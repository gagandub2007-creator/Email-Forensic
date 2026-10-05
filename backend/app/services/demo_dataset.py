"""
STEP 20 — Realistic Demonstration Dataset Engine

Provides 5 forensic demo emails covering key cyber threat scenarios:
    1. Legitimate Business Email (Clean authentication, normal domain)
    2. Credential Phishing Email (Microsoft 365 spoofing, credential request, Nederland Tor IP)
    3. CEO/Executive Impersonation (BEC) (David Miller CEO display-name, Reply-To mismatch, urgent wire transfer)
    4. Fake Invoice / Payment Diversion (Vendor billing scam, suspicious domain, offshore bank instructions)
    5. Malicious Link Email (HR Benefits typosquatted domain, credential harvester)

All entries are explicitly flagged as DEMO DATA and populated with complete evidence,
chain-of-custody logs, and tamper-evident ledger records.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models.entities import (
    Case, EmailRecord, EmailHop, AttachmentRecord, ExtractedURL,
    AIAnalysis, BlockchainLog, EvidenceRecord, CustodyEvent, EvidenceLedgerEntry, AuditLog
)
from app.services.evidence_preservation import compute_sha256, build_custody_event
from app.services.evidence_ledger import get_ledger

DEMO_DISCLAIMER = "DEMO DATA: Simulated digital forensics data for SIH 2026 PS ID: 26106 evaluation. Not real-world intelligence."

DEMO_EMAILS_SPEC = [
    {
        "id": "demo-email-01-legit",
        "subject": "[DEMO DATA] Q4 Product Strategy & Security Roadmap Sync",
        "sender_name": "Sarah Jenkins",
        "sender_address": "sjenkins@acmecorp.com",
        "recipient_address": "investigations@cybercell.gov.in",
        "cc": "management@acmecorp.com",
        "reply_to": "sjenkins@acmecorp.com",
        "return_path": "sjenkins@acmecorp.com",
        "email_date": datetime.now(timezone.utc) - timedelta(hours=12),
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "raw_headers": (
            "Received: from mail-ej1-f42.google.com (mail-ej1-f42.google.com [209.85.218.42])\n"
            "    by mx.cybercell.gov.in with ESMTPS id 8192abc\n"
            "    for <investigations@cybercell.gov.in>; Mon, 05 Oct 2026 10:15:00 +0000\n"
            "From: Sarah Jenkins <sjenkins@acmecorp.com>\n"
            "To: investigations@cybercell.gov.in\n"
            "Subject: [DEMO DATA] Q4 Product Strategy & Security Roadmap Sync\n"
            "Date: Mon, 05 Oct 2026 10:15:00 +0000\n"
            "Authentication-Results: mx.cybercell.gov.in; spf=pass; dkim=pass; dmarc=pass\n"
        ),
        "body_plain": (
            "Hi Team,\n\n"
            "Attached is the finalized Q4 product strategy and security roadmap for your review.\n"
            "Please review Section 3 regarding API security hardening prior to our Thursday sync.\n\n"
            "Best regards,\nSarah Jenkins\nDirector of Product, Acme Corp"
        ),
        "body_html": "<p>Hi Team,</p><p>Attached is the finalized Q4 product strategy and security roadmap for your review.</p><p>Best regards,<br/><strong>Sarah Jenkins</strong><br/>Director of Product, Acme Corp</p>",
        "overall_threat_score": 5,
        "threat_level": "LOW",
        "contributing_factors": ["Clean SPF/DKIM/DMARC authentication", "Known corporate domain", "No suspicious links or executables"],
        "originating_ip": "209.85.218.42",
        "originating_country": "United States",
        "hops": [
            {
                "hop_number": 1,
                "ip_address": "209.85.218.42",
                "reverse_dns": "mail-ej1-f42.google.com",
                "country": "United States",
                "city": "Mountain View",
                "isp": "Google LLC",
                "asn": "AS15169",
                "delay_seconds": 1,
                "is_vpn_proxy_tor": False,
                "sending_server": "mail-ej1-f42.google.com",
                "receiving_server": "mx.cybercell.gov.in"
            }
        ],
        "urls": [
            {
                "url": "https://acmecorp.com/roadmap/q4-2026",
                "domain": "acmecorp.com",
                "is_suspicious": False,
                "is_typosquatted": False,
                "reputation_score": 98,
                "url_details": {"type": "Corporate Documentation"}
            }
        ],
        "attachments": [],
        "ai_classification": "Legitimate Business Email",
        "ai_confidence": 0.99,
        "ai_signals": ["Valid DKIM signature", "SPF match", "Clean corporate headers"]
    },
    {
        "id": "demo-email-02-phish",
        "subject": "[DEMO DATA] URGENT: Microsoft 365 Password Expiration Notice",
        "sender_name": "Microsoft Security Team",
        "sender_address": "no-reply@account-verify-sec365-update.com",
        "recipient_address": "user.admin@acmecorp.com",
        "cc": None,
        "reply_to": "support@account-verify-sec365-update.com",
        "return_path": "bounce@account-verify-sec365-update.com",
        "email_date": datetime.now(timezone.utc) - timedelta(hours=6),
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "raw_headers": (
            "Received: from vps-nl-node12.untrusted-host.net (185.220.101.5)\n"
            "    by mx.acmecorp.com with SMTP id 9921xyz\n"
            "    for <user.admin@acmecorp.com>; Mon, 05 Oct 2026 14:20:00 +0000\n"
            "From: Microsoft Security Team <no-reply@account-verify-sec365-update.com>\n"
            "To: user.admin@acmecorp.com\n"
            "Subject: [DEMO DATA] URGENT: Microsoft 365 Password Expiration Notice\n"
            "Authentication-Results: mx.acmecorp.com; spf=fail; dkim=fail; dmarc=fail\n"
        ),
        "body_plain": (
            "Your Microsoft 365 password expires in 2 hours.\n"
            "To retain access to your corporate emails and SharePoint files, you must immediately re-authenticate at:\n"
            "https://account-verify-sec365-update.com/login/auth-ref-9821\n\n"
            "Failure to verify will result in immediate mailbox suspension."
        ),
        "body_html": (
            "<div style='font-family:sans-serif; padding:15px; border:1px solid #ccc;'>"
            "<h3 style='color:#d9534f;'>Microsoft 365 Security Alert</h3>"
            "<p>Your Microsoft 365 password expires in 2 hours.</p>"
            "<p><a href='https://account-verify-sec365-update.com/login/auth-ref-9821' style='background:#0078d4; color:#fff; padding:10px 15px; text-decoration:none;'>Keep Same Password & Verify Now</a></p>"
            "</div>"
        ),
        "overall_threat_score": 94,
        "threat_level": "CRITICAL",
        "contributing_factors": [
            "SPF & DKIM authentication failed",
            "Originating IP (185.220.101.5) is a known Tor Exit Node in Netherlands",
            "Typosquatted domain impersonating Microsoft 365",
            "Credential harvesting link detected"
        ],
        "originating_ip": "185.220.101.5",
        "originating_country": "Netherlands",
        "hops": [
            {
                "hop_number": 1,
                "ip_address": "185.220.101.5",
                "reverse_dns": "tor-exit-node-nl.privacy-net.org",
                "country": "Netherlands",
                "city": "Amsterdam",
                "isp": "M247 Europe S.R.L.",
                "asn": "AS9009",
                "delay_seconds": 4,
                "is_vpn_proxy_tor": True,
                "sending_server": "vps-nl-node12.untrusted-host.net",
                "receiving_server": "mx.acmecorp.com"
            }
        ],
        "urls": [
            {
                "url": "https://account-verify-sec365-update.com/login/auth-ref-9821",
                "domain": "account-verify-sec365-update.com",
                "is_suspicious": True,
                "is_typosquatted": True,
                "reputation_score": 12,
                "url_details": {"type": "Credential Harvester / Phishing"}
            }
        ],
        "attachments": [],
        "ai_classification": "Credential Phishing",
        "ai_confidence": 0.98,
        "ai_signals": ["Brand impersonation (Microsoft 365)", "Urgency language ('expires in 2 hours')", "Tor exit node origin", "Authentication failure"]
    },
    {
        "id": "demo-email-03-bec",
        "subject": "[DEMO DATA] CONFIDENTIAL: Urgent Wire Transfer Required for Project Alpha Acquisition",
        "sender_name": "David Miller (CEO)",
        "sender_address": "ceo.david.miller@executive-mail-portal.org",
        "recipient_address": "finance@acmecorp.com",
        "cc": None,
        "reply_to": "david.miller.private101@gmail.com",
        "return_path": "bounce@executive-mail-portal.org",
        "email_date": datetime.now(timezone.utc) - timedelta(hours=3),
        "spf_status": "SOFTFAIL",
        "dkim_status": "NONE",
        "dmarc_status": "FAIL",
        "raw_headers": (
            "Received: from host-45-142-214-120.bulletproof-vps.com (45.142.214.120)\n"
            "    by mx.acmecorp.com with ESMTP id 7781bec\n"
            "    for <finance@acmecorp.com>; Mon, 05 Oct 2026 17:10:00 +0000\n"
            "From: David Miller (CEO) <ceo.david.miller@executive-mail-portal.org>\n"
            "Reply-To: david.miller.private101@gmail.com\n"
            "To: finance@acmecorp.com\n"
            "Subject: [DEMO DATA] CONFIDENTIAL: Urgent Wire Transfer Required for Project Alpha Acquisition\n"
            "Authentication-Results: mx.acmecorp.com; spf=softfail; dmarc=fail\n"
        ),
        "body_plain": (
            "Hi Finance Team,\n\n"
            "I am currently in closed-door M&A negotiations for Project Alpha.\n"
            "I need an urgent wire transfer of $145,000 processed immediately to secure the acquisition deposit.\n\n"
            "Do NOT call me or discuss this with anyone as this is under strict SEC NDA.\n"
            "Reply directly to this email for wire instructions.\n\n"
            "David Miller\nChief Executive Officer, Acme Corp"
        ),
        "body_html": "<p>Hi Finance Team,</p><p>I am currently in closed-door M&A negotiations for Project Alpha.</p><p>I need an urgent wire transfer of <strong>$145,000</strong> processed immediately to secure the acquisition deposit.</p><p><em>Do NOT call me or discuss this with anyone as this is under strict SEC NDA.</em></p><p>David Miller<br/>CEO, Acme Corp</p>",
        "overall_threat_score": 91,
        "threat_level": "CRITICAL",
        "contributing_factors": [
            "Executive display-name impersonation ('David Miller (CEO)')",
            "Reply-To header mismatch (david.miller.private101@gmail.com)",
            "Urgent payment/wire request without purchase order",
            "Secrecy/isolation tactics ('Do NOT call me')",
            "Originating IP (45.142.214.120) flagged for bulletproof hosting in Russia"
        ],
        "originating_ip": "45.142.214.120",
        "originating_country": "Russian Federation",
        "hops": [
            {
                "hop_number": 1,
                "ip_address": "45.142.214.120",
                "reverse_dns": "host-45-142-214-120.bulletproof-vps.com",
                "country": "Russian Federation",
                "city": "Moscow",
                "isp": "ChangeNet Ltd",
                "asn": "AS49392",
                "delay_seconds": 2,
                "is_vpn_proxy_tor": True,
                "sending_server": "host-45-142-214-120.bulletproof-vps.com",
                "receiving_server": "mx.acmecorp.com"
            }
        ],
        "urls": [],
        "attachments": [],
        "ai_classification": "Business Email Compromise (BEC) / Executive Impersonation",
        "ai_confidence": 0.96,
        "ai_signals": ["Reply-To mismatch", "CEO impersonation", "High urgency financial request", "Secrecy demand"]
    },
    {
        "id": "demo-email-04-invoice",
        "subject": "[DEMO DATA] Overdue Invoice #INV-2026-8819 - Updated Offshore Settlement Instructions",
        "sender_name": "Global Vendor Billing",
        "sender_address": "billing@vendor-supplies-global.co.uk",
        "recipient_address": "ap-dept@acmecorp.com",
        "cc": "accounts@acmecorp.com",
        "reply_to": "payments@vendor-supplies-global.co.uk",
        "return_path": "bounce@vendor-supplies-global.co.uk",
        "email_date": datetime.now(timezone.utc) - timedelta(hours=8),
        "spf_status": "PASS",
        "dkim_status": "NONE",
        "dmarc_status": "FAIL",
        "raw_headers": (
            "Received: from mail.vendor-supplies-global.co.uk (194.26.29.110)\n"
            "    by mx.acmecorp.com with ESMTP id 4412inv\n"
            "    for <ap-dept@acmecorp.com>; Mon, 05 Oct 2026 12:40:00 +0000\n"
            "From: Global Vendor Billing <billing@vendor-supplies-global.co.uk>\n"
            "To: ap-dept@acmecorp.com\n"
            "Subject: [DEMO DATA] Overdue Invoice #INV-2026-8819 - Updated Offshore Settlement Instructions\n"
        ),
        "body_plain": (
            "Dear Accounts Payable,\n\n"
            "Please find attached overdue Invoice #INV-2026-8819 for $68,400.\n"
            "Note: Our UK banking partner is currently undergoing audit maintenance.\n"
            "Please process this payment to our updated offshore account details specified in the attached PDF.\n\n"
            "Thank you,\nGlobal Vendor Supplies Ltd"
        ),
        "body_html": "<p>Dear Accounts Payable,</p><p>Please find attached overdue Invoice #INV-2026-8819 for <strong>$68,400</strong>.</p><p>Note: Our UK banking partner is undergoing audit maintenance. Please remit to our updated offshore account instructions attached.</p>",
        "overall_threat_score": 86,
        "threat_level": "HIGH",
        "contributing_factors": [
            "Newly registered domain (vendor-supplies-global.co.uk registered 2 days ago)",
            "Bank account change request for existing vendor",
            "DKIM missing, DMARC failed",
            "Suspicious IP infrastructure (194.26.29.110 in Romania)"
        ],
        "originating_ip": "194.26.29.110",
        "originating_country": "Romania",
        "hops": [
            {
                "hop_number": 1,
                "ip_address": "194.26.29.110",
                "reverse_dns": "vps-ro-194.hosting-provider.ro",
                "country": "Romania",
                "city": "Bucharest",
                "isp": "Voxility S.R.L.",
                "asn": "AS39743",
                "delay_seconds": 3,
                "is_vpn_proxy_tor": False,
                "sending_server": "mail.vendor-supplies-global.co.uk",
                "receiving_server": "mx.acmecorp.com"
            }
        ],
        "urls": [],
        "attachments": [
            {
                "filename": "Invoice_INV20268819_Updated_BankDetails.pdf",
                "mime_type": "application/pdf",
                "file_size_bytes": 142080,
                "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "is_malicious": True,
                "threat_description": "Contains offshore wire transfer diversion instructions & embedded malicious macro script"
            }
        ],
        "ai_classification": "Fake Invoice / Payment Diversion Phishing",
        "ai_confidence": 0.94,
        "ai_signals": ["New domain registration", "Bank detail modification request", "Offshore payment diversion"]
    },
    {
        "id": "demo-email-05-malware-link",
        "subject": "[DEMO DATA] Security Action Required: Employee Benefits Portal Upgrade",
        "sender_name": "HR Benefits Operations",
        "sender_address": "hr-notice@internal-benefits-acme-update.net",
        "recipient_address": "all-employees@acmecorp.com",
        "cc": None,
        "reply_to": "support@internal-benefits-acme-update.net",
        "return_path": "bounce@internal-benefits-acme-update.net",
        "email_date": datetime.now(timezone.utc) - timedelta(hours=1),
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "raw_headers": (
            "Received: from relay.badactor-net.com (103.251.167.20)\n"
            "    by mx.acmecorp.com with ESMTP id 1120mal\n"
            "    for <all-employees@acmecorp.com>; Mon, 05 Oct 2026 19:10:00 +0000\n"
            "From: HR Benefits Operations <hr-notice@internal-benefits-acme-update.net>\n"
            "To: all-employees@acmecorp.com\n"
            "Subject: [DEMO DATA] Security Action Required: Employee Benefits Portal Upgrade\n"
        ),
        "body_plain": (
            "Dear Employees,\n\n"
            "Our annual benefits open-enrollment portal has been upgraded.\n"
            "To confirm your 2026 healthcare elections and prevent coverage lapse, log in here:\n"
            "http://login-acmecorp-hr.com/update/credential-harvest\n\n"
            "HR Operations Team"
        ),
        "body_html": "<p>Dear Employees,</p><p>Our annual benefits portal has been upgraded.</p><p><a href='http://login-acmecorp-hr.com/update/credential-harvest'>Click here to update your benefits elections</a></p>",
        "overall_threat_score": 96,
        "threat_level": "CRITICAL",
        "contributing_factors": [
            "Typosquatted domain (login-acmecorp-hr.com)",
            "HTTP unencrypted connection for sensitive credential entry",
            "SPF/DKIM/DMARC authentication failed",
            "Originating IP (103.251.167.20) in Vietnam on threat intelligence blacklist"
        ],
        "originating_ip": "103.251.167.20",
        "originating_country": "Vietnam",
        "hops": [
            {
                "hop_number": 1,
                "ip_address": "103.251.167.20",
                "reverse_dns": "relay.badactor-net.com",
                "country": "Vietnam",
                "city": "Hanoi",
                "isp": "VNPT Corp",
                "asn": "AS45899",
                "delay_seconds": 5,
                "is_vpn_proxy_tor": True,
                "sending_server": "relay.badactor-net.com",
                "receiving_server": "mx.acmecorp.com"
            }
        ],
        "urls": [
            {
                "url": "http://login-acmecorp-hr.com/update/credential-harvest",
                "domain": "login-acmecorp-hr.com",
                "is_suspicious": True,
                "is_typosquatted": True,
                "reputation_score": 8,
                "url_details": {"type": "Credential Harvester / Typosquat"}
            }
        ],
        "attachments": [],
        "ai_classification": "Malicious Link / Credential Harvester",
        "ai_confidence": 0.99,
        "ai_signals": ["Typosquatted corporate HR domain", "Unencrypted HTTP link", "Blacklisted originating IP"]
    }
]


class DemoDatasetManager:
    """Populates and resets the realistic forensic demo dataset."""

    @classmethod
    def seed_demo_dataset(cls, db: Session) -> List[EmailRecord]:
        """Seed or update all 5 demo emails with complete evidence & ledger records."""
        # 1. Ensure Default Case
        default_case = db.query(Case).filter(Case.case_number == "CASE-2026-DEMO").first()
        if not default_case:
            default_case = Case(
                id="case-2026-demo-uuid",
                case_number="CASE-2026-DEMO",
                title="SIH 2026 Forensic Demonstration Case",
                description=DEMO_DISCLAIMER,
                status="OPEN",
            )
            db.add(default_case)
            db.flush()

        seeded_records = []
        ledger = get_ledger()

        for spec in DEMO_EMAILS_SPEC:
            # Check existing
            email_rec = db.query(EmailRecord).filter(EmailRecord.id == spec["id"]).first()
            raw_bytes = spec["body_plain"].encode("utf-8")
            sha_hash = compute_sha256(raw_bytes)

            if not email_rec:
                email_rec = EmailRecord(
                    id=spec["id"],
                    case_id=default_case.id,
                    message_id=f"msg-{spec['id']}@sih2026.demo",
                    subject=spec["subject"],
                    sender_address=spec["sender_address"],
                    sender_name=spec["sender_name"],
                    recipient_address=spec["recipient_address"],
                    cc=spec.get("cc"),
                    reply_to=spec.get("reply_to"),
                    return_path=spec.get("return_path"),
                    email_date=spec["email_date"],
                    spf_status=spec["spf_status"],
                    dkim_status=spec["dkim_status"],
                    dmarc_status=spec["dmarc_status"],
                    raw_headers=spec["raw_headers"],
                    body_plain=spec["body_plain"],
                    body_html=spec["body_html"],
                    sha256_hash=sha_hash,
                    overall_threat_score=spec["overall_threat_score"],
                    threat_level=spec["threat_level"],
                    contributing_factors=spec["contributing_factors"],
                    originating_ip=spec["originating_ip"],
                    originating_country=spec["originating_country"],
                    analyzed_at=datetime.now(timezone.utc),
                )
                db.add(email_rec)
                db.flush()

                # Add Hops
                for h in spec["hops"]:
                    h_obj = EmailHop(
                        id=str(uuid.uuid4()),
                        email_id=email_rec.id,
                        hop_number=h["hop_number"],
                        ip_address=h["ip_address"],
                        reverse_dns=h["reverse_dns"],
                        country=h["country"],
                        city=h["city"],
                        isp=h["isp"],
                        asn=h["asn"],
                        delay_seconds=h["delay_seconds"],
                        is_vpn_proxy_tor=h["is_vpn_proxy_tor"],
                        sending_server=h.get("sending_server"),
                        receiving_server=h.get("receiving_server"),
                    )
                    db.add(h_obj)

                # Add URLs
                for u in spec.get("urls", []):
                    u_obj = ExtractedURL(
                        id=str(uuid.uuid4()),
                        email_id=email_rec.id,
                        url=u["url"],
                        domain=u["domain"],
                        is_suspicious=u["is_suspicious"],
                        is_typosquatted=u["is_typosquatted"],
                        reputation_score=u["reputation_score"],
                        url_details=u["url_details"],
                    )
                    db.add(u_obj)

                # Add Attachments
                for a in spec.get("attachments", []):
                    att_obj = AttachmentRecord(
                        id=str(uuid.uuid4()),
                        email_id=email_rec.id,
                        filename=a["filename"],
                        mime_type=a["mime_type"],
                        file_size_bytes=a["file_size_bytes"],
                        sha256_hash=a["sha256_hash"],
                        is_malicious=a["is_malicious"],
                        threat_description=a.get("threat_description"),
                    )
                    db.add(att_obj)

                # Add AI Analysis
                ai_obj = AIAnalysis(
                    id=str(uuid.uuid4()),
                    email_id=email_rec.id,
                    classification=spec["ai_classification"],
                    confidence=spec["ai_confidence"],
                    signals=spec["ai_signals"],
                    model_info="SIH-2026-Ensemble-v2 (Demo Dataset)",
                )
                db.add(ai_obj)

                # Add Evidence Record & Chain of Custody
                ev_id = f"EV-{email_rec.id.upper()}"
                ev_obj = EvidenceRecord(
                    id=ev_id,
                    email_id=email_rec.id,
                    case_id=default_case.id,
                    investigation_id=default_case.id,
                    sha256_hash=sha_hash,
                    filename=f"{email_rec.id}.eml",
                    file_size_bytes=len(raw_bytes),
                    collected_by="SIH Demo System",
                    integrity_status="Verified",
                )
                db.add(ev_obj)
                db.flush()

                # Custody events
                c1 = build_custody_event(evidence_id=ev_id, user="SIH Ingestion Bot", action="Evidence collected")
                db.add(CustodyEvent(id=c1["id"], evidence_id=ev_id, timestamp=c1["timestamp"], user=c1["user"], action=c1["action"]))

                c2 = build_custody_event(evidence_id=ev_id, user="Forensic Threat Engine", action="Analysis performed")
                db.add(CustodyEvent(id=c2["id"], evidence_id=ev_id, timestamp=c2["timestamp"], user=c2["user"], action=c2["action"]))

                # Blockchain / Ledger Registration
                ledger_rec = ledger.register(
                    evidence_id=ev_id,
                    evidence_hash=sha_hash,
                    case_reference=default_case.case_number,
                )
                ledger_obj = EvidenceLedgerEntry(
                    id=str(uuid.uuid4()),
                    evidence_id=ev_id,
                    ledger_tx_id=ledger_rec["ledger_tx_id"],
                    evidence_hash=ledger_rec["evidence_hash"],
                    case_reference=ledger_rec["case_reference"],
                    block_number=ledger_rec["block_number"],
                    prev_block_hash=ledger_rec.get("prev_block_hash"),
                    merkle_root=ledger_rec.get("merkle_root"),
                    contract_address=ledger_rec.get("contract_address"),
                    verification_status="Verified",
                    ledger_status="CONFIRMED",
                )
                db.add(ledger_obj)

            seeded_records.append(email_rec)

        db.commit()
        return seeded_records
