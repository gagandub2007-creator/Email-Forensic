import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.parser import EmailParserEngine
from app.services.geoip import GeoIPService
from app.services.threat_ai import AIThreatEngine
from app.services.blockchain import BlockchainService
from app.services.report import ForensicReportGenerator

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["sih_ps_id"] == "26106"

def test_eml_parser():
    sample_path = os.path.join(os.path.dirname(__file__), "sample_phishing.eml")
    with open(sample_path, "rb") as f:
        raw_bytes = f.read()

    parsed = EmailParserEngine.parse_eml_bytes(raw_bytes)
    assert parsed["sender_address"] == "ceo-office@company-corp-scam.com"
    assert "URGENT" in parsed["subject"]
    assert parsed["spf_status"] == "FAIL"
    assert len(parsed["received_headers"]) >= 2
    assert len(parsed["urls"]) >= 1

def test_threat_ai():
    sample_path = os.path.join(os.path.dirname(__file__), "sample_phishing.eml")
    with open(sample_path, "rb") as f:
        raw_bytes = f.read()
    parsed = EmailParserEngine.parse_eml_bytes(raw_bytes)
    hops = GeoIPService.parse_received_hops(parsed["received_headers"])
    
    threat_res = AIThreatEngine.analyze_email_threat(parsed, hops)
    assert threat_res["overall_threat_score"] >= 50.0
    assert threat_res["threat_level"] in ["HIGH_RISK", "CRITICAL"]
    assert threat_res["bec_probability"] > 0.3

def test_blockchain_anchor():
    res = BlockchainService.anchor_evidence_hash("test-email-id", "test-sha256-hash", "CASE-2026-TEST")
    assert res["status"] == "CONFIRMED"
    assert res["transaction_hash"].startswith("0x")

def test_full_analyze_endpoint():
    sample_path = os.path.join(os.path.dirname(__file__), "sample_phishing.eml")
    with open(sample_path, "rb") as f:
        response = client.post(
            "/api/v1/emails/analyze",
            files={"file": ("sample_phishing.eml", f, "message/rfc822")}
        )
    assert response.status_code == 200
    data = response.json()
    assert data["subject"] == "URGENT: Update Direct Deposit & Wire Transfer Information Immediately"
    assert data["threat_level"] in ["HIGH_RISK", "CRITICAL"]
    assert len(data["hops"]) >= 1

def test_pdf_report_endpoint():
    # Analyze first to populate DB
    sample_path = os.path.join(os.path.dirname(__file__), "sample_phishing.eml")
    with open(sample_path, "rb") as f:
        res = client.post(
            "/api/v1/emails/analyze",
            files={"file": ("sample_phishing.eml", f, "message/rfc822")}
        )
    email_id = res.json()["id"]

    pdf_res = client.get(f"/api/v1/reports/pdf/{email_id}")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert pdf_res.content.startswith(b"%PDF")
