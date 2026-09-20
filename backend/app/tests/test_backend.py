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

def test_analyze_endpoint_raw_text():
    sample_text = (
        "Received: from 10.0.0.1 by 10.0.0.2\n"
        "From: test@example.com\n"
        "To: user@example.com\n"
        "Subject: Normal Email\n\n"
        "Hello World\n"
    )
    response = client.post("/api/v1/emails/analyze", data={"raw_text": sample_text})
    assert response.status_code == 200
    data = response.json()
    assert data["subject"] == "Normal Email"
    assert data["sender_address"] == "test@example.com"
    assert len(data["hops"]) == 1

def test_missing_auth_headers():
    sample_text = (
        "From: test@example.com\n"
        "Subject: No Auth\n\n"
        "Body content\n"
    )
    parsed = EmailParserEngine.parse_eml_bytes(sample_text.encode("utf-8"))
    assert parsed["spf_status"] == "UNKNOWN"
    assert parsed["dkim_status"] == "UNKNOWN"
    assert parsed["dmarc_status"] == "UNKNOWN"

def test_auth_pass():
    sample_text = (
        "Authentication-Results: mx.google.com;\n"
        "       dkim=pass header.i=@example.com header.s=20210112 header.d=example.com;\n"
        "       spf=pass (google.com: domain of test@example.com designates 192.168.1.1 as permitted sender) smtp.mailfrom=test@example.com;\n"
        "       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.com\n"
        "From: test@example.com\n"
        "Subject: Auth Pass\n\nTest\n"
    )
    parsed = EmailParserEngine.parse_eml_bytes(sample_text.encode("utf-8"))
    assert parsed["spf_status"] == "PASS"
    assert parsed["spf_details"]["domain"] == "test@example.com"
    
    assert parsed["dkim_status"] == "PASS"
    assert parsed["dkim_details"]["domain"] == "example.com"
    assert parsed["dkim_details"]["selector"] == "20210112"
    
    assert parsed["dmarc_status"] == "PASS"
    assert parsed["dmarc_details"]["aligned_domain"] == "example.com"
    assert parsed["dmarc_details"]["policy"] == "REJECT"

def test_auth_fail():
    sample_text = (
        "Authentication-Results: mx.google.com;\n"
        "       dkim=fail header.i=@example.com header.s=bad header.d=example.com;\n"
        "       spf=softfail (google.com: domain of test@example.com does not designate 192.168.1.1 as permitted sender) smtp.mailfrom=test@example.com;\n"
        "       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=example.com\n"
        "From: test@example.com\n"
        "Subject: Auth Fail\n\nTest\n"
    )
    parsed = EmailParserEngine.parse_eml_bytes(sample_text.encode("utf-8"))
    assert parsed["spf_status"] == "SOFTFAIL"
    assert parsed["dkim_status"] == "FAIL"
    assert parsed["dmarc_status"] == "FAIL"

def test_auth_malformed():
    sample_text = (
        "Authentication-Results: mx.google.com; random garbage data\n"
        "From: test@example.com\n"
        "Subject: Malformed Auth\n\nTest\n"
    )
    parsed = EmailParserEngine.parse_eml_bytes(sample_text.encode("utf-8"))
    assert parsed["spf_status"] == "UNKNOWN"
    assert parsed["dkim_status"] == "UNKNOWN"
    assert parsed["dmarc_status"] == "UNKNOWN"

def test_multiple_received_headers():
    sample_text = (
        "Received: from mail.example.com ([1.1.1.1]) by mx.internal with SMTP id 1\n"
        "Received: from internal-node by mail.example.com with SMTP id 2\n"
        "From: a@b.com\n"
        "Subject: Hops\n\nTest\n"
    )
    parsed = EmailParserEngine.parse_eml_bytes(sample_text.encode("utf-8"))
    assert len(parsed["received_headers"]) == 2
    
    hops = GeoIPService.parse_received_hops(parsed["received_headers"])
    assert len(hops) == 2
    assert hops[0]["sending_server"] == "internal-node" # Reverses headers, so originating is first
    assert hops[0]["receiving_server"] == "mail.example.com"
    assert hops[1]["sending_server"] == "mail.example.com"
    assert hops[1]["receiving_server"] == "mx.internal"

def test_malformed_headers():
    sample_text = "Just some text without headers"
    parsed = EmailParserEngine.parse_eml_bytes(sample_text.encode("utf-8"))
    assert parsed["sender_address"] == ""
    assert parsed["subject"] == "(No Subject)"

def test_attachments():
    # MIME multipart string
    sample_text = (
        "Content-Type: multipart/mixed; boundary=\"frontier\"\n"
        "MIME-Version: 1.0\n\n"
        "--frontier\n"
        "Content-Type: text/plain\n\n"
        "This is the body of the message.\n"
        "--frontier\n"
        "Content-Type: application/octet-stream\n"
        "Content-Transfer-Encoding: base64\n"
        "Content-Disposition: attachment; filename=\"payload.exe\"\n\n"
        "MTIzNDU2\n"
        "--frontier--\n"
    )
    parsed = EmailParserEngine.parse_eml_bytes(sample_text.encode("utf-8"))
    assert len(parsed["attachments"]) == 1
    assert parsed["attachments"][0]["filename"] == "payload.exe"
    assert parsed["attachments"][0]["file_size_bytes"] == 6 # Decoded length of MTIzNDU2 is 4? Wait, length of "123456" is 6.

def test_urls():
    sample_text = (
        "From: t@t.com\nSubject: link\n\n"
        "Check this out: https://evil.com/path\n"
        "Also http://www.good.com"
    )
    parsed = EmailParserEngine.parse_eml_bytes(sample_text.encode("utf-8"))
    assert "https://evil.com/path" in parsed["urls"]
    assert "http://www.good.com" in parsed["urls"]
    assert "evil.com" in parsed["domains"]
    assert "good.com" in parsed["domains"]

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
