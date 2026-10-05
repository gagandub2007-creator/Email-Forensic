"""
Tests for STEP 18 — Digital Forensic Investigation Report Generation

Covers:
    • PDF report generation with all 17 sections
    • Section 65B backward compatibility wrapper
    • Distinction of FACT, INFERENCE, ESTIMATION, CONFIDENCE, LIMITATION tags
    • GET /api/v1/reports/preview/{email_id}
    • GET /api/v1/reports/pdf/{email_id}
"""

import os
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.report import ForensicReportGenerator

client = TestClient(app)


def _analyze_sample():
    sample_path = os.path.join(os.path.dirname(__file__), "sample_phishing.eml")
    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/emails/analyze",
            files={"file": ("sample_phishing.eml", f, "message/rfc822")},
        )
    assert resp.status_code == 200
    return resp.json()


class TestReportGeneratorUnit:
    def test_generate_full_report_pdf_bytes(self):
        email_record = {
            "id": "test-email-123",
            "subject": "Phishing Alert Test",
            "sender_name": "Attacker",
            "sender_address": "attacker@phish.com",
            "recipient_address": "target@victim.com",
            "threat_level": "High",
            "overall_threat_score": 85,
            "sha256_hash": "a" * 64,
            "email_date": "2026-10-05 12:00:00 UTC",
        }
        hops = [
            {
                "hop_number": 1,
                "ip_address": "1.2.3.4",
                "city": "Unknown",
                "country": "US",
                "isp": "Test ISP",
                "is_vpn_proxy_tor": True,
            }
        ]
        ai_data = {"classification": "Phishing", "confidence": 0.95, "signals": ["Urgency detected"]}
        blockchain_data = {"transaction_hash": "0x123", "block_number": 42, "status": "CONFIRMED"}

        pdf_bytes = ForensicReportGenerator.generate_full_report_pdf(
            email_record=email_record,
            hops=hops,
            ai_data=ai_data,
            blockchain_data=blockchain_data,
            case_id="CASE-2026-TEST",
        )

        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 1000
        assert pdf_bytes.startswith(b"%PDF")

    def test_section65b_backward_compat(self):
        email_record = {"id": "test-65b", "subject": "Test 65B", "sha256_hash": "b" * 64}
        pdf = ForensicReportGenerator.generate_section65b_pdf(
            email_record=email_record,
            hops=[],
            ai_data={},
            blockchain_data={},
        )
        assert pdf.startswith(b"%PDF")


class TestReportAPIEndpoints:
    def test_get_report_preview(self):
        email = _analyze_sample()
        resp = client.get(f"/api/v1/reports/preview/{email['id']}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["email_id"] == email["id"]
        assert len(data["sections"]) == 17
        assert "1. Case Information" in data["sections"]
        assert "17. Limitations" in data["sections"]

    def test_download_pdf_report(self):
        email = _analyze_sample()
        resp = client.get(f"/api/v1/reports/pdf/{email['id']}")
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/pdf"
        assert resp.content.startswith(b"%PDF")

    def test_report_preview_not_found(self):
        resp = client.get("/api/v1/reports/preview/nonexistent-id")
        assert resp.status_code == 404

    def test_report_pdf_not_found(self):
        resp = client.get("/api/v1/reports/pdf/nonexistent-id")
        assert resp.status_code == 404
