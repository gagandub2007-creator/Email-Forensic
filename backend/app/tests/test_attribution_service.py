import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.attribution_service import AttributionSupportEngine, PROHIBITED_PHRASES

client = TestClient(app)

def test_attribution_support_engine_fields():
    email_data = {
        "id": "email-attr-test-123",
        "originating_ip": "185.220.101.5",
        "originating_country": "Germany",
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL"
    }

    hops = [
        {
            "hop_number": 1,
            "ip_address": "185.220.101.5",
            "country": "Germany",
            "city": "Frankfurt",
            "isp": "Tor Anonymization Provider",
            "asn": "AS205100",
            "reverse_dns": "tor-exit-node.network",
            "is_vpn_proxy_tor": True
        }
    ]

    result = AttributionSupportEngine.analyze_attribution_support(email_data, hops)

    assert result["email_id"] == "email-attr-test-123"
    assert "Probable source infrastructure" in result or "probable_source_infrastructure" in result
    assert "Frankfurt" in result["probable_source_infrastructure"]
    assert result["confidence_score"] > 0.5
    assert len(result["supporting_evidence"]) > 0
    assert len(result["alternative_explanations"]) > 0
    assert "Network infrastructure location does not establish the physical location" in result["limitations"]

def test_prohibited_phrases_strict_language_compliance():
    """
    Ensure the system NEVER uses non-compliant assertive phrases such as:
    'Attacker identified', 'Attacker located', 'Exact origin', 'Confirmed attacker'.
    """
    email_data = {
        "id": "email-attr-compliance",
        "originating_ip": "198.51.100.1",
        "originating_country": "Japan",
        "spf_status": "PASS"
    }
    hops = [{"hop_number": 1, "ip_address": "198.51.100.1", "country": "Japan", "city": "Tokyo", "isp": "NTT Communications", "asn": "AS2514"}]

    result = AttributionSupportEngine.analyze_attribution_support(email_data, hops)
    result_str = str(result).lower()

    for phrase in PROHIBITED_PHRASES:
        assert phrase not in result_str, f"Violation: Prohibited phrase '{phrase}' found in output!"

def test_attribution_support_endpoint():
    raw_email = (
        "From: admin@company-fake.com\n"
        "To: employee@company.com\n"
        "Subject: System Upgrade Required\n"
        "Received: from mail.company-fake.com (203.0.113.19) by mx.company.com; Sun, 20 Sep 2026 12:00:00 +0000\n\n"
        "Please upgrade your system immediately."
    )
    analyze_resp = client.post("/api/v1/emails/analyze", data={"raw_text": raw_email})
    assert analyze_resp.status_code == 200
    email_id = analyze_resp.json()["id"]

    attr_resp = client.get(f"/api/v1/emails/{email_id}/attribution-support")
    assert attr_resp.status_code == 200
    attr_data = attr_resp.json()

    assert attr_data["email_id"] == email_id
    assert "probable_source_infrastructure" in attr_data
    assert "confidence_percentage" in attr_data
    assert len(attr_data["supporting_evidence"]) > 0
    assert len(attr_data["alternative_explanations"]) > 0
    assert "limitations" in attr_data

    # Check prohibited phrases on endpoint response
    attr_str = str(attr_data).lower()
    for phrase in PROHIBITED_PHRASES:
        assert phrase not in attr_str
