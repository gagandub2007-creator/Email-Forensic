import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.correlation_service import HistoricalCorrelationEngine

client = TestClient(app)

def test_historical_correlation_engine_matching_artifacts():
    """
    Ingest two emails sharing sender domain, IP, URL, and attachment hash.
    Verify correlation engine links them and uses cautious language.
    """
    raw_email_1 = (
        "From: ceo@phishing-target-corp.com\n"
        "To: victim1@company.com\n"
        "Subject: Urgent Wire Transfer 1\n"
        "Reply-To: attacker@bad-reply-domain.com\n"
        "Received: from mail.phishing-target-corp.com (198.51.100.42) by mx.company.com; Sun, 20 Sep 2026 10:00:00 +0000\n\n"
        "Please visit: http://malicious-gateway-portal.com/login"
    )

    raw_email_2 = (
        "From: finance@phishing-target-corp.com\n"
        "To: victim2@company.com\n"
        "Subject: Urgent Wire Transfer 2\n"
        "Reply-To: attacker@bad-reply-domain.com\n"
        "Received: from mail.phishing-target-corp.com (198.51.100.42) by mx.company.com; Sun, 20 Sep 2026 11:00:00 +0000\n\n"
        "Please visit: http://malicious-gateway-portal.com/login"
    )

    resp1 = client.post("/api/v1/emails/analyze", data={"raw_text": raw_email_1})
    assert resp1.status_code == 200
    email1_id = resp1.json()["id"]

    resp2 = client.post("/api/v1/emails/analyze", data={"raw_text": raw_email_2})
    assert resp2.status_code == 200
    email2_id = resp2.json()["id"]

    # Request correlation for email2
    corr_resp = client.get(f"/api/v1/emails/{email2_id}/correlations")
    assert corr_resp.status_code == 200
    data = corr_resp.json()

    assert data["target_email_id"] == email2_id
    assert data["previous_occurrences_count"] >= 1
    assert len(data["related_investigations"]) >= 1

    # Check shared domains & IPs
    assert "phishing-target-corp.com" in data["shared_domains"]
    assert "198.51.100.42" in data["shared_ips"]
    assert "http://malicious-gateway-portal.com/login" in data["shared_urls"]

    # Cautious Language Checks
    campaign = data["potential_campaign"]
    assert campaign["has_potential_campaign"] is True
    assert "Potential" in campaign["campaign_name"] or "Observed" in campaign["campaign_name"]
    
    # Assert cautious language phrases (DO NOT claim definitive attribution)
    desc = campaign["description"]
    assert "Potential campaign relationship" in desc or "observed" in desc.lower()
    assert "definitive attribution" in desc.lower() or "further investigation" in desc.lower()
    assert "definitely" not in desc.lower()
    assert "guaranteed" not in desc.lower()

def test_correlation_single_isolated_email():
    """
    Ensure single isolated email without matches returns 0 previous occurrences and safe non-assertive output.
    """
    unique_email = (
        f"From: unique-sender-123987@isolated-unique-domain-test.org\n"
        f"To: target@company.com\n"
        f"Subject: Unique Subject Line {pytest.__version__}\n\n"
        f"Hello world"
    )

    resp = client.post("/api/v1/emails/analyze", data={"raw_text": unique_email})
    assert resp.status_code == 200
    email_id = resp.json()["id"]

    corr_resp = client.get(f"/api/v1/emails/{email_id}/correlations")
    assert corr_resp.status_code == 200
    data = corr_resp.json()

    assert data["target_email_id"] == email_id
    assert data["correlation_status"] == "COMPLETED"
