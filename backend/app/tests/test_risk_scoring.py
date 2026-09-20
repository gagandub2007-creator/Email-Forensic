import pytest
from app.services.risk_scoring import RiskScoringEngine

def test_legitimate_email_score():
    parsed = {
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "sender_address": "user@example.com",
        "reply_to": "user@example.com",
        "urls": ["https://example.com/about"],
        "attachments": []
    }
    ai_threat_res = {"classification": "Legitimate", "signals": ["No suspicious indicators detected"]}
    hops = []
    
    res = RiskScoringEngine.calculate_risk(parsed, hops, ai_threat_res)
    assert res["risk_score"] == 0
    assert res["severity"] == "Low"
    assert len(res["contributing_factors"]) == 0

def test_mildly_suspicious_score():
    parsed = {
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "sender_address": "user@baddomain.xyz",
        "reply_to": "user@baddomain.xyz",
        "urls": [],
        "attachments": []
    }
    ai_threat_res = {"classification": "Legitimate", "signals": []}
    
    res = RiskScoringEngine.calculate_risk(parsed, [], ai_threat_res)
    assert res["risk_score"] == 25  # SUSPICIOUS_SENDER_DOMAIN (25)
    assert res["severity"] == "Low"
    assert len(res["contributing_factors"]) == 1
    assert "+25" in res["contributing_factors"][0]

def test_high_risk_phishing():
    parsed = {
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "sender_address": "secure@update-acc.com",
        "reply_to": "hacker@evil.com",
        "urls": ["http://192.168.1.100/login"],
        "attachments": []
    }
    ai_threat_res = {"classification": "Phishing", "signals": ["Credential theft language detected"]}
    
    res = RiskScoringEngine.calculate_risk(parsed, [], ai_threat_res)
    # AUTH_FAILURE (15) + REPLY_TO_MISMATCH (20) + SUSPICIOUS_URL (17) + PHISHING_LANGUAGE (15) = 67
    assert res["risk_score"] == 67
    assert res["severity"] == "High"
    assert len(res["contributing_factors"]) == 4
    assert any("DMARC failure" in f for f in res["contributing_factors"])

def test_critical_malicious_email():
    parsed = {
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "sender_address": "admin@weird.xyz",
        "reply_to": "attacker@weird.xyz",
        "urls": ["http://192.168.1.100/download.exe"],
        "attachments": [{"filename": "invoice.exe"}]
    }
    ai_threat_res = {"classification": "Suspicious Attachment", "signals": ["financial fraud indicators"]}
    
    res = RiskScoringEngine.calculate_risk(parsed, [], ai_threat_res)
    # AUTH_FAIL(15) + DOMAIN(25) + URL(17) + ATTACHMENT(35) + FINANCIAL(10) = 102 -> cap at 100
    assert res["risk_score"] == 100
    assert res["severity"] == "Critical"
    assert len(res["contributing_factors"]) == 5

def test_bec_scenario():
    parsed = {
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "sender_address": "ceo.office@gmail.com",
        "reply_to": "ceo.office@gmail.com",
        "urls": [],
        "attachments": []
    }
    ai_threat_res = {"classification": "Business Email Compromise", "signals": ["financial fraud indicators", "impersonation pattern"]}
    
    res = RiskScoringEngine.calculate_risk(parsed, [], ai_threat_res)
    # IMPERSONATION (25) + PAYMENT_FRAUD (10) = 35
    assert res["risk_score"] == 35
    assert res["severity"] == "Medium"
    assert len(res["contributing_factors"]) == 2
