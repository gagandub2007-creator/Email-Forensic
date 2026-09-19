import pytest
from app.services.threat_ai import AIThreatEngine, BaselineHeuristicDetector

def test_legitimate_email():
    parsed_email = {
        "subject": "Lunch today?",
        "body_plain": "Are we still on for lunch at noon?",
        "sender_address": "colleague@example.com",
        "sender_name": "John Doe",
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "urls": [],
        "attachments": []
    }
    
    res = AIThreatEngine.analyze_email_threat(parsed_email, [])
    assert res["classification"] == "Legitimate"
    assert res["confidence"] == 0.9
    assert res["threat_level"] == "CLEAN"
    assert len(res["signals"]) == 1
    assert "No suspicious indicators detected" in res["signals"]

def test_bec_impersonation_email():
    parsed_email = {
        "subject": "Urgent Request: Wire Transfer needed",
        "body_plain": "Please process a wire transfer to the new banking details.",
        "sender_address": "ceo.office@gmail.com",
        "sender_name": "CEO",
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "urls": [],
        "attachments": []
    }
    
    res = AIThreatEngine.analyze_email_threat(parsed_email, [])
    assert res["classification"] == "Business Email Compromise"
    assert res["confidence"] > 0.5
    assert "Impersonation" in str(res["signals"])
    assert "Financial" in str(res["signals"])

def test_phishing_malicious_link():
    parsed_email = {
        "subject": "Verify your account immediately",
        "body_plain": "Please click here to update your password.",
        "sender_address": "security@baddomain.xyz",
        "sender_name": "Security Team",
        "spf_status": "FAIL",
        "dkim_status": "FAIL",
        "dmarc_status": "FAIL",
        "urls": ["http://192.168.1.100/login", "https://verify-account.xyz"],
        "attachments": []
    }
    
    res = AIThreatEngine.analyze_email_threat(parsed_email, [])
    assert res["classification"] in ["Phishing", "Malicious Link"]
    assert res["confidence"] > 0.8
    assert res["threat_level"] == "CRITICAL"
    assert any("Authentication failure" in s for s in res["signals"])

def test_suspicious_attachment():
    parsed_email = {
        "subject": "Invoice attached",
        "body_plain": "Please review the attached invoice.",
        "sender_address": "billing@unknown.com",
        "sender_name": "Billing",
        "spf_status": "PASS",
        "dkim_status": "PASS",
        "dmarc_status": "PASS",
        "urls": [],
        "attachments": [{"filename": "invoice.exe"}]
    }
    
    res = AIThreatEngine.analyze_email_threat(parsed_email, [])
    assert res["classification"] == "Suspicious Attachment"
    assert res["confidence"] > 0.8
    assert res["threat_level"] == "CRITICAL"
    assert any("Executable or dangerous attachment detected" in s for s in res["signals"])
