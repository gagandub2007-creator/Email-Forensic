import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_case_crud_and_status_lifecycle():
    # 1. Create a Case
    create_resp = client.post("/api/v1/cases", json={
        "title": "Phishing Attack on Executive Accounts",
        "description": "Multi-stage phishing campaign targeting executive financial directors.",
        "severity": "High",
        "status": "Open",
        "assigned_analyst": "Sarah M. (Lead SOC Analyst)"
    })
    assert create_resp.status_code == 200
    case_data = create_resp.json()
    case_id = case_data["id"]

    assert case_data["status"] == "Open"
    assert case_data["severity"] == "High"
    assert case_data["assigned_analyst"] == "Sarah M. (Lead SOC Analyst)"

    # 2. Update Case Status through Lifecycle: Investigating -> Resolved -> Closed
    for status in ["Investigating", "Resolved", "Closed"]:
        patch_resp = client.patch(f"/api/v1/cases/{case_id}", json={"status": status})
        assert patch_resp.status_code == 200
        assert patch_resp.json()["status"] == status

    # Invalid status should return 400
    bad_patch = client.patch(f"/api/v1/cases/{case_id}", json={"status": "INVALID_STATUS"})
    assert bad_patch.status_code == 400

def test_case_notes():
    # Create Case
    create_resp = client.post("/api/v1/cases", json={
        "title": "BEC Wire Transfer Investigation"
    })
    case_id = create_resp.json()["id"]

    # Add Note
    note_resp = client.post(f"/api/v1/cases/{case_id}/notes", json={
        "text": "Analyzed suspicious IP 185.220.101.5 - matches known Tor exit router.",
        "author": "Marcus K. (SOC L2 Analyst)"
    })
    assert note_resp.status_code == 200
    case_data = note_resp.json()
    assert len(case_data["notes"]) == 1
    assert case_data["notes"][0]["text"] == "Analyzed suspicious IP 185.220.101.5 - matches known Tor exit router."

def test_create_case_from_investigation():
    # Analyze email first
    raw_email = "From: scam@domain.com\nTo: target@company.com\nSubject: Urgent Refund\n\nPlease click link."
    an_resp = client.post("/api/v1/emails/analyze", data={"raw_text": raw_email})
    assert an_resp.status_code == 200
    email_id = an_resp.json()["id"]

    # Create Case from investigation
    create_case_resp = client.post("/api/v1/cases/create-from-investigation", json={
        "email_id": email_id,
        "title": "Case for Urgent Refund Phish",
        "severity": "Critical",
        "status": "Open"
    })
    assert create_case_resp.status_code == 200
    case_data = create_case_resp.json()
    assert case_data["investigation_count"] >= 1
    assert case_data["severity"] == "Critical"
