"""
Tests for STEP 20 — Realistic Demonstration Dataset

Covers:
    • Demo dataset seeding via DemoDatasetManager
    • POST /api/v1/demo/seed
    • GET /api/v1/demo/dataset
    • Presence of all 5 mandatory forensic threat scenarios:
        1. Legitimate Business Email
        2. Credential Phishing Email
        3. CEO/Executive Impersonation (BEC)
        4. Fake Invoice / Payment Diversion
        5. Malicious Link Email
    • Automatic creation of evidence preservation, chain of custody, and tamper-evident ledger entries for demo dataset
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestDemoDatasetAPI:
    def test_seed_demo_data_endpoint(self):
        resp = client.post("/api/v1/demo/seed")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "success"
        assert data["count"] == 5
        assert "DEMO DATA" in data["disclaimer"]
        assert len(data["demo_email_ids"]) == 5

    def test_get_demo_dataset_endpoint(self):
        resp = client.get("/api/v1/demo/dataset")
        assert resp.status_code == 200
        data = resp.json()
        assert data["is_demo_data"] is True
        assert data["count"] == 5
        assert len(data["items"]) == 5

        # Check threat classifications present
        classifications = {item["ai_classification"] for item in data["items"]}
        assert "Legitimate Business Email" in classifications
        assert "Credential Phishing" in classifications
        assert "Business Email Compromise (BEC) / Executive Impersonation" in classifications
        assert "Fake Invoice / Payment Diversion Phishing" in classifications
        assert "Malicious Link / Credential Harvester" in classifications

    def test_demo_email_details_and_evidence_integration(self):
        dataset = client.get("/api/v1/demo/dataset").json()["items"]
        phish_email = next(e for e in dataset if e["id"] == "demo-email-02-phish")

        # Fetch email details
        email_resp = client.get(f"/api/v1/emails/{phish_email['id']}")
        assert email_resp.status_code == 200
        email_data = email_resp.json()
        assert email_data["spf_status"] == "FAIL"
        assert email_data["threat_level"] == "CRITICAL"

        # Fetch evidence record
        ev_resp = client.get(f"/api/v1/evidence/{phish_email['id']}")
        assert ev_resp.status_code == 200
        ev_data = ev_resp.json()
        assert ev_data["integrity_status"] == "Verified"

        # Fetch custody timeline
        custody_resp = client.get(f"/api/v1/evidence/{ev_data['id']}/custody")
        assert custody_resp.status_code == 200
        custody_events = custody_resp.json()
        assert len(custody_events) >= 2

        # Fetch ledger entry
        ledger_resp = client.get(f"/api/v1/ledger/{ev_data['id']}")
        assert ledger_resp.status_code == 200
        ledger_data = ledger_resp.json()
        assert ledger_data["ledger_status"] == "CONFIRMED"
