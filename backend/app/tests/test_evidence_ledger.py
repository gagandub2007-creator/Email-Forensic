"""
Tests for STEP 17 — Blockchain / Tamper-Evident Ledger

Covers:
    • MockPermissionedLedger unit tests
    • LedgerProvider interface contract
    • Chain validation
    • API integration: ledger auto-created during /emails/analyze
    • GET /ledger/{evidence_id}
    • GET /ledger/{evidence_id}/verify
    • GET /ledger (list)
"""

import os
import pytest

from app.services.evidence_ledger import (
    MockPermissionedLedger,
    LedgerProvider,
    get_ledger,
    set_ledger,
)
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


# ---------------------------------------------------------------
#  Unit tests — MockPermissionedLedger
# ---------------------------------------------------------------

class TestMockPermissionedLedger:
    def setup_method(self):
        self.ledger = MockPermissionedLedger()

    def test_register_returns_required_fields(self):
        rec = self.ledger.register(
            evidence_id="EV-001",
            evidence_hash="a" * 64,
            case_reference="CASE-001",
        )
        required_keys = {
            "ledger_tx_id", "evidence_id", "evidence_hash",
            "case_reference", "timestamp", "block_number",
            "prev_block_hash", "merkle_root", "contract_address", "status",
        }
        assert required_keys.issubset(rec.keys())
        assert rec["status"] == "CONFIRMED"
        assert rec["ledger_tx_id"].startswith("0x")
        assert rec["block_number"] == 1

    def test_sequential_block_numbers(self):
        r1 = self.ledger.register(evidence_id="E1", evidence_hash="a" * 64, case_reference="C")
        r2 = self.ledger.register(evidence_id="E2", evidence_hash="b" * 64, case_reference="C")
        assert r2["block_number"] == r1["block_number"] + 1

    def test_verify_success(self):
        rec = self.ledger.register(evidence_id="E1", evidence_hash="abc123" + "0" * 58, case_reference="C")
        result = self.ledger.verify(evidence_hash="abc123" + "0" * 58, ledger_tx_id=rec["ledger_tx_id"])
        assert result["verified"] is True
        assert result["status"] == "Verified"

    def test_verify_mismatch(self):
        rec = self.ledger.register(evidence_id="E1", evidence_hash="a" * 64, case_reference="C")
        result = self.ledger.verify(evidence_hash="b" * 64, ledger_tx_id=rec["ledger_tx_id"])
        assert result["verified"] is False
        assert result["status"] == "Integrity mismatch"

    def test_verify_not_found(self):
        result = self.ledger.verify(evidence_hash="x" * 64, ledger_tx_id="0xnotexist")
        assert result["verified"] is False
        assert result["status"] == "Ledger record not found"

    def test_get_record(self):
        rec = self.ledger.register(evidence_id="E1", evidence_hash="a" * 64, case_reference="C")
        fetched = self.ledger.get_record(rec["ledger_tx_id"])
        assert fetched is not None
        assert fetched["evidence_id"] == "E1"

    def test_get_record_not_found(self):
        assert self.ledger.get_record("0xghost") is None

    def test_list_records_all(self):
        self.ledger.register(evidence_id="E1", evidence_hash="a" * 64, case_reference="C1")
        self.ledger.register(evidence_id="E2", evidence_hash="b" * 64, case_reference="C2")
        records = self.ledger.list_records()
        assert len(records) == 2

    def test_list_records_filtered(self):
        self.ledger.register(evidence_id="E1", evidence_hash="a" * 64, case_reference="C1")
        self.ledger.register(evidence_id="E2", evidence_hash="b" * 64, case_reference="C2")
        records = self.ledger.list_records(case_reference="C1")
        assert len(records) == 1
        assert records[0]["case_reference"] == "C1"

    def test_chain_validation_valid(self):
        self.ledger.register(evidence_id="E1", evidence_hash="a" * 64, case_reference="C")
        self.ledger.register(evidence_id="E2", evidence_hash="b" * 64, case_reference="C")
        self.ledger.register(evidence_id="E3", evidence_hash="c" * 64, case_reference="C")
        assert self.ledger.validate_chain() is True

    def test_chain_validation_tampered(self):
        self.ledger.register(evidence_id="E1", evidence_hash="a" * 64, case_reference="C")
        self.ledger.register(evidence_id="E2", evidence_hash="b" * 64, case_reference="C")
        # Tamper with block 1
        self.ledger._chain[0]["evidence_hash"] = "z" * 64
        assert self.ledger.validate_chain() is False

    def test_implements_abstract_interface(self):
        assert isinstance(self.ledger, LedgerProvider)

    def test_no_raw_content_stored(self):
        """Ensure no field in the ledger record could contain raw email data."""
        rec = self.ledger.register(
            evidence_id="EV-001",
            evidence_hash="a" * 64,
            case_reference="CASE-001",
        )
        for key in rec:
            assert key in {
                "ledger_tx_id", "evidence_id", "evidence_hash",
                "case_reference", "timestamp", "block_number",
                "prev_block_hash", "merkle_root", "contract_address", "status",
            }, f"Unexpected field '{key}' — raw content must never be stored on-chain"


# ---------------------------------------------------------------
#  Integration tests — API endpoints
# ---------------------------------------------------------------

import uuid

def _analyze_sample():
    unique_sub = f"Phishing Test {uuid.uuid4()}"
    raw_text = f"From: attacker@phish.com\nTo: target@victim.com\nSubject: {unique_sub}\nDate: Mon, 05 Oct 2026 12:00:00 +0000\n\nPlease click http://phish.com urgently."
    resp = client.post(
        "/api/v1/emails/analyze",
        data={"raw_text": raw_text},
    )
    assert resp.status_code == 200
    return resp.json()


class TestLedgerAPIEndpoints:
    def test_ledger_entry_created_on_analyze(self):
        email = _analyze_sample()
        ev_resp = client.get(f"/api/v1/evidence/{email['id']}")
        assert ev_resp.status_code == 200
        ev = ev_resp.json()

        # Ledger entry should exist
        le_resp = client.get(f"/api/v1/ledger/{ev['id']}")
        assert le_resp.status_code == 200
        le = le_resp.json()
        assert le["ledger_tx_id"].startswith("0x")
        assert le["evidence_hash"]
        assert le["ledger_status"] == "CONFIRMED"
        assert le["block_number"] >= 1

    def test_ledger_verify(self):
        email = _analyze_sample()
        ev = client.get(f"/api/v1/evidence/{email['id']}").json()

        verify = client.get(f"/api/v1/ledger/{ev['id']}/verify")
        assert verify.status_code == 200
        body = verify.json()
        assert body["verified"] is True
        assert body["status"] == "Verified"

    def test_list_ledger_entries(self):
        _analyze_sample()
        resp = client.get("/api/v1/ledger")
        assert resp.status_code == 200
        entries = resp.json()
        assert isinstance(entries, list)
        assert len(entries) >= 1

    def test_ledger_entry_not_found(self):
        resp = client.get("/api/v1/ledger/nonexistent-id")
        assert resp.status_code == 404
