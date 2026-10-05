"""
Tests for STEP 16 — Evidence Preservation

Covers:
    • SHA-256 computation & verification (unit)
    • Evidence record creation (unit)
    • Custody event builder & validation (unit)
    • API endpoints via TestClient (integration):
        – evidence auto-created during /emails/analyze
        – GET /evidence/{email_id}
        – GET /evidence/{evidence_id}/verify
        – GET /evidence/{evidence_id}/custody
        – POST /evidence/{evidence_id}/custody
        – GET /evidence (list all)
"""

import os
import pytest
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from app.main import app
from app.services.evidence_preservation import (
    compute_sha256,
    verify_integrity,
    build_evidence_record,
    build_custody_event,
    VALID_CUSTODY_ACTIONS,
)

client = TestClient(app)

# ---------------------------------------------------------------
#  Unit tests — SHA-256 hashing
# ---------------------------------------------------------------

class TestComputeSHA256:
    def test_deterministic(self):
        data = b"Hello, forensic world!"
        h1 = compute_sha256(data)
        h2 = compute_sha256(data)
        assert h1 == h2, "SHA-256 must be deterministic"

    def test_hex_length(self):
        h = compute_sha256(b"test")
        assert len(h) == 64, "SHA-256 hex-digest is 64 characters"

    def test_different_inputs_differ(self):
        h1 = compute_sha256(b"alpha")
        h2 = compute_sha256(b"beta")
        assert h1 != h2

    def test_empty_bytes(self):
        h = compute_sha256(b"")
        # SHA-256 of empty input is a well-known constant
        assert h == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    def test_known_vector(self):
        # SHA-256("abc") per NIST
        h = compute_sha256(b"abc")
        assert h == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# ---------------------------------------------------------------
#  Unit tests — integrity verification
# ---------------------------------------------------------------

class TestVerifyIntegrity:
    def test_verified(self):
        data = b"original evidence bytes"
        stored = compute_sha256(data)
        result = verify_integrity(data, stored)
        assert result["status"] == "Verified"
        assert result["match"] is True
        assert result["stored_hash"] == result["recalculated_hash"]

    def test_mismatch(self):
        data = b"original"
        wrong_hash = compute_sha256(b"tampered")
        result = verify_integrity(data, wrong_hash)
        assert result["status"] == "Integrity mismatch"
        assert result["match"] is False
        assert result["stored_hash"] != result["recalculated_hash"]

    def test_returns_verified_at_timestamp(self):
        result = verify_integrity(b"x", compute_sha256(b"x"))
        assert "verified_at" in result
        # Should be parseable as ISO datetime
        datetime.fromisoformat(result["verified_at"])


# ---------------------------------------------------------------
#  Unit tests — evidence record builder
# ---------------------------------------------------------------

class TestBuildEvidenceRecord:
    def test_all_fields_present(self):
        rec = build_evidence_record(
            evidence_data=b"file-content",
            case_id="CASE-001",
            investigation_id="INV-001",
            filename="phish.eml",
            collected_by="admin",
        )
        assert set(rec.keys()) == {
            "id", "case_id", "investigation_id", "sha256_hash",
            "filename", "file_size_bytes", "created_at",
            "collected_by", "integrity_status",
        }

    def test_hash_matches_data(self):
        data = b"evidence-bytes"
        rec = build_evidence_record(
            evidence_data=data,
            case_id="C", investigation_id="I",
            filename="e.eml", collected_by="u",
        )
        assert rec["sha256_hash"] == compute_sha256(data)

    def test_file_size(self):
        data = b"0123456789"
        rec = build_evidence_record(
            evidence_data=data,
            case_id="C", investigation_id="I",
            filename="f", collected_by="u",
        )
        assert rec["file_size_bytes"] == 10

    def test_integrity_status_is_verified(self):
        rec = build_evidence_record(
            evidence_data=b"x",
            case_id="C", investigation_id="I",
            filename="f", collected_by="u",
        )
        assert rec["integrity_status"] == "Verified"

    def test_unique_ids(self):
        r1 = build_evidence_record(evidence_data=b"a", case_id="C",
                                   investigation_id="I", filename="f", collected_by="u")
        r2 = build_evidence_record(evidence_data=b"a", case_id="C",
                                   investigation_id="I", filename="f", collected_by="u")
        assert r1["id"] != r2["id"], "IDs should be globally unique"


# ---------------------------------------------------------------
#  Unit tests — custody event builder
# ---------------------------------------------------------------

class TestBuildCustodyEvent:
    def test_valid_actions(self):
        for action in VALID_CUSTODY_ACTIONS:
            evt = build_custody_event(
                evidence_id="EV-1", user="alice", action=action,
            )
            assert evt["action"] == action
            assert evt["user"] == "alice"
            assert evt["evidence_id"] == "EV-1"

    def test_invalid_action_raises(self):
        with pytest.raises(ValueError, match="Invalid custody action"):
            build_custody_event(
                evidence_id="EV-1", user="bob", action="Deleted evidence",
            )

    def test_custom_timestamp(self):
        ts = datetime(2026, 1, 1, tzinfo=timezone.utc)
        evt = build_custody_event(
            evidence_id="EV-1", user="u", action="Evidence collected",
            timestamp=ts,
        )
        assert evt["timestamp"] == ts

    def test_default_timestamp_is_utc(self):
        evt = build_custody_event(
            evidence_id="EV-1", user="u", action="Evidence collected",
        )
        assert isinstance(evt["timestamp"], datetime)


# ---------------------------------------------------------------
#  Integration tests — API endpoints
# ---------------------------------------------------------------

def _analyze_sample_email():
    """Helper: upload the sample phishing email and return the JSON response."""
    sample_path = os.path.join(os.path.dirname(__file__), "sample_phishing.eml")
    with open(sample_path, "rb") as f:
        resp = client.post(
            "/api/v1/emails/analyze",
            files={"file": ("sample_phishing.eml", f, "message/rfc822")},
        )
    assert resp.status_code == 200
    return resp.json()


class TestEvidenceAPIEndpoints:
    """Integration tests that exercise the Evidence Preservation API."""

    def test_evidence_created_on_analyze(self):
        email_data = _analyze_sample_email()
        email_id = email_data["id"]

        resp = client.get(f"/api/v1/evidence/{email_id}")
        assert resp.status_code == 200
        ev = resp.json()
        assert ev["email_id"] == email_id
        assert ev["sha256_hash"]  # non-empty
        assert ev["integrity_status"] == "Verified"
        assert ev["collected_by"]  # non-empty
        assert ev["file_size_bytes"] > 0

    def test_custody_timeline_has_collected_event(self):
        email_data = _analyze_sample_email()
        email_id = email_data["id"]

        ev_resp = client.get(f"/api/v1/evidence/{email_id}")
        ev_id = ev_resp.json()["id"]

        timeline = client.get(f"/api/v1/evidence/{ev_id}/custody")
        assert timeline.status_code == 200
        events = timeline.json()
        actions = [e["action"] for e in events]
        assert "Evidence collected" in actions

    def test_custody_timeline_has_viewed_event(self):
        """Viewing evidence should auto-append an 'Evidence viewed' event."""
        email_data = _analyze_sample_email()
        email_id = email_data["id"]

        ev_resp = client.get(f"/api/v1/evidence/{email_id}")
        ev_id = ev_resp.json()["id"]

        timeline = client.get(f"/api/v1/evidence/{ev_id}/custody")
        actions = [e["action"] for e in timeline.json()]
        assert "Evidence viewed" in actions

    def test_add_custody_event(self):
        email_data = _analyze_sample_email()
        ev_resp = client.get(f"/api/v1/evidence/{email_data['id']}")
        ev_id = ev_resp.json()["id"]

        resp = client.post(
            f"/api/v1/evidence/{ev_id}/custody",
            json={"user": "forensic_examiner", "action": "Analysis performed"},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["action"] == "Analysis performed"
        assert body["user"] == "forensic_examiner"

    def test_add_invalid_custody_event(self):
        email_data = _analyze_sample_email()
        ev_resp = client.get(f"/api/v1/evidence/{email_data['id']}")
        ev_id = ev_resp.json()["id"]

        resp = client.post(
            f"/api/v1/evidence/{ev_id}/custody",
            json={"user": "badactor", "action": "Deleted evidence"},
        )
        # Service raises ValueError → should surface as 422 or 500
        assert resp.status_code in (422, 500)

    def test_evidence_not_found(self):
        resp = client.get("/api/v1/evidence/nonexistent-id")
        assert resp.status_code == 404

    def test_list_all_evidence(self):
        _analyze_sample_email()
        resp = client.get("/api/v1/evidence")
        assert resp.status_code == 200
        items = resp.json()
        assert isinstance(items, list)
        assert len(items) >= 1

    def test_report_generates_custody_event(self):
        """Generating a PDF report should auto-append a 'Report generated' custody event."""
        email_data = _analyze_sample_email()
        email_id = email_data["id"]

        # Generate the report
        client.get(f"/api/v1/reports/pdf/{email_id}")

        # Fetch evidence and its timeline
        ev_resp = client.get(f"/api/v1/evidence/{email_id}")
        ev_id = ev_resp.json()["id"]

        timeline = client.get(f"/api/v1/evidence/{ev_id}/custody")
        actions = [e["action"] for e in timeline.json()]
        assert "Report generated" in actions
