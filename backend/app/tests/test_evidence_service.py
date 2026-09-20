import os
import pytest
import hashlib
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models.database import Base
from app.models.entities import Case, EmailRecord
from app.services.evidence_service import EvidencePreservationService, VAULT_DIR

# Use file-based SQLite test db for thread consistency
TEST_DB_PATH = "./test_evidence_forensics.db"
SQLALCHEMY_DATABASE_URL = f"sqlite:///{TEST_DB_PATH}"

@pytest.fixture(scope="function")
def test_db():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)
    engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    
    # Create mock Case and EmailRecord
    c = Case(id="case-100", case_number="CASE-TEST-100", title="Evidence Vault Test")
    e = EmailRecord(
        id="email-100",
        case_id="case-100",
        subject="Test Forensic Evidence Email",
        sha256_hash="dummyhash100"
    )
    db.add(c)
    db.add(e)
    db.commit()
    
    yield db
    
    db.close()
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

def test_store_raw_evidence(test_db):
    raw_content = b"From: attacker@malicious.com\nTo: victim@gov.in\nSubject: Urgent Action Required\n\nMalicious Payload Content"
    expected_hash = hashlib.sha256(raw_content).hexdigest()
    
    record = EvidencePreservationService.store_raw_evidence(
        db=test_db,
        email_id="email-100",
        case_id="case-100",
        file_name="phishing_sample.eml",
        raw_content=raw_content,
        collected_by="Forensic Specialist"
    )
    
    assert record.id is not None
    assert record.sha256_hash == expected_hash
    assert record.file_size_bytes == len(raw_content)
    assert record.integrity_status == "Verified"
    assert os.path.exists(record.file_path)
    
    # Verify initial logs
    logs = record.chain_of_custody_logs
    assert len(logs) == 2
    actions = [l["action"] for l in logs]
    assert "Evidence collected" in actions
    assert "Analysis performed" in actions

def test_verify_evidence_integrity_success(test_db):
    raw_content = b"Authentic Raw Email Evidence Bytes"
    record = EvidencePreservationService.store_raw_evidence(
        db=test_db,
        email_id="email-100",
        file_name="authentic.eml",
        raw_content=raw_content
    )
    
    res = EvidencePreservationService.verify_evidence_integrity(test_db, record.id, user="Analyst Alice")
    assert res["status"] == "Verified"
    assert res["stored_hash"] == record.sha256_hash
    assert res["recalculated_hash"] == record.sha256_hash
    
    # Check updated custody log
    updated_rec = EvidencePreservationService.get_evidence_by_id(test_db, record.id)
    actions = [l["action"] for l in updated_rec.chain_of_custody_logs]
    assert "Evidence viewed" in actions

def test_tamper_detection_integrity_mismatch(test_db):
    raw_content = b"Original Immutable Evidence Content"
    record = EvidencePreservationService.store_raw_evidence(
        db=test_db,
        email_id="email-100",
        file_name="vault_sample.eml",
        raw_content=raw_content
    )
    
    # Simulate illegal file tampering inside evidence vault
    with open(record.file_path, "wb") as f:
        f.write(b"Tampered Email Evidence Content")
        
    res = EvidencePreservationService.verify_evidence_integrity(test_db, record.id, user="Auditor Bob")
    assert res["status"] == "Integrity mismatch"
    assert res["stored_hash"] != res["recalculated_hash"]

def test_log_custody_action(test_db):
    raw_content = b"Chain of Custody Test Content"
    record = EvidencePreservationService.store_raw_evidence(
        db=test_db,
        email_id="email-100",
        file_name="custody.eml",
        raw_content=raw_content
    )
    
    # Log Evidence exported and Report generated
    rec_export = EvidencePreservationService.log_custody_action(
        db=test_db, evidence_id=record.id, user="Investigator Charlie", action="Evidence exported"
    )
    assert rec_export is not None
    
    rec_report = EvidencePreservationService.log_custody_action(
        db=test_db, evidence_id=record.id, user="Report Engine", action="Report generated"
    )
    
    actions = [l["action"] for l in rec_report.chain_of_custody_logs]
    assert "Evidence collected" in actions
    assert "Analysis performed" in actions
    assert "Evidence exported" in actions
    assert "Report generated" in actions
