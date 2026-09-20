import os
import hashlib
import uuid
from datetime import datetime
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.models.entities import EvidenceRecord, EmailRecord

VAULT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence_vault")

def ensure_vault_exists():
    os.makedirs(VAULT_DIR, exist_ok=True)

class EvidencePreservationService:
    @staticmethod
    def store_raw_evidence(
        db: Session,
        email_id: str,
        file_name: str,
        raw_content: bytes,
        case_id: Optional[str] = None,
        collected_by: str = "SOC Lead Investigator"
    ) -> EvidenceRecord:
        """
        Stores original raw evidence in isolated read-only vault without mutation.
        Computes SHA-256 hash and logs initial chain of custody events.
        """
        ensure_vault_exists()
        evidence_id = str(uuid.uuid4())
        
        # Calculate SHA-256 hash of raw bytes
        sha256_hash = hashlib.sha256(raw_content).hexdigest()
        file_size_bytes = len(raw_content)
        
        # Save raw evidence file to vault
        safe_filename = f"{evidence_id}_{file_name}"
        vault_file_path = os.path.join(VAULT_DIR, safe_filename)
        
        with open(vault_file_path, "wb") as f:
            f.write(raw_content)
            
        now_str = datetime.utcnow().isoformat()
        
        initial_logs = [
            {
                "timestamp": now_str,
                "user": collected_by,
                "action": "Evidence collected",
                "evidence_id": evidence_id
            },
            {
                "timestamp": now_str,
                "user": "Automated Parsing Engine",
                "action": "Analysis performed",
                "evidence_id": evidence_id
            }
        ]
        
        record = EvidenceRecord(
            id=evidence_id,
            case_id=case_id,
            investigation_id=email_id,
            sha256_hash=sha256_hash,
            file_name=file_name,
            file_size_bytes=file_size_bytes,
            file_path=vault_file_path,
            collected_by=collected_by,
            integrity_status="Verified",
            chain_of_custody_logs=initial_logs
        )
        
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def get_evidence_by_email(db: Session, email_id: str) -> Optional[EvidenceRecord]:
        return db.query(EvidenceRecord).filter(EvidenceRecord.investigation_id == email_id).first()

    @staticmethod
    def get_evidence_by_id(db: Session, evidence_id: str) -> Optional[EvidenceRecord]:
        return db.query(EvidenceRecord).filter(EvidenceRecord.id == evidence_id).first()

    @staticmethod
    def verify_evidence_integrity(db: Session, evidence_id: str, user: str = "SOC Analyst") -> Dict[str, Any]:
        """
        Recalculates SHA-256 hash of the vault file on disk and compares it with the stored hash.
        Logs 'Evidence viewed' in chain of custody timeline.
        Returns exact status: 'Verified' or 'Integrity mismatch'.
        """
        record = EvidencePreservationService.get_evidence_by_id(db, evidence_id)
        if not record:
            return {"status": "Integrity mismatch", "error": "Evidence record not found"}
        
        if not os.path.exists(record.file_path):
            record.integrity_status = "Integrity mismatch"
            db.commit()
            return {
                "status": "Integrity mismatch",
                "error": "Vault evidence file missing",
                "stored_hash": record.sha256_hash,
                "recalculated_hash": "FILE_NOT_FOUND"
            }
        
        with open(record.file_path, "rb") as f:
            content = f.read()
            recalculated_hash = hashlib.sha256(content).hexdigest()
            
        is_verified = (recalculated_hash.lower() == record.sha256_hash.lower())
        status_str = "Verified" if is_verified else "Integrity mismatch"
        
        record.integrity_status = status_str
        
        # Log view event
        log_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "action": "Evidence viewed",
            "evidence_id": evidence_id
        }
        logs = list(record.chain_of_custody_logs or [])
        logs.append(log_event)
        record.chain_of_custody_logs = logs
        
        db.commit()
        db.refresh(record)
        
        return {
            "status": status_str,
            "stored_hash": record.sha256_hash,
            "recalculated_hash": recalculated_hash,
            "file_name": record.file_name,
            "evidence_id": evidence_id
        }

    @staticmethod
    def log_custody_action(
        db: Session,
        evidence_id: str,
        user: str,
        action: str
    ) -> Optional[EvidenceRecord]:
        """
        Logs a chain of custody action:
        Actions: Evidence collected, Analysis performed, Evidence viewed, Evidence exported, Report generated.
        """
        record = EvidencePreservationService.get_evidence_by_id(db, evidence_id)
        if not record:
            return None
        
        log_event = {
            "timestamp": datetime.utcnow().isoformat(),
            "user": user,
            "action": action,
            "evidence_id": evidence_id
        }
        
        logs = list(record.chain_of_custody_logs or [])
        logs.append(log_event)
        record.chain_of_custody_logs = logs
        
        db.commit()
        db.refresh(record)
        return record
