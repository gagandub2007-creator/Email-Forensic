"""
Evidence Preservation Service — STEP 16

Responsibilities:
    1.  Calculate SHA-256 hashes for uploaded/analyzed email evidence.
    2.  Create immutable EvidenceRecord metadata (evidence ID, case ID,
        investigation ID, SHA-256, filename, file-size, timestamps, etc.).
    3.  Maintain a chain-of-custody timeline (CustodyEvent entries).
    4.  Verify evidence integrity by recalculating SHA-256 and comparing
        it against the stored hash.

CRITICAL DESIGN RULE
    • Original evidence bytes are NEVER modified.
    • Derived analysis data lives in separate tables/records.
    • This module only reads original bytes for hashing/verification.
"""

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
#  Hashing helpers
# ---------------------------------------------------------------------------

def compute_sha256(data: bytes) -> str:
    """Return the hex-digest SHA-256 of *data*."""
    return hashlib.sha256(data).hexdigest()


def verify_integrity(data: bytes, stored_hash: str) -> dict:
    """Recalculate SHA-256 and compare with *stored_hash*.

    Returns
    -------
    dict
        ``{"status": "Verified", ...}`` or
        ``{"status": "Integrity mismatch", ...}``
    """
    recalculated = compute_sha256(data)
    is_match = recalculated == stored_hash
    return {
        "status": "Verified" if is_match else "Integrity mismatch",
        "stored_hash": stored_hash,
        "recalculated_hash": recalculated,
        "verified_at": datetime.now(timezone.utc).isoformat(),
        "match": is_match,
    }


# ---------------------------------------------------------------------------
#  Evidence record builder
# ---------------------------------------------------------------------------

def build_evidence_record(
    *,
    evidence_data: bytes,
    case_id: str,
    investigation_id: str,
    filename: str,
    collected_by: str,
) -> dict:
    """Create a new evidence-record dict ready for DB persistence.

    The SHA-256 is computed from the raw *evidence_data* bytes.
    """
    sha256 = compute_sha256(evidence_data)
    now = datetime.now(timezone.utc)
    return {
        "id": str(uuid.uuid4()),
        "case_id": case_id,
        "investigation_id": investigation_id,
        "sha256_hash": sha256,
        "filename": filename,
        "file_size_bytes": len(evidence_data),
        "created_at": now,
        "collected_by": collected_by,
        "integrity_status": "Verified",  # freshly computed → always valid
    }


# ---------------------------------------------------------------------------
#  Chain-of-custody event builder
# ---------------------------------------------------------------------------

VALID_CUSTODY_ACTIONS = frozenset([
    "Evidence collected",
    "Analysis performed",
    "Evidence viewed",
    "Evidence exported",
    "Report generated",
])


def build_custody_event(
    *,
    evidence_id: str,
    user: str,
    action: str,
    timestamp: Optional[datetime] = None,
) -> dict:
    """Return a chain-of-custody event dict.

    Parameters
    ----------
    evidence_id : str
        The evidence record this event relates to.
    user : str
        Identifier (username / ID) of the person performing the action.
    action : str
        One of the ``VALID_CUSTODY_ACTIONS``.
    timestamp : datetime, optional
        Defaults to *now* (UTC).
    """
    if action not in VALID_CUSTODY_ACTIONS:
        raise ValueError(
            f"Invalid custody action '{action}'. "
            f"Must be one of: {sorted(VALID_CUSTODY_ACTIONS)}"
        )
    return {
        "id": str(uuid.uuid4()),
        "evidence_id": evidence_id,
        "timestamp": timestamp or datetime.now(timezone.utc),
        "user": user,
        "action": action,
    }
