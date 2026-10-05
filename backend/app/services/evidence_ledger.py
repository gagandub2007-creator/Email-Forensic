"""
Blockchain / Tamper-Evident Evidence Layer — STEP 17

Architecture
~~~~~~~~~~~~
    LedgerProvider (abstract interface)
        └── MockPermissionedLedger   (SIH prototype / local demo)
        └── (future) HyperledgerFabricLedger
        └── (future) EthereumLedger

CRITICAL PRIVACY RULE
    Only the following metadata is ever stored on any ledger:
        • evidence_hash   (SHA-256)
        • evidence_id
        • timestamp       (UTC ISO-8601)
        • case_reference  (case/investigation ID)
        • ledger_tx_id    (transaction hash returned by the ledger)

    NO raw email content, attachments, PII, or private forensic data
    is ever written to a public or permissioned chain.

Design note
~~~~~~~~~~~
    "Blockchain is used here as a tamper-evident record for evidence
     integrity, not as storage for the original email."
"""

from __future__ import annotations

import abc
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
#  Abstract Ledger Provider
# ---------------------------------------------------------------------------

class LedgerProvider(abc.ABC):
    """Technology-agnostic interface for registering and verifying
    evidence hashes on a tamper-evident ledger.

    Implementations must guarantee:
        1. ``register`` appends an immutable record.
        2. ``verify`` checks that a previously registered hash has
           not been altered.
        3. ``get_record`` retrieves a record by its transaction ID.
    """

    @abc.abstractmethod
    def register(
        self,
        *,
        evidence_id: str,
        evidence_hash: str,
        case_reference: str,
    ) -> Dict[str, Any]:
        """Register an evidence hash on the ledger.

        Returns a dict containing at minimum:
            ledger_tx_id, evidence_id, evidence_hash,
            timestamp, case_reference, block_number,
            contract_address, merkle_root, status.
        """
        ...

    @abc.abstractmethod
    def verify(
        self,
        *,
        evidence_hash: str,
        ledger_tx_id: str,
    ) -> Dict[str, Any]:
        """Verify an evidence hash against its on-ledger record.

        Returns a dict containing:
            verified (bool), status (str), recorded_hash, submitted_hash,
            block_number, timestamp, contract_address.
        """
        ...

    @abc.abstractmethod
    def get_record(self, ledger_tx_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a ledger record by transaction ID, or None."""
        ...

    @abc.abstractmethod
    def list_records(self, case_reference: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all records, optionally filtered by case reference."""
        ...


# ---------------------------------------------------------------------------
#  Mock Permissioned Ledger — SIH Prototype
# ---------------------------------------------------------------------------

class MockPermissionedLedger(LedgerProvider):
    """In-memory permissioned ledger that simulates a Hyperledger Fabric-style
    chain.  Each block is append-only and hashed to the previous block,
    providing basic tamper evidence for the hackathon demo.

    Thread-safety: acceptable for single-process demo; production code
    should use a DB-backed implementation behind the same interface.
    """

    def __init__(self) -> None:
        self._chain: List[Dict[str, Any]] = []
        self._genesis_hash = "0" * 64  # genesis block prev-hash

    # -- helpers --

    def _prev_hash(self) -> str:
        if not self._chain:
            return self._genesis_hash
        last = self._chain[-1]
        return hashlib.sha256(
            f"{last['ledger_tx_id']}:{last['evidence_hash']}:{last['block_number']}".encode()
        ).hexdigest()

    @staticmethod
    def _merkle_root(evidence_hash: str, case_reference: str) -> str:
        return hashlib.sha256(
            f"{evidence_hash}:{case_reference}".encode()
        ).hexdigest()

    @staticmethod
    def _tx_id(evidence_id: str, evidence_hash: str, block_number: int) -> str:
        raw = f"{evidence_id}:{evidence_hash}:{block_number}:{uuid.uuid4().hex[:8]}"
        return "0x" + hashlib.sha256(raw.encode()).hexdigest()

    # -- interface implementation --

    def register(
        self,
        *,
        evidence_id: str,
        evidence_hash: str,
        case_reference: str,
    ) -> Dict[str, Any]:
        block_number = len(self._chain) + 1
        tx_id = self._tx_id(evidence_id, evidence_hash, block_number)
        merkle = self._merkle_root(evidence_hash, case_reference)
        now = datetime.now(timezone.utc)
        prev = self._prev_hash()

        record = {
            "ledger_tx_id": tx_id,
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "case_reference": case_reference,
            "timestamp": now.isoformat(),
            "block_number": block_number,
            "prev_block_hash": prev,
            "merkle_root": merkle,
            "contract_address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
            "status": "CONFIRMED",
        }
        self._chain.append(record)
        return record

    def verify(
        self,
        *,
        evidence_hash: str,
        ledger_tx_id: str,
    ) -> Dict[str, Any]:
        rec = self.get_record(ledger_tx_id)
        if rec is None:
            return {
                "verified": False,
                "status": "Ledger record not found",
                "recorded_hash": None,
                "submitted_hash": evidence_hash,
                "block_number": None,
                "timestamp": None,
                "contract_address": None,
            }

        is_match = rec["evidence_hash"] == evidence_hash
        return {
            "verified": is_match,
            "status": "Verified" if is_match else "Integrity mismatch",
            "recorded_hash": rec["evidence_hash"],
            "submitted_hash": evidence_hash,
            "block_number": rec["block_number"],
            "timestamp": rec["timestamp"],
            "contract_address": rec["contract_address"],
        }

    def get_record(self, ledger_tx_id: str) -> Optional[Dict[str, Any]]:
        for rec in self._chain:
            if rec["ledger_tx_id"] == ledger_tx_id:
                return dict(rec)
        return None

    def list_records(self, case_reference: Optional[str] = None) -> List[Dict[str, Any]]:
        if case_reference is None:
            return [dict(r) for r in self._chain]
        return [dict(r) for r in self._chain if r["case_reference"] == case_reference]

    @property
    def chain_length(self) -> int:
        return len(self._chain)

    def validate_chain(self) -> bool:
        """Walk the chain and verify each block links to its predecessor."""
        prev = self._genesis_hash
        for block in self._chain:
            if block["prev_block_hash"] != prev:
                return False
            prev = hashlib.sha256(
                f"{block['ledger_tx_id']}:{block['evidence_hash']}:{block['block_number']}".encode()
            ).hexdigest()
        return True


# ---------------------------------------------------------------------------
#  Singleton ledger instance for the application
# ---------------------------------------------------------------------------

_default_ledger: Optional[LedgerProvider] = None


def get_ledger() -> LedgerProvider:
    """Return the application-wide ledger provider (lazy singleton)."""
    global _default_ledger
    if _default_ledger is None:
        _default_ledger = MockPermissionedLedger()
    return _default_ledger


def set_ledger(provider: LedgerProvider) -> None:
    """Override the default ledger provider (useful for testing or
    swapping in a HyperledgerFabricLedger in production)."""
    global _default_ledger
    _default_ledger = provider
