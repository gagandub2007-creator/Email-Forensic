# Security Architecture & Forensic Compliance Specification

**SIH PS ID:** 26106  
**AICTE - Cyber Security Cell Theme: Blockchain & Cybersecurity**

---

## 1. STRIDE Threat Model Analysis

| Threat Category | Risk Description | Mitigation Strategy |
| :--- | :--- | :--- |
| **Spoofing** | Attacker spoofs sender headers or user accounts in platform. | Mandatory SPF/DKIM/DMARC alignment check; JWT token auth; 2FA support for investigators. |
| **Tampering** | Alteration of raw email evidence post-ingestion. | SHA-256 cryptographic hashing upon ingestion with immediate smart contract anchoring on Blockchain. |
| **Repudiation** | Suspect claims email evidence was fabricated by investigators. | Immutable Blockchain ledger + Section 65B Indian Evidence Act compliant cryptographic timestamp certificate. |
| **Information Disclosure** | Leakage of confidential email content or case details. | AES-256 encrypted evidence storage at rest, strict RBAC, TLS 1.3 in transit. |
| **Denial of Service** | Malicious zip bombs or massive `.mbox` uploads crashing parser. | Strict file size limits, rate limiting (10 req/min per IP), background asynchronous task execution via Celery/Redis. |
| **Elevation of Privilege** | Attacker gaining admin access or executing malicious attachment scripts. | Isolated static attachment scanning; strict file extension white-listing; Docker non-root execution. |

---

## 2. Chain of Custody & Legal Admissibility (Indian Evidence Act Sec 65B / IT Act)

For digital email evidence to be admissible in legal proceedings (such as Indian Courts under Section 65B of the Indian Evidence Act / Bharatiya Sakshya Adhiniyam 2023):
1. **Hash Verification:** As soon as an `.eml` or `.msg` file is received, the system calculates its SHA-256 hash before parsing.
2. **Blockchain Non-Repudiation:** The hash, file size, timestamp, and investigator ID are written into the `EmailEvidenceRegistry` smart contract.
3. **Automated 65B Certificate Generation:** The platform automatically compiles a digital evidence certificate detailing system parameters, hashing methodology, audit logs, and on-chain verification proof.

---

## 3. Attachment Sandboxing & Threat Inspection Guidelines

1. **No Code Execution:** Email attachments are never executed or rendered directly in the main server environment.
2. **Static Inspection:** Attachments undergo SHA-256 lookup against VirusTotal/local threat databases, MIME-type verification, and YARA rule matching.
3. **Sanitized Storage:** Files are stored with `.quarantine` extensions in an isolated volume.

---

## 4. Platform Security Hardening

- **CORS Policies:** Configured explicitly to allow origins from the frontend domain only.
- **Input Validation:** Pydantic schemas enforce type safety and prevent SQL injection or path traversal (`../`) vulnerabilities during file uploads.
- **Secret Management:** API keys (VirusTotal, MaxMind, Web3 RPC endpoints) stored exclusively in `.env` environment variables.
