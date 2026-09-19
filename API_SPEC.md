# API Specification: AI-Powered Email Threat Detection & Forensic Platform

**SIH PS ID:** 26106  
**RESTful API Interface Documentation (FastAPI)**

---

## 1. Authentication & Security

All protected endpoints require HTTP Bearer JWT authentication headers:
`Authorization: Bearer <access_token>`

---

## 2. API Endpoints Overview

### 2.1 Authentication & User Management
- `POST /api/v1/auth/login` - Authenticate investigator and issue JWT.
- `POST /api/v1/auth/register` - Create new investigator account (Admin only).
- `GET /api/v1/auth/me` - Fetch current active user profile.

### 2.2 Case Management
- `GET /api/v1/cases` - List forensic investigation cases.
- `POST /api/v1/cases` - Create a new forensic case.
- `GET /api/v1/cases/{case_id}` - Retrieve details of a specific case.

### 2.3 Email Forensic & Threat Ingestion Engine
- `POST /api/v1/emails/analyze`  
  **Request:** `multipart/form-data` with `.eml` or `.msg` file.  
  **Response:**
  ```json
  {
    "email_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "case_id": "3c901c80-1a2b-3c4d-5e6f-7a8b9c0d1e2f",
    "sha256_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "subject": "URGENT: Update Direct Deposit Information Immediately",
    "sender": {
      "address": "ceo-office@company-corp-scam.com",
      "display_name": "Executive Management",
      "spf_status": "FAIL",
      "dkim_status": "FAIL",
      "dmarc_status": "FAIL"
    },
    "threat_assessment": {
      "overall_score": 92.5,
      "threat_level": "CRITICAL",
      "is_bec": true,
      "is_phishing": true,
      "ai_confidence": 0.96
    },
    "total_hops": 4,
    "originating_ip": "185.220.101.5",
    "originating_country": "Germany (Tor Exit Node)"
  }
  ```

- `GET /api/v1/emails/{email_id}` - Retrieve complete email analysis.
- `GET /api/v1/emails/{email_id}/hops` - Fetch GeoJSON node array for route mapping.
- `GET /api/v1/emails/{email_id}/headers` - Fetch parsed & raw header comparison.

### 2.4 Blockchain & Chain of Custody
- `POST /api/v1/blockchain/anchor/{email_id}` - Commit evidence hash to smart contract.
- `GET /api/v1/blockchain/verify/{email_id}`  
  **Response:**
  ```json
  {
    "email_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
    "on_chain_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "local_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "is_authentic": true,
    "transaction_hash": "0x8f3c7b2a...1a",
    "block_number": 19482710,
    "contract_address": "0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
    "timestamp": "2026-09-19T11:25:00Z"
  }
  ```

### 2.5 Report Generation & Legal Evidence
- `GET /api/v1/reports/pdf/{email_id}` - Download Section 65B compliant forensic PDF report.
- `GET /api/v1/reports/json/{email_id}` - Download standardized STIX 2.1 / MISP threat report.
