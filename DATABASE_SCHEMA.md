# Database Schema Specification: Forensic Intelligence Platform

**SIH PS ID:** 26106  
**Relational Model (PostgreSQL / SQLite)**

---

## 1. Entity Relationship Diagram (ERD)

```mermaid
erDiagram
    CASES ||--o{ EMAILS : contains
    USERS ||--o{ CASES : manages
    EMAILS ||--o{ EMAIL_HOPS : traces
    EMAILS ||--o{ ATTACHMENTS : includes
    EMAILS ||--o{ EXTRACTED_URLS : contains
    EMAILS ||--|| AI_ANALYSIS : evaluated_by
    EMAILS ||--|| BLOCKCHAIN_LOGS : anchored_to

    USERS {
        uuid id PK
        string username
        string email
        string password_hash
        string role
        datetime created_at
    }

    CASES {
        uuid id PK
        uuid user_id FK
        string case_number
        string title
        string description
        string status
        datetime created_at
    }

    EMAILS {
        uuid id PK
        uuid case_id FK
        string message_id
        string subject
        string sender_address
        string sender_name
        string recipient_address
        datetime email_date
        text raw_headers
        text body_plain
        text body_html
        string sha256_hash
        float overall_threat_score
        string threat_level
        datetime analyzed_at
    }

    EMAIL_HOPS {
        uuid id PK
        uuid email_id FK
        int hop_number
        string ip_address
        string reverse_dns
        string country
        string city
        float latitude
        float longitude
        string isp
        string asn
        int delay_seconds
        boolean is_vpn_proxy_tor
    }

    ATTACHMENTS {
        uuid id PK
        uuid email_id FK
        string filename
        string mime_type
        int file_size_bytes
        string sha256_hash
        boolean is_malicious
        string YARA_matches
    }

    EXTRACTED_URLS {
        uuid id PK
        uuid email_id FK
        string url
        string domain
        boolean is_suspicious
        boolean is_typosquatted
        int domain_age_days
        float reputation_score
    }

    AI_ANALYSIS {
        uuid id PK
        uuid email_id FK
        float phishing_probability
        float bec_probability
        float scam_probability
        float header_anomaly_score
        json detected_keywords
        json key_phrases
    }

    BLOCKCHAIN_LOGS {
        uuid id PK
        uuid email_id FK
        string transaction_hash
        int block_number
        string contract_address
        string merkle_root
        string status
        datetime anchored_at
    }
```

---

## 2. Table Specifications

### 2.1 `cases`
Stores forensic investigation cases created by investigators.
- `id` (UUID, Primary Key)
- `case_number` (VARCHAR(50), Unique, e.g. `CASE-2026-0089`)
- `title` (VARCHAR(255))
- `description` (TEXT)
- `status` (VARCHAR(20), e.g. `OPEN`, `IN_PROGRESS`, `CLOSED`, `ARCHIVED`)
- `created_at` (TIMESTAMP)

### 2.2 `emails`
Stores core metadata and raw content hash of analyzed emails.
- `id` (UUID, Primary Key)
- `case_id` (UUID, Foreign Key -> `cases.id`)
- `message_id` (VARCHAR(255))
- `subject` (TEXT)
- `sender_address` (VARCHAR(255))
- `sender_name` (VARCHAR(255))
- `recipient_address` (VARCHAR(255))
- `email_date` (TIMESTAMP)
- `raw_headers` (TEXT)
- `sha256_hash` (VARCHAR(64), Unique - Used for Blockchain non-repudiation)
- `overall_threat_score` (FLOAT, 0.0 to 100.0)
- `threat_level` (VARCHAR(20), e.g. `CLEAN`, `SUSPICIOUS`, `HIGH_RISK`, `CRITICAL`)

### 2.3 `email_hops`
Stores sequential routing hops extracted from `Received:` headers.
- `id` (UUID, Primary Key)
- `email_id` (UUID, Foreign Key -> `emails.id`)
- `hop_number` (INTEGER, 1 = Originating server)
- `ip_address` (VARCHAR(45))
- `country` (VARCHAR(100))
- `city` (VARCHAR(100))
- `latitude` (FLOAT)
- `longitude` (FLOAT)
- `isp` (VARCHAR(255))
- `delay_seconds` (INTEGER)
- `is_vpn_proxy_tor` (BOOLEAN)

### 2.4 `blockchain_logs`
Stores immutable proof details of evidence submitted to the Smart Contract.
- `id` (UUID, Primary Key)
- `email_id` (UUID, Foreign Key -> `emails.id`)
- `transaction_hash` (VARCHAR(66))
- `block_number` (INTEGER)
- `contract_address` (VARCHAR(42))
- `merkle_root` (VARCHAR(64))
- `status` (VARCHAR(20), `CONFIRMED`, `PENDING`)
- `anchored_at` (TIMESTAMP)

---

## 3. Database Constraints & Indexes

1. **Unique Index:** `emails(sha256_hash)` to prevent duplicate forensic evidence records and speed up lookup.
2. **Composite Index:** `email_hops(email_id, hop_number)` for fast sequential rendering of route maps.
3. **Foreign Key Constraints:** Cascade deletes on `email_hops`, `attachments`, and `extracted_urls` when an `email` record is removed.
