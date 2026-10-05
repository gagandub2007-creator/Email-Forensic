export interface Hop {
  hop_number: number;
  timestamp?: string;
  receiving_server?: string;
  sending_server?: string;
  ip_address: string;
  reverse_dns?: string;
  country: string;
  city: string;
  latitude: number;
  longitude: number;
  isp: string;
  asn: string;
  delay_seconds: number;
  is_vpn_proxy_tor: boolean;
  raw_header_reference?: string;
  infrastructure_intel?: any;
}

export interface Attachment {
  id: string;
  filename: string;
  mime_type?: string;
  file_size_bytes: number;
  sha256_hash: string;
  is_malicious: boolean;
  threat_description?: string;
}

export interface URLIntel {
  id: string;
  url: string;
  domain: string;
  is_suspicious: boolean;
  is_typosquatted: boolean;
  reputation_score: number;
  url_details?: any;
  domain_intel?: any;
  lookalike_intel?: any;
}

export interface AIAnalysis {
  classification: string;
  confidence: number;
  signals?: string[];
  model_info?: string;
}

export interface BlockchainLog {
  transaction_hash: string;
  block_number: number;
  contract_address: string;
  merkle_root: string;
  status: string;
  anchored_at: string;
}

export interface CustodyEvent {
  id: string;
  evidence_id: string;
  timestamp: string;
  user: string;
  action: string;
}

export interface EvidenceLedgerEntry {
  id: string;
  evidence_id: string;
  ledger_tx_id: string;
  evidence_hash: string;
  case_reference?: string;
  block_number: number;
  prev_block_hash?: string;
  merkle_root?: string;
  contract_address?: string;
  registered_at: string;
  verification_status: string;
  ledger_status: string;
}

export interface LedgerVerifyResult {
  evidence_id: string;
  verified: boolean;
  status: string;
  recorded_hash?: string;
  submitted_hash: string;
  block_number?: number;
  timestamp?: string;
  contract_address?: string;
}

export interface EvidenceRecord {
  id: string;
  email_id: string;
  case_id?: string;
  investigation_id?: string;
  sha256_hash: string;
  filename: string;
  file_size_bytes: number;
  created_at: string;
  collected_by: string;
  integrity_status: string;
  custody_events: CustodyEvent[];
  ledger_entry?: EvidenceLedgerEntry;
}

export interface EvidenceVerifyResult {
  evidence_id: string;
  status: string;
  stored_hash: string;
  recalculated_hash: string;
  verified_at: string;
  match: boolean;
}

export interface EmailRecord {
  id: string;
  case_id?: string;
  message_id?: string;
  subject?: string;
  sender_address?: string;
  sender_name?: string;
  recipient_address?: string;
  cc?: string;
  reply_to?: string;
  return_path?: string;
  email_date?: string;
  spf_status: string;
  spf_details?: any;
  dkim_status: string;
  dkim_details?: any;
  dmarc_status: string;
  dmarc_details?: any;
  auth_caveat: string;
  sha256_hash: string;
  overall_threat_score: number;
  threat_level: string;
  contributing_factors?: string[];
  originating_ip?: string;
  originating_country?: string;
  earliest_external_source?: string;
  x_headers?: any;
  domains?: string[];
  ipv4_addresses?: string[];
  ipv6_addresses?: string[];
  ip_intelligence?: any;
  analyzed_at: string;
  hops: Hop[];
  attachments: Attachment[];
  urls: URLIntel[];
  ai_analysis?: AIAnalysis;
  blockchain_log?: BlockchainLog;
  evidence_record?: EvidenceRecord;
}

