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
}

export interface GraphNode {
  id: string;
  label: 'Email' | 'Sender' | 'Domain' | 'URL' | 'IP' | 'ASN' | 'ISP' | 'Country' | 'Campaign' | 'Case' | string;
  properties: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: 'SENT_BY' | 'CONTAINS' | 'HOSTED_ON' | 'RESOLVES_TO' | 'BELONGS_TO' | 'ASSOCIATED_WITH' | 'PART_OF' | 'USES_DOMAIN' | string;
  properties?: Record<string, any>;
}

export interface GraphDataResponse {
  provider_mode: 'NEO4J_LIVE' | 'DEMO_FALLBACK' | string;
  is_neo4j_connected: boolean;
  note?: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface RelatedInvestigation {
  email_id: string;
  case_id?: string;
  case_number: string;
  case_title: string;
  subject_summary: string;
  sender_address?: string;
  threat_level?: string;
  analyzed_at?: string;
  matched_artifacts: string[];
}

export interface SharedInfrastructure {
  shared_ips: string[];
  shared_asns: string[];
  shared_isps: string[];
  shared_countries: string[];
}

export interface PotentialCampaign {
  has_potential_campaign: boolean;
  confidence_score: number;
  campaign_name: string;
  description: string;
  observed_indicators: string[];
  cautious_language_disclaimer: string;
}

export interface SharedAttachment {
  hash: string;
  filename: string;
}

export interface CorrelationResponse {
  target_email_id: string;
  correlation_status: string;
  previous_occurrences_count: number;
  related_investigations: RelatedInvestigation[];
  shared_infrastructure: SharedInfrastructure;
  shared_domains: string[];
  shared_urls: string[];
  shared_ips: string[];
  shared_attachments?: SharedAttachment[];
  potential_campaign: PotentialCampaign;
}

export interface AttributionSupportResponse {
  email_id: string;
  probable_source_infrastructure: string;
  confidence_score: number;
  confidence_percentage: string;
  supporting_evidence: string[];
  alternative_explanations: string[];
  limitations: string;
}

export interface CaseNote {
  id: string;
  author: string;
  text: string;
  timestamp: string;
}

export interface CaseRecord {
  id: string;
  case_number: string;
  title: string;
  description?: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical' | string;
  status: 'Open' | 'Investigating' | 'Resolved' | 'Closed' | string;
  assigned_analyst: string;
  investigation_count: number;
  notes: CaseNote[];
  created_at: string;
  updated_at: string;
}

export interface CustodyLogEvent {
  timestamp: string;
  user: string;
  action: 'Evidence collected' | 'Analysis performed' | 'Evidence viewed' | 'Evidence exported' | 'Report generated' | string;
  evidence_id: string;
}

export interface EvidenceRecord {
  id: string;
  case_id?: string;
  investigation_id: string;
  sha256_hash: string;
  file_name: string;
  file_size_bytes: number;
  file_path: string;
  collected_by: string;
  integrity_status: 'Verified' | 'Integrity mismatch' | string;
  chain_of_custody_logs: CustodyLogEvent[];
  created_at: string;
}

export interface IntegrityCheckResult {
  status: 'Verified' | 'Integrity mismatch' | string;
  stored_hash: string;
  recalculated_hash: string;
  file_name: string;
  evidence_id: string;
  error?: string;
}





