export type RiskLabel =
  | "Low Risk"
  | "Suspicious"
  | "High Risk"
  | "Confirmed Malicious"
  | "Inconclusive";

export type FindingSeverity = "Info" | "Low" | "Medium" | "High" | "Critical";

export interface Finding {
  id: string;
  signal_id: string;
  category: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  points: number;
  technical_evidence: Record<string, any>;
  source: string;
  potential_impact: string;
  recommendation: string;
  limitation: string;
}

export interface CheckRecord {
  check_id: string;
  status: "passed" | "flagged" | "unavailable" | "skipped";
  duration_ms: number;
  short_note: string;
}

export interface RedirectHop {
  url: string;
  status_code: number;
  registrable_domain: string;
  same_site: boolean;
}

export interface TLSReport {
  subject: string;
  san_list: string[];
  issuer: string;
  validity_start: string;
  validity_end: string;
  days_remaining: number;
  public_key_algorithm: string;
  public_key_size: number;
  signature_algorithm: string;
  certificate_sha256: string;
  spki_sha256: string;
  chain_list: string[];
  trust_result: string;
  ct_summary: Record<string, any>;
  tls_verdict: "Valid configuration" | "Configuration problems" | "Suspicious" | "Potentially compromised trust";
  https_note: string;
}

export interface SecurityHeaderResult {
  header_name: string;
  present: boolean;
  observed_value?: string;
  severity: FindingSeverity;
}

export interface ThreatIntelMatch {
  source_name: string;
  listing_status: string;
  listing_date?: string;
  threat_type?: string;
  reference_url?: string;
}

export interface ThreatIntelSummary {
  feeds_queried: string[];
  feeds_answered: string[];
  feeds_unavailable: string[];
  matches: ThreatIntelMatch[];
}

export interface CampaignInfo {
  linked: boolean;
  strength?: "strong" | "possible";
  matched_indicators: string[];
  related_report_count: number;
  first_seen?: string;
  cluster_size: number;
  ai_summary?: string;
}

export interface MessageAnalysis {
  extracted_urls: string[];
  emails: string[];
  phone_numbers: string[];
  upi_ids: string[];
  crypto_addresses: string[];
  signals_triggered: string[];
  per_url_labels: Record<string, string>;
  what_message_says: string[];
  what_checks_found: string[];
  redaction_applied: boolean;
}

export interface AIEvidencePoint {
  finding_id: string;
  explanation: string;
}

export interface AIExplanation {
  summary: string;
  evidence_points: AIEvidencePoint[];
  recommended_actions: string[];
  limitations_note: string;
  model_name: string;
  generated_by: "llm" | "fallback_template";
}

export interface EvidenceCoverage {
  percent: number;
  completed_groups: string[];
  unavailable_groups: string[];
}

export interface Web3Info {
  status: "not_committed" | "pending" | "committed";
  report_hash: string;
  tx_hash: string;
  block_number: number;
  network: string;
  chain_id: number;
  contract_address: string;
  committed_at: string;
  revision: number;
}

export interface Report {
  report_id: string;
  schema_version: number;
  created_at: string;
  input_type: "url" | "message";
  input_display: string;
  normalized_url?: string;
  registrable_domain?: string;
  final_url?: string;
  final_domain?: string;
  resolved_ips: string[];
  risk_label: RiskLabel;
  risk_score: number;
  evidence_coverage: EvidenceCoverage;
  findings: Finding[];
  checks: CheckRecord[];
  redirect_chain: RedirectHop[];
  tls?: TLSReport;
  security_headers: SecurityHeaderResult[];
  threat_intel: ThreatIntelSummary;
  campaign: CampaignInfo;
  message_analysis?: MessageAnalysis;
  ai_explanation: AIExplanation;
  recommended_actions: string[];
  limitations: string[];
  disclaimer: string;
  analysis_duration_ms: number;
  is_cached_sample?: boolean;
  is_committed?: boolean;
  web3?: Web3Info;
  report_hash?: string;
}

export interface DemoSample {
  id: string;
  group: string;
  type: "url" | "message";
  title: string;
  value: string;
  expected_label: string;
  description?: string;
}


export interface PlatformStats {
  total_scans_analyzed: number;
  threats_mitigated: number;
  active_indicators_tracked: number;
  onchain_verifications: number;
  heuristic_eval_time_ms: number;
  tamper_detection_rate: string;
  uptime_percent: number;
  threat_feeds_connected: number;
  blockchain_network: string;
}
