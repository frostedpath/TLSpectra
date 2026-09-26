export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type ConfidenceLevel = 'DIRECT' | 'HIGH CONFIDENCE' | 'MEDIUM CONFIDENCE' | 'EXTERNAL VALIDATION' | 'UNKNOWN';
export type VisibilityState = 'OBSERVED' | 'NOT_OBSERVED' | 'NOT_APPLICABLE' | 'UNKNOWN' | 'NOT_OBSERVABLE';

export interface Capture {
  capture_id: string;
  filename: string;
  size_bytes: number;
  status: 'QUEUED' | 'PROCESSING' | 'COMPLETE' | 'FAILED' | 'PARTIAL';
  completeness: number;
  uploaded_at: string;
  processed_at?: string;
  error_message?: string;
  error_stage?: string;
  processing_stage: string;
  passive_visibility_rate: number;
}

export interface CaptureList {
  items: Capture[];
  total: number;
  limit: number;
  cursor?: string;
}

export interface Certificate {
  cert_id: string;
  handshake_id: string;
  subject?: string;
  issuer?: string;
  san: string[];
  not_before?: string;
  not_after?: string;
  public_key_alg?: string;
  key_bits?: number;
  signature_alg?: string;
  basic_constraints?: string;
  key_usage?: string;
  extended_key_usage?: string;
  chain_position: number;
  is_self_signed: boolean;
}

export interface TLSHandshake {
  handshake_id: string;
  session_id: string;
  version?: string;
  cipher_suite?: string;
  key_exchange?: string;
  forward_secrecy: boolean;
  sni?: string;
  alpn?: string;
  supported_groups: string[];
  signature_algorithm?: string;
  session_resumption: boolean;
  handshake_sequence: string[];
  alerts: Array<{ level: string; description: string; code: number }>;
  ja3_fingerprint?: string;
  ja3s_fingerprint?: string;
  duration_ms: number;
  certificates: Certificate[];
}

export interface Session {
  session_id: string;
  capture_id: string;
  host_id?: string;
  protocol: string;
  protocol_confidence: string;
  client_ip: string;
  client_port: number;
  server_ip: string;
  server_port: number;
  starttls_state: string;
  capture_completeness: number;
  start_time?: string;
  end_time?: string;
  packet_count: number;
  byte_count: number;
  auth_observed: boolean;
  auth_plaintext: boolean;
  handshake?: TLSHandshake;
}

export interface SessionList {
  items: Session[];
  total: number;
  limit: number;
  cursor?: string;
  starttls_counts?: Record<string, number>;
}

export interface Finding {
  finding_id: string;
  capture_id: string;
  session_id?: string;
  rule_id: string;
  ml_model_id?: string;
  title: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  protocol?: string;
  evidence_json: Record<string, any>;
  impact: string;
  recommendation: string;
  limitations_json: Record<string, any>;
  standards_ref: string;
  category: string;
  analyst_feedback?: string;
  analyst_notes?: string;
}

export interface FindingList {
  items: Finding[];
  total: number;
  limit: number;
  cursor?: string;
  severity_counts?: Record<string, number>;
}

export interface Host {
  host_id: string;
  capture_id: string;
  ip: string;
  hostname?: string;
  session_count: number;
  posture_score?: number;
}

export interface HostList {
  items: Host[];
  total: number;
  limit: number;
  cursor?: string;
}

export interface ScoreBreakdownItem {
  category: string;
  deduction: number;
  findings_count: number;
  grouped_rules: string[];
}

export interface ScoreAuditItem {
  session_id: string;
  category: string;
  primary_rule: string;
  primary_severity: string;
  findings_count: number;
  deduction: number;
  all_rules: string[];
}

export interface ScoreData {
  score_id: string;
  scope: string;
  scope_id: string;
  posture_score: number;
  breakdown: ScoreBreakdownItem[];
  audit_trail: ScoreAuditItem[];
  disclaimer: string;
}

export interface Policy {
  tls_min_version: string;
  cert_max_validity_days: number;
  rsa_min_key_bits: number;
  ec_min_key_bits: number;
  allow_self_signed: boolean;
  require_forward_secrecy: boolean;
  require_starttls: boolean;
  repeated_failures_threshold: number;
  scoring_weights: Record<string, number>;
}
