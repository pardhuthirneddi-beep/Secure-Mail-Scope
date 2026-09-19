/**
 * SecureMailScope evidence-linked data model.
 *
 * Traceability chain: finding -> evidence -> session -> capture.
 * Every finding carries capture_id, session_id, evidence_ids.
 */

import type { EvidenceState, RiskLevel, Severity } from "./theme";

export interface Capture {
  id: string;
  name: string;
  sizeBytes: number;
  packetCount: number;
  startTs: number; // epoch seconds
  endTs: number; // epoch seconds
  durationSec: number;
  parseWarnings: string[];
  isDemo: boolean;
  demoScenarioId?: string;
  uploadedAt: number;
}

export interface Session {
  id: string; // e.g. "S-018"
  captureId: string;
  index: number; // 0-based order of first packet
  transport: "TCP";
  srcIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  startTs: number;
  endTs: number;
  durationSec: number;
  packetCount: number;
  byteCount: number;
  protocol: "SMTP" | "IMAP" | "POP3" | "OTHER";
  protocolConfidence: number; // 0..1
  protocolReasons: string[];
  detectionState: EvidenceState;
  connectionStatus: "completed" | "reset" | "truncated";
  serverKey: string; // server ip for grouping, evidence-based
  serverLabel: string; // e.g. hostname derived from cert CN when evidence permits
  serverLabelState: "verified" | "unavailable";
  tls: TlsHandshake | null;
  timeline: TimelineEvent[];
  clientBanner: string | null; // only from observed bytes
  serverBanner: string | null;
}

export type TimelineEventKind =
  | "tcp-established"
  | "protocol-identified"
  | "starttls-advertised"
  | "starttls-requested"
  | "starttls-accepted"
  | "starttls-failed"
  | "tls-started"
  | "tls-negotiated"
  | "tls-failed"
  | "certificate-presented"
  | "certificate-evaluated"
  | "plaintext-after-failed-starttls"
  | "assessment-complete";

export interface TimelineEvent {
  ts: number;
  kind: TimelineEventKind;
  label: string;
  evidenceIds: string[];
}

export interface TlsHandshake {
  version: string; // "TLS 1.2" | "SSL 3.0" | "TLS 1.3" ...
  versionCode: { major: number; minor: number };
  cipherHex: string; // "0x002F"
  cipherName: string | null;
  keyExchange: string | null; // "ECDHE" | "DHE" | "RSA"
  authMethod: string | null;
  bulkCipher: string | null;
  hashMac: string | null;
  forwardSecrecy: boolean | null; // null = cannot determine
  hasCertificateMessage: boolean;
  certificate: ParsedCertificate | null;
  handshakeBytes: number;
  offerCount: number;
  clientRandom: string | null;
  serverRandom: string | null;
  hasAlert: boolean;
  alertDescription: number | null;
  extendedMasterSecret: boolean;
  sessionIdPresent: boolean;
  extractionState: "complete" | "partial" | "none";
  extractionNote: string;
}
type recordUnused = boolean;
export interface ParsedCertificate {
  rawDer: Uint8Array;
  subject: string;
  issuer: string;
  serialHex: string;
  notBefore: number;
  notAfter: number;
  nowValid: boolean; // notBefore <= now <= notAtAfter at analysis time
  expiredAtAnalysis: boolean;
  notYetValidAtAnalysis: boolean;
  atCaptureTimeValid: boolean; // validity at capture end time
  validityAtCaptureState: "verified" | "unavailable";
  sigAlgOid: string;
  sigAlgName: string;
  pkAlgOid: string;
  pkAlgName: string;
  keyBits: number | null;
  keyBitsState: "verified" | "unavailable";
  sanDnsNames: string[];
  cn: string | null;
  isSelfSigned: boolean;
  chain: "single" | "chain-present" | "unavailable";
  chainLeafFirst: boolean | null;
  validationState: "verified" | "requires-investigation" | "unavailable";
  validationNote: string;
}

export interface Evidence {
  id: string;
  findingId: string | null;
  sessionId: string;
  captureId: string;
  kind:
    | "tls-version"
    | "cipher-suite"
    | "key-exchange"
    | "certificate"
    | "starttls-sequence"
    | "banner"
    | "endpoints"
    | "alert"
    | "handshake-shape"
    | "protocol-classification";
  label: string;
  summary: string;
  state: EvidenceState;
  packetIndex: number | null;
  timestamp: number | null;
  raw: string; // short hex/ascii excerpt of the observed bytes
}

export interface Finding {
  id: string; // e.g. "TLS-001-S018"
  ruleId: string; // "TLS-001"
  title: string;
  severity: Severity;
  sessionId: string;
  captureId: string;
  evidenceIds: string[];
  evidenceSummary: string;
  whyItMatters: string;
  confidence: number; // 0..1, derived from rule evidence quality
  confidenceState: "verified" | "derived" | "ai-assessed";
  recommendedAction: string;
  status: "open" | "acknowledged";
  category: "TLS" | "Certificate" | "STARTTLS" | "Anomaly" | "Protocol";
  detectedBy: "deterministic" | "ml";
}

export interface RiskAssessment {
  sessionId: string;
  level: RiskLevel;
  score: number; // 0..100
  factors: Array<{ label: string; weight: number; source: string }>;
  anomalyScore: number | null; // from Isolation-Forest-like model
  anomalyClass: "normal" | "unusual" | "unavailable";
  mlRisk: RiskLevel | null;
  mlConfidence: number | null;
  confidenceState: "verified" | "derived" | "ai-assessed" | "unavailable";
  rationale: string;}

export interface Anomaly {
  sessionId: string;
  score: number; // 0..1 (higher = more anomalous)
  classification: "normal" | "unusual";
  featureVector: Record<string, number>;
  contributingFeatures: Array<{ name: string; direction: string; value: number }>;
  note: string;
}

export interface Recommendation {
  id: string;
  rank: number;
  title: string;
  severity: Severity;
  affectedSessions: string[];
  why: string;
  action: string;
  ruleIds: string[];
  category: Finding["category"];
}

export interface PostureScore {
  category: string;
  score: number; // 0..100
  method: string; // "How this score was calculated"
  basisCount: number; // sessions contributing
}

export interface AnalysisReport {
  id: string;
  captureId: string;
  createdAt: number;
  sessionCount: number;
  secureCount: number;
  warningCount: number;
  highRiskCount: number;
  criticalCount: number;
  findings: Finding[];
  riskBySession: Record<string, RiskAssessment>;
  anomalies: Anomaly[];
  recommendations: Recommendation[];
  posture: PostureScore[];
  limitations: string;
  scenarioId?: string;
  scenarioLabel?: string;
  scenarioExpected?: string;
}


