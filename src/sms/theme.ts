export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export type EvidenceState =
  | "verified"
  | "derived"
  | "ai-assessed"
  | "unavailable"
  | "requires-investigation";

export const EVIDENCE_STATE_LABEL: Record<EvidenceState, string> = {
  verified: "Verified",
  derived: "Derived",
  "ai-assessed": "AI-Assessed",
  unavailable: "Unavailable",
  "requires-investigation": "Requires Investigation",
};

export const EVIDENCE_STATE_DESC: Record<EvidenceState, string> = {
  verified: "Evidence directly observed in the capture.",
  derived: "Calculated from observed evidence.",
  "ai-assessed": "Produced by the ML classification layer.",
  unavailable: "Required evidence was not present in the capture.",
  "requires-investigation":
    "Evidence suggests a potential issue but does not prove malicious activity.",
};

export type RiskLevel = "healthy" | "low" | "medium" | "high" | "critical";

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#ff5c5c",
  high: "#ff8f3f",
  medium: "#ffb340",
  low: "#4cc9c9",
  info: "#8b9bb4",
};

export const RISK_COLOR: Record<RiskLevel, string> = {
  healthy: "#2fd08c",
  low: "#4cc9c9",
  medium: "#ffb340",
  high: "#ff8f3f",
  critical: "#ff5c5c",
};

export const SEVERITY_TO_RISK: Record<Severity, RiskLevel> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "low",
};
