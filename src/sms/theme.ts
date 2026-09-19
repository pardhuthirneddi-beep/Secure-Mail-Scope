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

/* Graphite Forensic severity palette. Color appears only as status: muted
 * red = critical, rust/amber = high and medium, restrained green = healthy.
 * Low/info are neutral gray so no evidence ever reads as "technical blue". */
export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#c96a5a",
  high: "#c98a5a",
  medium: "#d6b35c",
  low: "#9aa3a3",
  info: "#8a8f8a",
};

export const RISK_COLOR: Record<RiskLevel, string> = {
  healthy: "#7fae8e",
  low: "#9aa3a3",
  medium: "#d6b35c",
  high: "#c98a5a",
  critical: "#c96a5a",
};

export const SEVERITY_TO_RISK: Record<Severity, RiskLevel> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "low",
};
