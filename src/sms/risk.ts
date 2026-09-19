/**
 * Risk engine. Deterministic findings and ML output are combined with an
 * explicit, explainable policy. Every contributing factor is labeled with
 * its source (deterministic evidence vs AI-assessed).
 */

import { SEVERITY_ORDER } from "./theme";
import type { RiskLevel, Severity } from "./theme";
import type { Anomaly, Finding, RiskAssessment, Session } from "./types";
import { riskModelPredict, type RiskLabel, type SessionFeatures } from "./ml";

export const RISK_LEVEL_ORDER: Record<RiskLevel, number> = {
  healthy: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function severityToRisk(sev: Severity): RiskLevel {
  switch (sev) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    default:
      return "low";
  }
}

export function maxLevel(a: RiskLevel, b: RiskLevel): RiskLevel {
  return RISK_LEVEL_ORDER[a] >= RISK_LEVEL_ORDER[b] ? a : b;
}

export function mlLabelToRisk(label: RiskLabel): RiskLevel {
  switch (label) {
    case "Critical":
      return "critical";
    case "High":
      return "high";
    case "Medium":
      return "medium";
    default:
      return "low";
  }
}

/** Deterministic score from finding severities (0..100). */
function deterministicScore(findings: Finding[]): number {
  let score = 0;
  for (const f of findings) {
    switch (f.severity) {
      case "critical":
        score += 40;
        break;
      case "high":
        score += 22;
        break;
      case "medium":
        score += 10;
        break;
      default:
        score += 3;
    }
  }
  return Math.min(100, score);
}

function scoreToBand(score: number, mlScore: number, level: RiskLevel): number {
  // Final numeric score: max of deterministic and ML contributions, then
  // nudged to sit consistently inside the declared level band.
  const raw = Math.max(score, Math.round(mlScore));
  const bands: Record<RiskLevel, [number, number]> = {
    healthy: [0, 9],
    low: [10, 39],
    medium: [40, 69],
    high: [70, 89],
    critical: [90, 100],
  };
  const [lo, hi] = bands[level];
  if (raw < lo) return lo;
  if (raw > hi) return hi;
  return raw;
}

export interface RiskComputationInput {
  session: Session;
  findings: Finding[];
  features: SessionFeatures;
  anomaly: Anomaly | null;
}

export function assessSessionRisk(input: RiskComputationInput): RiskAssessment {
  const { session, findings, features, anomaly } = input;
  const detFindings = findings.filter((f) => f.detectedBy === "deterministic");

  // Deterministic level
  let detLevel: RiskLevel = "healthy";
  for (const f of detFindings) {
    detLevel = maxLevel(detLevel, severityToRisk(f.severity));
  }

  // ML level
  const ml = riskModelPredict(features);
  const mlLevel = mlLabelToRisk(ml.label);

  // Anomaly influence: an "unusual" classification is a contributing factor;
  // it elevates the narrative but does not exceed HIGH on its own.
  let anomalyLevel: RiskLevel = "healthy";
  if (anomaly && anomaly.classification === "unusual") {
    anomalyLevel = detLevel === "healthy" ? "medium" : maxLevel(detLevel, "medium");
  }

  const finalLevel = maxLevel(maxLevel(detLevel, mlLevel), anomalyLevel);

  const factors: RiskAssessment["factors"] = [];
  for (const f of detFindings) {
    factors.push({
      label: f.title,
      weight: SEVERITY_ORDER[f.severity],
      source: "deterministic: " + f.evidenceSummary,
    });
  }
  const topMl = ml.contributions.slice(0, 4);
  for (const c of topMl) {
    factors.push({
      label: "ML factor: " + c.feature,
      weight: Math.abs(c.contribution),
      source: "ai-assessed contribution " + c.contribution.toFixed(2),
    });
  }
  if (anomaly && anomaly.classification === "unusual") {
    factors.push({
      label: "Unusual TLS behavior (anomaly score " + anomaly.score.toFixed(2) + ")",
      weight: 2,
      source: "ai-assessed anomaly model",
    });
  }
  if (factors.length === 0) {
    factors.push({
      label: "No security findings detected",
      weight: 0,
      source: "deterministic",
    });
  }

  const detScore = deterministicScore(detFindings);
  const finalScore = scoreToBand(detScore, ml.pUrgent * 100, finalLevel);

  const levelSource = finalLevel === detLevel
    ? "deterministic findings"
    : finalLevel === mlLevel
      ? "ML risk classification (AI-Assessed)"
      : "anomaly classification (AI-Assessed)";

  const rationale =
    "Level " +
    finalLevel.toUpperCase() +
    " driven primarily by " +
    levelSource +
    ". Deterministic score " +
    detScore +
    "/100 from " +
    detFindings.length +
    " finding(s); ML urgency probability " +
    (ml.pUrgent * 100).toFixed(0) +
    "%." +
    (anomaly
      ? " Anomaly score " + anomaly.score.toFixed(2) + " (" + anomaly.classification + ")."
      : " No anomaly signal.");

  return {
    sessionId: session.id,
    level: finalLevel,
    score: finalScore,
    factors,
    anomalyScore: anomaly ? anomaly.score : null,
    anomalyClass: anomaly ? anomaly.classification : "unavailable",
    mlRisk: mlLevel,
    mlConfidence: ml.pUrgent,
    confidenceState: detFindings.length > 0 ? "verified" : "ai-assessed",
    rationale,
  };
}

export interface PostureInput {
  sessions: Session[];
  findings: Finding[];
  anomalies: Anomaly[];
}

export interface PostureResult {
  category: string;
  score: number;
  method: string;
  basisCount: number;
}

export function computePosture(input: PostureInput): PostureResult[] {
  const { sessions, findings, anomalies } = input;
  const email = sessions.filter((s) => s.protocol !== "OTHER");
  const tlsSessions = sessions.filter((s) => s.tls !== null);
  const withCert = sessions.filter(
    (s) => s.tls?.certificate !== null && s.tls?.certificate !== undefined,
  );
  const has = (sid: string, rule: string) =>
    findings.some((f) => f.sessionId === sid && f.ruleId === rule);

  const pct = (good: number, total: number): number | null =>
    total === 0 ? null : Math.round((good / total) * 100);

  const transport = pct(
    email.filter((s) => s.tls !== null).length,
    email.length,
  );
  const cert = pct(
    withCert.filter(
      (s) =>
        !has(s.id, "CERT-001") && !has(s.id, "CERT-002") && !has(s.id, "CERT-003"),
    ).length,
    withCert.length,
  );
  const proto = pct(
    email.filter((s) => !has(s.id, "PROTO-001") && !has(s.id, "STARTTLS-001"))
      .length,
    email.length,
  );
  const tlsConf = pct(
    tlsSessions.filter(
      (s) =>
        !has(s.id, "TLS-001") &&
        !has(s.id, "TLS-002") &&
        !has(s.id, "TLS-003") &&
        !has(s.id, "TLS-004"),
    ).length,
    tlsSessions.length,
  );
  const anomaly = anomalies.length
    ? pct(
        anomalies.filter((a) => a.classification === "normal").length,
        anomalies.length,
      )
    : null;

  const out: PostureResult[] = [];
  if (transport !== null) {
    out.push({
      category: "Transport Security",
      score: transport,
      method: "Share of email sessions where a TLS record layer was established, from observed evidence.",
      basisCount: email.length,
    });
  }
  if (cert !== null) {
    out.push({
      category: "Certificate Security",
      score: cert,
      method: "Share of TLS sessions whose presented certificate produced no certificate rule finding (CERT-001/002/003).",
      basisCount: withCert.length,
    });
  }
  if (proto !== null) {
    out.push({
      category: "Protocol Security",
      score: proto,
      method: "Share of email sessions with no plaintext-transport or unsafe STARTTLS finding.",
      basisCount: email.length,
    });
  }
  if (tlsConf !== null) {
    out.push({
      category: "TLS Configuration",
      score: tlsConf,
      method: "Share of TLS sessions with no TLS version, cipher, forward-secrecy or downgrade finding.",
      basisCount: tlsSessions.length,
    });
  }
  if (anomaly !== null) {
    out.push({
      category: "Anomaly Status",
      score: anomaly,
      method: "Share of sessions whose ML anomaly classification is normal.",
      basisCount: anomalies.length,
    });
  }
  return out;
}
