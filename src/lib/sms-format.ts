import type { AnalysisReport, Evidence, Finding, Session } from "@/sms/types";
import type { RiskLevel, Severity } from "@/sms/theme";

/**
 * Formatting, serialization, and export helpers shared by the app pages.
 * Everything here is presentation-only: analysis data is produced by the
 * evidence-driven pipeline in src/sms.
 */

export function formatBytes(n: number): string {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / (1024 * 1024)).toFixed(2) + " MB";
}

export function formatDuration(sec: number): string {
  if (sec < 1) return Math.round(sec * 1000) + " ms";
  if (sec < 60) return sec.toFixed(1) + " s";
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return m + "m " + s + "s";
}

export function formatTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
}

export function formatDate(ms: number): string {
  return new Date(ms).toISOString().replace("T", " ").slice(0, 16) + " UTC";
}

const SEVERITY_TOKEN: Record<Severity, string> = {
  critical: "text-(--sms-critical) border-(--sms-critical)/40 bg-(--sms-critical)/10",
  high: "text-(--sms-high) border-(--sms-high)/40 bg-(--sms-high)/10",
  medium: "text-(--sms-medium) border-(--sms-medium)/40 bg-(--sms-medium)/10",
  low: "text-(--sms-low) border-(--sms-low)/40 bg-(--sms-low)/10",
  info: "text-muted-foreground border-border bg-muted",
};

const RISK_TOKEN: Record<RiskLevel, string> = {
  healthy: "text-(--sms-healthy) border-(--sms-healthy)/40 bg-(--sms-healthy)/10",
  low: "text-(--sms-low) border-(--sms-low)/40 bg-(--sms-low)/10",
  medium: "text-(--sms-medium) border-(--sms-medium)/40 bg-(--sms-medium)/10",
  high: "text-(--sms-high) border-(--sms-high)/40 bg-(--sms-high)/10",
  critical: "text-(--sms-critical) border-(--sms-critical)/40 bg-(--sms-critical)/10",
};

export function severityClass(s: Severity): string {
  return SEVERITY_TOKEN[s];
}

export function riskClass(r: RiskLevel): string {
  return RISK_TOKEN[r];
}

export function riskLabel(r: RiskLevel): string {
  return r.charAt(0).toUpperCase() + r.slice(1);
}

/** Deserialize the report + session payloads stored in Convex. */
export interface StoredCapturePayload {
  report: AnalysisReport;
  sessions: Session[];
  evidence: Evidence[];
}

export function parseCapturePayload(
  reportJson: string,
  sessionsJson: string,
): StoredCapturePayload | null {
  try {
    const report = JSON.parse(reportJson) as AnalysisReport;
    const sess = JSON.parse(sessionsJson) as { sessions: Session[]; evidence: Evidence[] };
    return { report, sessions: sess.sessions ?? [], evidence: sess.evidence ?? [] };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Report exports
// ---------------------------------------------------------------------------

const findingHeading: Record<Severity, string> = {
  critical: "Critical findings",
  high: "High findings",
  medium: "Medium findings",
  low: "Low findings",
  info: "Informational",
};

/**
 * Render the analysis report as a standalone Markdown document suitable for
 * client remediation workflows. Every claim in the report is quoted from the
 * evidence produced by the pipeline.
 */
export function buildMarkdownReport(
  report: AnalysisReport,
  captureName: string,
  meta: { sizeBytes: number; packetCount: number; durationSec: number; isDemo: boolean },
): string {
  const L: string[] = [];
  const counts = [
    report.criticalCount + " critical",
    report.highRiskCount + " high",
    report.warningCount + " medium",
  ].join(", ");
  L.push("# SecureMailScope — Posture Report");
  L.push("");
  L.push("AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications.");
  L.push("");
  L.push("## Capture");
  L.push("");
  L.push("- **File:** " + captureName + (meta.isDemo ? " (generated demonstration capture)" : ""));
  L.push("- **Size:** " + formatBytes(meta.sizeBytes) + " · " + meta.packetCount + " packets · " + formatDuration(meta.durationSec) + " captured");
  L.push("- **Analyzed:** " + formatDate(report.createdAt));
  L.push("- **Email sessions reconstructed:** " + report.sessionCount);
  L.push("- **Findings:** " + report.findings.length + " (" + counts + ")");
  L.push("");

  L.push("## Posture summary");
  L.push("");
  if (report.posture.length === 0) {
    L.push("_No posture categories were measurable in this capture._");
  } else {
    L.push("| Category | Score | Basis | Method |");
    L.push("| --- | --- | --- | --- |");
    for (const p of report.posture) {
      L.push(
        "| " + p.category + " | " + p.score + "% | " + p.basisCount + " sessions | " + p.method + " |",
      );
    }
  }
  L.push("");

  const bySeverity = (["critical", "high", "medium", "low", "info"] as Severity[])
    .map((s) => ({ s, items: report.findings.filter((f) => f.severity === s) }))
    .filter((g) => g.items.length > 0);

  if (bySeverity.length === 0) {
    L.push("## Findings");
    L.push("");
    L.push("No rule findings were detected in this capture. Sessions that present a TLS record layer with a modern configuration produce no findings by design.");
    L.push("");
  } else {
    for (const group of bySeverity) {
      L.push("## " + findingHeading[group.s]);
      L.push("");
      for (const f of group.items) {
        L.push("### [" + f.ruleId + "] " + f.title + " — session " + f.sessionId);
        L.push("");
        L.push("- **Evidence (observed):** " + f.evidenceSummary);
        L.push("- **Why it matters:** " + f.whyItMatters);
        L.push("- **Recommended action:** " + f.recommendedAction);
        L.push("- **Confidence:** " + Math.round(f.confidence * 100) + "% (" + f.confidenceState + ")");
        L.push("");
      }
    }
  }

  const risky = Object.values(report.riskBySession).sort((a, b) => b.score - a.score);
  if (risky.length > 0) {
    L.push("## Session risk");
    L.push("");
    L.push("| Session | Level | Score | Basis |");
    L.push("| --- | --- | --- | --- |");
    for (const r of risky) {
      L.push("| " + r.sessionId + " | " + riskLabel(r.level) + " | " + r.score + "/100 | " + r.rationale + " |");
    }
    L.push("");
  }

  if (report.recommendations.length > 0) {
    L.push("## Prioritized remediation");
    L.push("");
    let i = 1;
    for (const rec of report.recommendations) {
      L.push(
        i + ". **" + rec.title + "** (" + rec.severity + ", " + rec.affectedSessions.length + " session" + (rec.affectedSessions.length === 1 ? "" : "s") + ")",
      );
      L.push("   - Why: " + rec.why);
      L.push("   - Action: " + rec.action);
      i++;
    }
    L.push("");
  }

  L.push("## Scope and limitations");
  L.push("");
  L.push(report.limitations);
  L.push("");
  L.push("---");
  L.push("");
  L.push("_Generated by SecureMailScope. Findings are traceable to packet evidence captured in the supplied PCAP; nothing in this report is inferred beyond the captured data._");
  return L.join("\n");
}

/** Compact JSON export of the full analysis result. */
export function buildJsonExport(
  report: AnalysisReport,
  sessions: Session[],
  evidence: Evidence[],
): string {
  return JSON.stringify(
    { report, sessions, evidence, exportedAt: new Date().toISOString() },
    null,
    2,
  );
}

export function downloadText(filename: string, text: string, mime = "text/plain"): void {
  const blob = new Blob([text], { type: mime + ";charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function safeFileStem(name: string): string {
  return (name.replace(/\.(pcap|pcapng)$/i, "") || "capture")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .slice(0, 64);
}

/** Evidence lookup grouped by session for the session detail view. */
export function evidenceForSession(evidence: Evidence[], sessionId: string): Evidence[] {
  return evidence.filter((e) => e.sessionId === sessionId);
}

export function findingsForSession(findings: Finding[], sessionId: string): Finding[] {
  return findings.filter((f) => f.sessionId === sessionId);
}

export function sessionTitle(s: Session): string {
  const dir = s.srcIp + ":" + s.srcPort + " → " + s.dstIp + ":" + s.dstPort;
  return s.id + " · " + s.protocol + " · " + dir;
}
