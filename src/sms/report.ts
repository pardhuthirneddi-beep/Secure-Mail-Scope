/**
 * Report generation: machine-readable JSON and standalone HTML.
 * Every value comes from the analysis result — no fabricated metrics.
 */

import { DISCLAIMER, type PipelineResult } from "./pipeline";
import type { AnalysisReport } from "./types";

export function buildJsonReport(
  result: PipelineResult,
  report: AnalysisReport,
): string {
  return JSON.stringify(
    {
      tool: "SecureMailScope",
      subtitle: "AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
      generatedAt: new Date().toISOString(),
      capture: {
        name: result.capture.name,
        sizeBytes: result.capture.sizeBytes,
        packetCount: result.capture.packetCount,
        startTs: new Date(result.capture.startTs * 1000).toISOString(),
        endTs: new Date(result.capture.endTs * 1000).toISOString(),
        durationSec: Number(result.capture.durationSec.toFixed(3)),
        parseWarnings: result.capture.parseWarnings,
      },
      benchmark: {
        ...result.benchmark,
        throughputPacketsPerSec: Math.round(
          result.benchmark.packetsProcessed / Math.max(0.001, result.benchmark.processingMs / 1000),
        ),
      },
      sessions: result.sessions.map((s) => ({
        id: s.id,
        protocol: s.protocol,
        protocolConfidence: s.protocolConfidence,
        src: s.srcIp + ":" + s.srcPort,
        dst: s.dstIp + ":" + s.dstPort,
        packetCount: s.packetCount,
        byteCount: s.byteCount,
        durationSec: Number(s.durationSec.toFixed(3)),
        status: s.connectionStatus,
        risk: report.riskBySession[s.id] ?? null,
        tls: s.tls
          ? {
              version: s.tls.version,
              cipherSuite: s.tls.cipherName ?? s.tls.cipherHex,
              keyExchange: s.tls.keyExchange,
              forwardSecrecy: s.tls.forwardSecrecy,
              certificate: s.tls.certificate
                ? {
                    subject: s.tls.certificate.subject,
                    issuer: s.tls.certificate.issuer,
                    notBefore: new Date(s.tls.certificate.notBefore * 1000).toISOString(),
                    notAfter: new Date(s.tls.certificate.notAfter * 1000).toISOString(),
                    signatureAlgorithm: s.tls.certificate.sigAlgName,
                    keyBits: s.tls.certificate.keyBits,
                  }
                : null,
              extractionState: s.tls.extractionState,
              extractionNote: s.tls.extractionNote,
            }
          : null,
      })),
      findings: result.findings.map((f) => ({
        findingId: f.id,
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        sessionId: f.sessionId,
        captureId: f.captureId,
        evidenceIds: f.evidenceIds,
        evidenceSummary: f.evidenceSummary,
        whyItMatters: f.whyItMatters,
        confidence: f.confidence,
        confidenceState: f.confidenceState,
        recommendedAction: f.recommendedAction,
        detectedBy: f.detectedBy,
        category: f.category,
      })),
      evidence: result.evidence.map((e) => ({
        id: e.id,
        sessionId: e.sessionId,
        findingId: e.findingId,
        kind: e.kind,
        label: e.label,
        summary: e.summary,
        state: e.state,
      })),
      anomalies: result.anomalies,
      posture: result.posture,
      recommendations: result.recommendations,
      summary: {
        sessionCount: report.sessionCount,
        secureCount: report.secureCount,
        warningCount: report.warningCount,
        highRiskCount: report.highRiskCount,
        criticalCount: report.criticalCount,
      },
      scenario: report.scenarioId
        ? {
            id: report.scenarioId,
            label: report.scenarioLabel,
            expected: report.scenarioExpected,
          }
        : null,
      limitations: DISCLAIMER,
    },
    null,
    2,
  );
}

function esc(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export function buildHtmlReport(
  result: PipelineResult,
  report: AnalysisReport,
): string {
  const fmtTime = (ts: number) => new Date(ts * 1000).toISOString().replace("T", " ").slice(0, 19) + " UTC";
  const sevClass = (sev: string) =>
    sev === "critical"
      ? "crit"
      : sev === "high"
        ? "high"
        : sev === "medium"
          ? "med"
          : "low";

  const sessionRows = result.sessions
    .map((s) => {
      const risk = report.riskBySession[s.id];
      return `<tr>
        <td>${esc(s.id)}</td>
        <td>${esc(s.protocol)}</td>
        <td>${esc(s.srcIp + ":" + s.srcPort)} &rarr; ${esc(s.dstIp + ":" + s.dstPort)}</td>
        <td>${s.packetCount}</td>
        <td>${risk ? esc(risk.level.toUpperCase()) : "—"}</td>
        <td>${s.tls ? esc(s.tls.version) : "No TLS"}</td>
      </tr>`;
    })
    .join("\n");

  const findingRows = result.findings
    .map(
      (f) => `<tr>
        <td><span class="sev ${sevClass(f.severity)}">${esc(f.severity.toUpperCase())}</span></td>
        <td>${esc(f.id)}</td>
        <td>${esc(f.title)}</td>
        <td>${esc(f.sessionId)}</td>
        <td>${esc(f.evidenceSummary)}</td>
        <td>${f.detectedBy === "ml" ? "AI-Assessed" : "Verified"}</td>
      </tr>`,
    )
    .join("\n");

  const postureRows = result.posture
    .map(
      (p) => `<tr>
        <td>${esc(p.category)}</td>
        <td>${p.score}%</td>
        <td>${esc(p.method)}</td>
        <td>${p.basisCount} sessions</td>
      </tr>`,
    )
    .join("\n");

  const anomalyRows = result.anomalies
    .filter((a) => a.classification !== "normal")
    .map(
      (a) => `<tr>
        <td>${esc(a.sessionId)}</td>
        <td>${a.score.toFixed(2)}</td>
        <td>Unusual</td>
        <td>${esc(a.note)}</td>
      </tr>`,
    )
    .join("\n");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecureMailScope Report — ${esc(result.capture.name)}</title>
<style>
  body { background: #0b0f14; color: #d7dee8; font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; margin: 0; padding: 32px; }
  h1, h2 { color: #e8eef6; font-family: "Inter", system-ui, sans-serif; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  h2 { font-size: 15px; text-transform: uppercase; letter-spacing: 0.08em; color: #59c2c9; border-bottom: 1px solid #1e2733; padding-bottom: 6px; margin-top: 28px; }
  .sub { color: #8b9bb4; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 12.5px; }
  th { text-align: left; color: #8b9bb4; font-weight: 500; border-bottom: 1px solid #1e2733; padding: 6px 8px; text-transform: uppercase; font-size: 11px; letter-spacing: 0.06em; }
  td { border-bottom: 1px solid #141b24; padding: 6px 8px; vertical-align: top; }
  .sev { padding: 1px 7px; border-radius: 3px; font-size: 11px; font-weight: 600; }
  .crit { background: #3d1518; color: #ff5c5c; border: 1px solid #7a2a2f; }
  .high { background: #38230f; color: #ff8f3f; border: 1px solid #7a4a20; }
  .med { background: #362c10; color: #ffb340; border: 1px solid #6e581f; }
  .low { background: #10282a; color: #4cc9c9; border: 1px solid #1f4a4d; }
  .box { border: 1px solid #1e2733; background: #10161d; border-radius: 6px; padding: 14px 16px; margin-top: 12px; }
  .kv { display: grid; grid-template-columns: 220px 1fr; row-gap: 4px; font-size: 13px; }
  .kv div:nth-child(odd) { color: #8b9bb4; }
  .limit { font-size: 12.5px; color: #9aa7ba; border-left: 3px solid #2a3644; padding-left: 12px; }
</style>
</head>
<body>
<h1>SecureMailScope — Security Assessment Report</h1>
<div class="sub">AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications</div>

<h2>Capture</h2>
<div class="box kv">
  <div>Capture file</div><div>${esc(result.capture.name)}</div>
  <div>Packets</div><div>${result.capture.packetCount}</div>
  <div>Duration</div><div>${result.capture.durationSec.toFixed(2)} s</div>
  <div>First packet</div><div>${fmtTime(result.capture.startTs)}</div>
  <div>Last packet</div><div>${fmtTime(result.capture.endTs)}</div>
  <div>Analysis time</div><div>${(result.benchmark.processingMs / 1000).toFixed(2)} s (${result.benchmark.packetsProcessed} packets, ${result.benchmark.sessionsReconstructed} sessions)</div>
</div>

<h2>Session Summary</h2>
<div class="box kv">
  <div>Sessions analyzed</div><div>${report.sessionCount}</div>
  <div>Healthy / low</div><div>${report.secureCount}</div>
  <div>Medium</div><div>${report.warningCount}</div>
  <div>High</div><div>${report.highRiskCount}</div>
  <div>Critical</div><div>${report.criticalCount}</div>
</div>

<h2>Security Posture</h2>
<table>
  <tr><th>Category</th><th>Score</th><th>How this score was calculated</th><th>Basis</th></tr>
  ${postureRows}
</table>

<h2>Findings</h2>
<table>
  <tr><th>Severity</th><th>Finding ID</th><th>Title</th><th>Session</th><th>Evidence</th><th>Detected by</th></tr>
  ${findingRows || '<tr><td colspan="6">No findings</td></tr>'}
</table>

<h2>Anomalies (unusual only)</h2>
<table>
  <tr><th>Session</th><th>Score</th><th>Classification</th><th>Note</th></tr>
  ${anomalyRows || '<tr><td colspan="4">No unusual TLS behavior classified</td></tr>'}
</table>

<h2>Recommendations</h2>
${result.recommendations
  .map(
    (r, i) => `<div class="box">
  <strong>${i + 1}. ${esc(r.title)}</strong> <span class="sev ${sevClass(r.severity)}">${esc(r.severity.toUpperCase())}</span><br>
  <span class="sub">Affected: ${r.affectedSessions.length} session(s) — ${esc(r.affectedSessions.join(", "))}</span><br>
  Why: ${esc(r.why)}<br>
  Action: ${esc(r.action)}
</div>`,
  )
  .join("\n") || '<div class="box">No recommendations</div>'}

<h2>Sessions</h2>
<table>
  <tr><th>ID</th><th>Protocol</th><th>Endpoints</th><th>Packets</th><th>Risk</th><th>TLS</th></tr>
  ${sessionRows}
</table>

<h2>Limitations</h2>
<p class="limit">${esc(DISCLAIMER)}</p>
</body>
</html>`;
}

export function downloadBlob(content: string | Uint8Array, mime: string, fileName: string) {
  const blob =
    content instanceof Uint8Array
      ? new Blob([content.slice().buffer as ArrayBuffer], { type: mime })
      : new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = fileName;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
