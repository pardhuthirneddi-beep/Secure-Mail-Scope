/**
 * SecureMailScope analysis pipeline orchestrator.
 * PCAP -> packets -> TCP sessions -> protocol classification -> STARTTLS
 * tracking -> TLS extraction -> certificate parsing -> deterministic rules
 * -> ML anomaly/risk -> evidence-linked findings and recommendations.
 */

import {
  parseCapture,
  decodePacket,
  type DecodedPacket,
} from "./pcap";
import { reconstructSessions, type TcpSegment } from "./tcp";
import {
  classifyProtocol,
  concatSegments,
  type ProtoGuess,
} from "./proto";
import { analyzeTls, type TlsAnalysis } from "./tls";
import { parseCertificateDer, type CertInfo } from "./x509";
import { RULES, ruleById } from "./rule-definitions";
import { evaluateRule, type CertEvidence, type RuleInput } from "./rule-eval";
import {
  analyzeStarttls,
  buildRecommendations,
  buildTlsHandshake,
  chainStateOf,
  contributingFeatures,
  evidenceKindForRule,
  featureRowOf,
  featuresFromSession,
  hashString,
  hexPreview,
  serverHostnameHint,
  starttlsEventKind,
  type StarttlsAnalysis,
} from "./pipeline-helpers";
import { assessSessionRisk, computePosture } from "./risk";
import {
  trainAnomalyModel,
  calibrateThreshold,
  scoreAnomaly,
  FEATURE_NAMES,
  type SessionFeatures,
} from "./ml";
import type {
  AnalysisReport,
  Anomaly,
  Capture,
  Evidence,
  Finding,
  Recommendation,
  Session,
  TlsHandshake,
  TimelineEvent,
} from "./types";
import type { EvidenceState } from "./theme";

export interface PipelineStage {
  id: string;
  label: string;
}

export const STAGES: PipelineStage[] = [
  { id: "parse", label: "Reading capture" },
  { id: "sessions", label: "Reconstructing TCP sessions" },
  { id: "proto", label: "Identifying email protocols" },
  { id: "starttls", label: "Detecting STARTTLS" },
  { id: "tls", label: "Analyzing TLS handshakes" },
  { id: "certs", label: "Validating certificates" },
  { id: "rules", label: "Evaluating cryptographic posture" },
  { id: "ml", label: "Running anomaly analysis" },
  { id: "findings", label: "Generating findings" },
];

export type OnStage = (update: { stageId: string; done: boolean }) => void;

export interface PipelineResult {
  capture: Capture;
  sessions: Session[];
  evidence: Evidence[];
  findings: Finding[];
  riskBySession: Record<string, RiskAssessment>;
  anomalies: Anomaly[];
  recommendations: Recommendation[];
  posture: ReturnType<typeof computePosture>;
  benchmark: {
    packetsProcessed: number;
    sessionsReconstructed: number;
    processingMs: number;
    bytesParsed: number;
  };
}

type RiskAssessment = import("./types").RiskAssessment;

export async function runPipeline(
  buffer: ArrayBuffer,
  fileName: string,
  onStage: OnStage,
): Promise<PipelineResult> {
  const t0 = performance.now();

  // Stage 1: parse
  const parsed = parseCapture(buffer);
  onStage({ stageId: "parse", done: true });

  // Stage 2: sessions
  const packets = parsed.packets;
  const decoded: DecodedPacket[] = packets.map((p) =>
    decodePacket(p, parsed.linkType),
  );
  const flows = reconstructSessions(parsed, decoded);
  onStage({ stageId: "sessions", done: true });

  const captureId =
    "cap_" + hashString(fileName + ":" + packets.length + ":" + (packets[0]?.ts ?? 0));
  const startTs = packets[0]?.ts ?? 0;
  const endTs = packets.length ? packets[packets.length - 1].ts : 0;
  const capture: Capture = {
    id: captureId,
    name: fileName,
    sizeBytes: buffer.byteLength,
    packetCount: packets.length,
    startTs,
    endTs,
    durationSec: Math.max(0, endTs - startTs),
    parseWarnings: parsed.parseWarnings,
    isDemo: false,
    uploadedAt: Date.now(),
  };

  const evidence: Evidence[] = [];
  const findings: Finding[] = [];
  const sessions: Session[] = [];
  const featureRows: number[][] = [];
  const featureBySession = new Map<string, SessionFeatures>();
  let sessionNo = 0;
  let bytesParsed = 0;
  for (const p of packets) bytesParsed += p.data.length;

  // Stage 3-7: per-session analysis
  for (const flow of flows) {
    sessionNo++;
    const sid = "S-" + String(sessionNo).padStart(3, "0");

    const serverIsB =
      flow.responderIp === flow.bIp && flow.responderPort === flow.bPort;
    const clientToServer: TcpSegment[] = serverIsB
      ? flow.clientToServer
      : flow.serverToClient;
    const serverToClient: TcpSegment[] = serverIsB
      ? flow.serverToClient
      : flow.clientToServer;
    const serverPort = serverIsB ? flow.bPort : flow.aPort;

    const protoGuess: ProtoGuess = classifyProtocol({
      clientToServer,
      serverToClient,
      serverPort,
    });

    const cStream = concatSegments(clientToServer, 1 << 20);
    const sStream = concatSegments(serverToClient, 1 << 20);
    const tlsAnalysis: TlsAnalysis = analyzeTls(cStream, sStream);
    const starttls: StarttlsAnalysis = analyzeStarttls({
      flowProto: protoGuess.protocol,
      clientToServer,
      serverToClient,
      tlsAnalysis,
    });

    // ---- Evidence collection ----------------------------------------------
    const sessionEvidence: Evidence[] = [];
    const addEvidence = (
      kind: Evidence["kind"],
      label: string,
      summary: string,
      state: EvidenceState,
      raw: string,
    ): string => {
      const id = "EV-" + sid + "-" + (evidence.length + sessionEvidence.length + 1);
      sessionEvidence.push({
        id,
        findingId: null,
        sessionId: sid,
        captureId,
        kind,
        label,
        summary,
        state,
        packetIndex: null,
        timestamp: null,
        raw: raw.slice(0, 512),
      });
      return id;
    };

    addEvidence(
      "endpoints",
      "Session endpoints",
      flow.initiatorIp + ":" + flow.initiatorPort + " -> " + flow.responderIp + ":" + flow.responderPort,
      "verified",
      "",
    );
    if (protoGuess.protocol !== "OTHER") {
      addEvidence(
        "protocol-classification",
        "Protocol classification",
        protoGuess.protocol + " detected. " + protoGuess.reasons.join("; "),
        "verified",
        (protoGuess.serverBanner ?? "") + " | " + (protoGuess.clientBanner ?? ""),
      );
    }
    if (starttls.trace.events.length > 0) {
      addEvidence(
        "starttls-sequence",
        "STARTTLS sequence",
        starttls.trace.events.map((e) => e.phase + ": " + e.detail).join(" | "),
        "verified",
        "",
      );
    }

    let certInfo: CertInfo | null = null;
    const certEvIds: string[] = [];
    if (tlsAnalysis.certDers.length > 0) {
      certInfo = parseCertificateDer(tlsAnalysis.certDers[0].der);
      if (certInfo.parseOk) {
        certEvIds.push(
          addEvidence(
            "certificate",
            "Server certificate",
            "Subject " + certInfo.subject + "; issuer " + certInfo.issuer + "; valid until " + isoDate(certInfo.notAfter),
            "verified",
            hexPreview(tlsAnalysis.certDers[0].der),
          ),
        );
      }
    }
    if (tlsAnalysis.negotiated) {
      addEvidence(
        "tls-version",
        "TLS version",
        tlsAnalysis.negotiated.version + " negotiated",
        "verified",
        "",
      );
      addEvidence(
        "cipher-suite",
        "Cipher suite",
        (tlsAnalysis.negotiated.cipherName ?? "unrecognized suite") + " (" + tlsAnalysis.negotiated.cipherHex + ")",
        "verified",
        "",
      );
    }
    if (tlsAnalysis.alert) {
      addEvidence(
        "alert",
        "TLS alert",
        "Alert " + tlsAnalysis.alert.description + " at level " + tlsAnalysis.alert.level,
        "verified",
        "",
      );
    }

    // ---- Session object ----------------------------------------------------
    const tls: TlsHandshake | null = buildTlsHandshake(
      tlsAnalysis,
      certInfo,
      capture.endTs,
    );
    const timeline: TimelineEvent[] = [];
    timeline.push({ ts: flow.startTs, kind: "tcp-established", label: "TCP flow observed", evidenceIds: [] });
    timeline.push({
      ts: flow.startTs,
      kind: "protocol-identified",
      label:
        protoGuess.protocol +
        " protocol detected (" +
        Math.round(protoGuess.confidence * 100) +
        "% confidence)",
      evidenceIds: [],
    });
    for (const ev of starttls.trace.events) {
      timeline.push({
        ts: flow.startTs,
        kind: starttlsEventKind(ev.phase),
        label: ev.detail,
        evidenceIds: [],
      });
    }
    if (tlsAnalysis.present) {
      timeline.push({ ts: flow.startTs, kind: "tls-started", label: "TLS record layer detected", evidenceIds: [] });
      if (tlsAnalysis.negotiated) {
        timeline.push({
          ts: flow.startTs,
          kind: "tls-negotiated",
          label: tlsAnalysis.negotiated.version + " negotiated, " + (tlsAnalysis.negotiated.cipherName ?? tlsAnalysis.negotiated.cipherHex),
          evidenceIds: [],
        });
      }
      if (tlsAnalysis.certDers.length > 0) {
        timeline.push({
          ts: flow.startTs,
          kind: "certificate-presented",
          label: tlsAnalysis.certDers.length + " certificate(s) presented by server",
          evidenceIds: [],
        });
        timeline.push({
          ts: flow.startTs,
          kind: "certificate-evaluated",
          label: certInfo?.parseOk
            ? "Certificate parsed and evaluated against certificate rules"
            : "Certificate bytes present but DER parse failed",
          evidenceIds: [],
        });
      }
    }

    const serverLabel = tls?.certificate?.cn
      ? tls.certificate.cn + " (identity claimed, not verified)"
      : "";
    const session: Session = {
      id: sid,
      captureId,
      index: sessionNo - 1,
      transport: "TCP",
      srcIp: flow.initiatorIp,
      srcPort: flow.initiatorPort,
      dstIp: flow.responderIp,
      dstPort: flow.responderPort,
      startTs: flow.startTs,
      endTs: flow.endTs,
      durationSec: Math.max(0, flow.endTs - flow.startTs),
      packetCount: flow.packetCount,
      byteCount: flow.byteCount,
      protocol: protoGuess.protocol,
      protocolConfidence: protoGuess.confidence,
      protocolReasons: protoGuess.reasons,
      detectionState: protoGuess.confidence >= 0.5 ? "verified" : "requires-investigation",
      connectionStatus: flow.status,
      serverKey: flow.responderIp,
      serverLabel,
      serverLabelState: tls?.certificate ? "verified" : "unavailable",
      tls,
      timeline,
      clientBanner: protoGuess.clientBanner,
      serverBanner: protoGuess.serverBanner,
    };
    sessions.push(session);
    evidence.push(...sessionEvidence);

    // ---- Deterministic rules ------------------------------------------------
    const certEvidence: CertEvidence | null =
      certInfo && certInfo.parseOk
        ? {
            subject: certInfo.subject,
            issuer: certInfo.issuer,
            notBefore: certInfo.notBefore,
            notAfter: certInfo.notAfter,
            sigAlgName: certInfo.sigAlgName,
            pkAlgName: certInfo.pkAlgName,
            keyBits: certInfo.keyBits,
            keyBitsState: certInfo.keyBitsState,
            sanDnsNames: certInfo.sanDnsNames,
            cn: certInfo.cn,
            isSelfSigned: certInfo.isSelfSigned,
            chainState: chainStateOf(tlsAnalysis),
            chainNote: "Full trust-chain validation unavailable from captured evidence.",
          }
        : null;
    const ruleInput: RuleInput = {
      session,
      captureEndTs: capture.endTs,
      hostnameHint: serverHostnameHint(session, certInfo),
      tls: {
        negotiatedVersion: tls?.version ?? null,
        negotiatedCipherHex: tls?.cipherHex ?? null,
        negotiatedCipherName: tls?.cipherName ?? null,
        keyExchange: tls?.keyExchange ?? null,
        forwardSecrecy: tls?.forwardSecrecy ?? null,
        clientHelloOfferedVersions: tlsAnalysis.clientHello?.offeredVersions ?? [],
        alertDescription: tlsAnalysis.alert?.description ?? null,
      },
      starttls: {
        advertised: starttls.trace.advertised,
        requested: starttls.trace.requested,
        accepted: starttls.trace.accepted,
        tlsEstablished: starttls.tlsEstablished,
        transition: starttls.trace.transition,
      },
      certificate: certEvidence,
    };

    const sessionFindings: Finding[] = [];
    for (const rule of RULES) {
      if (rule.id === "ANOM-001") continue;
      const result = evaluateRule(rule, ruleInput);
      if (!result.fired) continue;
      const fid = rule.id + "-" + sid;
      const evId = addEvidence(
        evidenceKindForRule(rule.id),
        rule.name,
        result.evidenceSummary,
        result.state,
        "",
      );
      for (const ev of sessionEvidence) {
        if (ev.id === evId) ev.findingId = fid;
      }
      sessionFindings.push({
        id: fid,
        ruleId: rule.id,
        title: rule.name,
        severity: result.severity ?? rule.severity,
        sessionId: sid,
        captureId,
        evidenceIds: [evId],
        evidenceSummary: result.evidenceSummary,
        whyItMatters: result.whyItMatters,
        confidence: result.confidence,
        confidenceState:
          result.state === "requires-investigation"
            ? "derived"
            : "verified",
        recommendedAction: rule.recommendation,
        status: "open",
        category: rule.category,
        detectedBy: "deterministic",
      });
    }
    findings.push(...sessionFindings);

    // ---- ML feature extraction ---------------------------------------------
    const features = featuresFromSession(session, sessionFindings, tlsAnalysis);
    featureBySession.set(sid, features);
    featureRows.push(featureRowOf(features));

    timeline.push({
      ts: flow.endTs,
      kind: "assessment-complete",
      label: "Security assessment stage complete",
      evidenceIds: [],
    });
  }

  onStage({ stageId: "proto", done: true });
  onStage({ stageId: "starttls", done: true });
  onStage({ stageId: "tls", done: true });
  onStage({ stageId: "certs", done: true });
  onStage({ stageId: "rules", done: true });

  // Stage 8: ML anomaly model over the capture population
  const model = trainAnomalyModel(featureRows, FEATURE_NAMES);
  const threshold = calibrateThreshold(model, featureRows);
  const anomalies: Anomaly[] = [];
  for (let i = 0; i < sessions.length; i++) {
    const session = sessions[i];
    if (!session.tls) continue;
    const row = featureRows[i];
    const scored = scoreAnomaly(model, row);
    const classification: Anomaly["classification"] =
      scored.score > threshold ? "unusual" : "normal";
    const contrib = contributingFeatures(model, row, model.featureNames);
    anomalies.push({
      sessionId: session.id,
      score: scored.score,
      classification,
      featureVector: Object.fromEntries(FEATURE_NAMES.map((k, j) => [k, row[j]])),
      contributingFeatures: contrib,
      note:
        "Isolation Forest ensemble (64 trees, seed 20260101) over " +
        featureRows.length +
        " TLS sessions. Unusual TLS behavior — investigation recommended.",
    });
    if (classification === "unusual") {
      const rule = ruleById("ANOM-001");
      if (rule) {
        const fid = rule.id + "-" + session.id;
        const evId = "EV-" + session.id + "-ANOM";
        evidence.push({
          id: evId,
          findingId: fid,
          sessionId: session.id,
          captureId,
          kind: "handshake-shape",
          label: "Anomalous TLS feature vector",
          summary:
            "Anomaly score " +
            scored.score.toFixed(2) +
            " above calibrated threshold " +
            threshold.toFixed(2) +
            ". Top contributors: " +
            contrib.slice(0, 3).map((c) => c.name).join(", "),
          state: "ai-assessed",
          packetIndex: null,
          timestamp: null,
          raw: "",
        });
        findings.push({
          id: fid,
          ruleId: "ANOM-001",
          title: rule.name,
          severity: rule.severity,
          sessionId: session.id,
          captureId,
          evidenceIds: [evId],
          evidenceSummary:
            "Anomaly score " + scored.score.toFixed(2) + " (threshold " + threshold.toFixed(2) + ")",
          whyItMatters: rule.reason,
          confidence: Math.min(0.9, scored.score),
          confidenceState: "ai-assessed",
          recommendedAction: rule.recommendation,
          status: "open",
          category: "Anomaly",
          detectedBy: "ml",
        });
      }
    }
  }
  onStage({ stageId: "ml", done: true });

  // Stage 9: risk + report assembly
  const riskBySession: Record<string, RiskAssessment> = {};
  for (const session of sessions) {
    const sFindings = findings.filter((f) => f.sessionId === session.id);
    const features = featureBySession.get(session.id);
    if (!features) continue;
    const anomaly = anomalies.find((a) => a.sessionId === session.id) ?? null;
    riskBySession[session.id] = assessSessionRisk({
      session,
      findings: sFindings,
      features,
      anomaly,
    });
    const last = session.timeline[session.timeline.length - 1];
    if (last?.kind === "assessment-complete") {
      last.label =
        "Security assessment completed (risk " + riskBySession[session.id].level + ")";
    }
  }
  const recommendations = buildRecommendations(findings);
  const posture = computePosture({ sessions, findings, anomalies });
  onStage({ stageId: "findings", done: true });

  const t1 = performance.now();
  return {
    capture,
    sessions,
    evidence,
    findings,
    riskBySession,
    anomalies,
    recommendations,
    posture,
    benchmark: {
      packetsProcessed: packets.length,
      sessionsReconstructed: sessions.length,
      processingMs: Math.round(t1 - t0),
      bytesParsed,
    },
  };
}

// Small local constants + utils -------------------------------------------

function isoDate(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

export function resultToReportSeed(
  result: PipelineResult,
  opts: { scenarioId?: string; scenarioLabel?: string; scenarioExpected?: string },
): AnalysisReport {
  const secureCount = result.sessions.filter(
    (s) =>
      (result.riskBySession[s.id]?.level ?? "healthy") === "healthy" ||
      (result.riskBySession[s.id]?.level ?? "healthy") === "low",
  ).length;
  const warningCount = result.sessions.filter((s) => {
    const lv = result.riskBySession[s.id]?.level ?? "healthy";
    return lv === "medium";
  }).length;
  const highCount = result.sessions.filter((s) => {
    const lv = result.riskBySession[s.id]?.level ?? "healthy";
    return lv === "high";
  }).length;
  const criticalCount = result.sessions.filter((s) => {
    const lv = result.riskBySession[s.id]?.level ?? "healthy";
    return lv === "critical";
  }).length;
  return {
    id: "rep_" + result.capture.id + "_" + Date.now().toString(36),
    captureId: result.capture.id,
    createdAt: Date.now(),
    sessionCount: result.sessions.length,
    secureCount,
    warningCount,
    highRiskCount: highCount,
    criticalCount,
    findings: result.findings,
    riskBySession: result.riskBySession,
    anomalies: result.anomalies,
    recommendations: result.recommendations,
    posture: result.posture,
    limitations: DISCLAIMER,
    scenarioId: opts.scenarioId,
    scenarioLabel: opts.scenarioLabel,
    scenarioExpected: opts.scenarioExpected,
  };
}

export const DISCLAIMER =
  "SecureMailScope performs passive analysis of captured network traffic. Findings are based only on evidence available in the supplied capture. Encrypted email content is not decrypted or inspected. Some certificate-chain or application-level properties may not be fully verifiable from a PCAP alone.";
