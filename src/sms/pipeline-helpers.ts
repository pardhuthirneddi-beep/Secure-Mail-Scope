/**
 * Helpers for the analysis pipeline. Kept separate to keep the orchestrator
 * readable. All functions are pure and evidence-driven.
 */

import type { TlsAnalysis } from "./tls";
import type { CertInfo } from "./x509";
import type { StarttlsTrace, EmailProtocol } from "./proto";
import { detectStarttls } from "./proto";
import type { TcpSegment } from "./tcp";
import { FEATURE_NAMES, type SessionFeatures } from "./ml";
import { ruleById } from "./rule-definitions";
import type { AnomalyModel } from "./ml";
import type {
  Evidence,
  Finding,
  ParsedCertificate,
  Recommendation,
  TlsHandshake,
  TimelineEvent,
} from "./types";
import type { Severity } from "./theme";

const severityRank: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
};

export function buildTlsHandshake(
  tlsAnalysis: TlsAnalysis,
  certInfo: CertInfo | null,
  captureEndTs: number,
): TlsHandshake | null {
  if (!tlsAnalysis.negotiated) return null;
  const neg = tlsAnalysis.negotiated;
  const cert: ParsedCertificate | null =
    certInfo && certInfo.parseOk
      ? {
          rawDer: tlsAnalysis.certDers[0].der,
          subject: certInfo.subject,
          issuer: certInfo.issuer,
          serialHex: certInfo.serialHex,
          notBefore: certInfo.notBefore,
          notAfter: certInfo.notAfter,
          nowValid:
            Date.now() / 1000 >= certInfo.notBefore &&
            Date.now() / 1000 <= certInfo.notAfter,
          expiredAtAnalysis: Date.now() / 1000 > certInfo.notAfter,
          notYetValidAtAnalysis: Date.now() / 1000 < certInfo.notBefore,
          atCaptureTimeValid:
            captureEndTs >= certInfo.notBefore && captureEndTs <= certInfo.notAfter,
          validityAtCaptureState: "verified",
          sigAlgOid: "",
          sigAlgName: certInfo.sigAlgName,
          pkAlgOid: "",
          pkAlgName: certInfo.pkAlgName,
          keyBits: certInfo.keyBits,
          keyBitsState: certInfo.keyBitsState,
          sanDnsNames: certInfo.sanDnsNames,
          cn: certInfo.cn,
          isSelfSigned: certInfo.isSelfSigned,
          chain: chainComposition(tlsAnalysis),
          chainLeafFirst: tlsAnalysis.certDers.length > 1,
          validationState: "unavailable",
          validationNote:
            "Full trust-chain validation unavailable from captured evidence.",
        }
      : null;
  return {
    version: neg.version,
    versionCode: { major: neg.versionMajor, minor: neg.versionMinor },
    cipherHex: neg.cipherHex,
    cipherName: neg.cipherName,
    keyExchange: neg.keyExchange,
    authMethod: neg.authMethod,
    bulkCipher: neg.bulkCipher,
    hashMac: neg.hashMac,
    forwardSecrecy: neg.forwardSecrecy,
    hasCertificateMessage: tlsAnalysis.certDers.length > 0,
    certificate: cert,
    handshakeBytes: tlsAnalysis.recordCount,
    offerCount: tlsAnalysis.clientHello?.offeredCipherHexes.length ?? 0,
    clientRandom: tlsAnalysis.clientHello?.randomHex ?? null,
    serverRandom: tlsAnalysis.serverHello?.randomHex ?? null,
    hasAlert: tlsAnalysis.alert !== null,
    alertDescription: tlsAnalysis.alert?.description ?? null,
    extendedMasterSecret: false,
    sessionIdPresent: false,
    extractionState: tlsAnalysis.extractionState,
    extractionNote: tlsAnalysis.extractionNote,
  };
}

function chainComposition(tlsAnalysis: TlsAnalysis): ParsedCertificate["chain"] {
  if (tlsAnalysis.certDers.length === 0) return "unavailable";
  if (tlsAnalysis.certDers.length >= 2) return "chain-present";
  return "single";
}

export function chainStateOf(
  tlsAnalysis: TlsAnalysis,
): "verified" | "requires-investigation" | "unavailable" {
  if (tlsAnalysis.certDers.length === 0) return "unavailable";
  if (tlsAnalysis.certDers.length >= 2) return "verified";
  return "requires-investigation";
}

export function serverHostnameHint(
  session: { dstIp: string; serverBanner: string | null },
  certInfo: CertInfo | null,
): string {
  // Evidence-based hint: the reverse-DNS/hostname of the server IP is not in
  // a PCAP, so the only usable comparison anchor is the certificate CN itself
  // against SAN entries. When no certificate exists there is no hint.
  void session;
  return certInfo?.parseOk ? (certInfo.cn ?? "") : "";
}

export function evidenceKindForRule(ruleId: string): Evidence["kind"] {
  switch (ruleId) {
    case "TLS-001":
    case "TLS-004":
      return "tls-version";
    case "TLS-002":
    case "TLS-003":
      return "cipher-suite";
    case "CERT-001":
    case "CERT-002":
    case "CERT-003":
      return "certificate";
    case "STARTTLS-001":
      return "starttls-sequence";
    case "PROTO-001":
      return "protocol-classification";
    default:
      return "handshake-shape";
  }
}

export function ruleCategoriesShare(
  ruleId: string,
  kind: Evidence["kind"],
): boolean {
  return evidenceKindForRule(ruleId) === kind;
}

export function starttlsEventKind(
  phase: StarttlsTrace["events"][number]["phase"],
): TimelineEvent["kind"] {
  switch (phase) {
    case "advertised":
      return "starttls-advertised";
    case "requested":
      return "starttls-requested";
    case "accepted":
      return "starttls-accepted";
    case "rejected":
    case "failed":
      return "starttls-failed";
  }
}

export function featuresFromSession(
  session: { tls: TlsHandshake | null },
  findings: Finding[],
  tlsAnalysis: TlsAnalysis,
): SessionFeatures {
  const rankMap: Record<string, number> = {
    "TLS 1.3": 4,
    "TLS 1.2": 3,
    "TLS 1.1": 2,
    "TLS 1.0": 1,
    "SSL 3.0": 0,
  };
  const version = session.tls?.version ?? null;
  const hasTls = session.tls ? 1 : 0;
  const fs = session.tls ? session.tls.forwardSecrecy : null;
  const weakCipherFinding = findings.some((f) => f.ruleId === "TLS-002");
  const cert002 = findings.find((f) => f.ruleId === "CERT-002");
  const summary = cert002 ? cert002.evidenceSummary.toLowerCase() : "";
  return {
    tlsVersionRank: version ? (rankMap[version] ?? -1) : -1,
    hasTls,
    forwardSecrecy: fs === null || fs === undefined ? 0.5 : fs ? 1 : 0,
    cipherStrength: weakCipherFinding ? 0 : hasTls === 0 ? 0.5 : 1,
    certExpired: findings.some((f) => f.ruleId === "CERT-001") ? 1 : 0,
    certSelfSigned: summary.includes("self-signed") ? 1 : 0,
    certWeakKey: findings.some((f) => f.ruleId === "CERT-003") ? 1 : 0,
    certChainUnavailable: summary.includes("chain absent") ? 1 : 0,
    starttlsFailed: findings.some((f) => f.ruleId === "STARTTLS-001") ? 1 : 0,
    plaintextSession: hasTls === 0 ? 1 : 0,
    findingCriticalCount: findings.filter((f) => f.severity === "critical").length,
    findingHighCount: findings.filter((f) => f.severity === "high").length,
    findingMediumCount: findings.filter((f) => f.severity === "medium").length,
    findingLowCount: findings.filter((f) => f.severity === "low").length,
    recordCountNorm: Math.min(1, tlsAnalysis.recordCount / 20),
  };
}

export function featureRowOf(f: SessionFeatures): number[] {
  return FEATURE_NAMES.map((k) => Number(f[k]));
}

export function contributingFeatures(
  model: AnomalyModel,
  row: number[],
  featureNames: string[],
): Array<{ name: string; direction: string; value: number }> {
  const counts = new Map<string, number>();
  for (const tree of model.trees) {
    let node = tree;
    let depth = 0;
    while (node.featureIndex >= 0 && node.left && node.right && depth < 12) {
      const fname = featureNames[node.featureIndex];
      counts.set(fname, (counts.get(fname) ?? 0) + 1);
      const goLeft = row[node.featureIndex] < node.threshold;
      node = goLeft ? node.left : node.right;
      depth++;
    }
  }
  const total = [...counts.values()].reduce((a, b) => a + b, 0) || 1;
  return [...counts.entries()]
    .map(([name, count]) => ({
      name,
      direction: row[featureNames.indexOf(name)] >= 0.5 ? "high" : "low",
      value: count / total,
    }))
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);
}

export function buildRecommendations(findings: Finding[]): Recommendation[] {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    groups.set(f.ruleId, [...(groups.get(f.ruleId) ?? []), f]);
  }
  const out: Recommendation[] = [];
  let rank = 1;
  const sorted = [...groups.entries()].sort((a, b) => {
    const maxSev = (fs: Finding[]) =>
      Math.max(...fs.map((f) => severityRank[f.severity]));
    return maxSev(b[1]) - maxSev(a[1]) || b[1].length - a[1].length;
  });
  for (const [ruleId, fs] of sorted) {
    const rule = ruleById(ruleId);
    if (!rule) continue;
    const topSeverity = fs.reduce<Severity>(
      (acc, f) => (severityRank[f.severity] > severityRank[acc] ? f.severity : acc),
      "info",
    );
    out.push({
      id: "REC-" + rank,
      rank,
      title: rule.name,
      severity: topSeverity,
      affectedSessions: fs.map((f) => f.sessionId),
      why: rule.reason,
      action: rule.recommendation,
      ruleIds: [ruleId],
      category: rule.category,
    });
    rank++;
  }
  return out;
}

export function hexPreview(b: Uint8Array): string {
  return Array.from(b.subarray(0, 24))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join(" ");
}

export function hashString(s: string): string {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  }
  return (h >>> 0).toString(36);
}

export type StarttlsAnalysis = {
  trace: StarttlsTrace;
  tlsEstablished: boolean;
};

export function analyzeStarttls(args: {
  flowProto: EmailProtocol;
  clientToServer: TcpSegment[];
  serverToClient: TcpSegment[];
  tlsAnalysis: TlsAnalysis;
}): StarttlsAnalysis {
  const tlsEstablished =
    !!args.tlsAnalysis.present && !!args.tlsAnalysis.negotiated;
  const trace = detectStarttls({
    protocol: args.flowProto,
    clientToServer: args.clientToServer,
    serverToClient: args.serverToClient,
    preTlsBoundary: args.tlsAnalysis.boundaryClient,
    tlsEstablished,
  });
  return { trace, tlsEstablished };
}
