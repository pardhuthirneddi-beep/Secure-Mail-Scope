/**
 * Test Lab scenarios + Demo mode + automated evaluation.
 * Scenarios build real PCAPs via pcapgen and run the real pipeline.
 * Expected findings are declared per scenario and compared with detected
 * findings to produce measured (never invented) pass/fail metrics.
 */

import { buildPcap, buildDerCertificate, buildClientTlsStream, buildServerTlsStream, type TcpExchange, type TlsSpec } from "./pcapgen";
import { runPipeline, type PipelineResult } from "./pipeline";
import type { Finding, Session } from "./types";

export interface ScenarioDef {
  id: string;
  label: string;
  description: string;
  expectedFindings: string[]; // rule ids expected to fire
  expectedRisk: "healthy" | "low" | "medium" | "high" | "critical";
  build: (t0: number) => TcpExchange[];
}

const CLIENT_IP = "10.0.0.15";
const SMTP_SERVER_IP = "10.0.0.20";
const IMAP_SERVER_IP = "10.0.0.21";
const POP3_SERVER_IP = "10.0.0.22";

function smtpGreeting(hostname: string): string[] {
  return [
    "220 " + hostname + " ESMTP Postfix",
  ];
}

function ehloWithStarttls(hostname: string): string[] {
  return [
    "EHLO client.local",
    "AUTH LOGIN",
  ];
}

function smtpStarttlsSequence(hostname: string): { client: string[]; server: string[] } {
  return {
    client: ["EHLO client.local", "STARTTLS"],
    server: [
      "220 " + hostname + " ESMTP Postfix",
      "250-" + hostname,
      "250-PIPELINING",
      "250-SIZE 10240000",
      "250-STARTTLS",
      "250 ENHANCEDSTATUSCODES",
      "220 2.0.0 Ready to start TLS",
    ],
  };
}

function certFor(spec: {
  cn: string;
  expired?: boolean;
  selfSigned?: boolean;
  weakKey?: boolean;
  sha1?: boolean;
}): Uint8Array {
  const now = Date.now();
  const year = 365 * 24 * 3600;
  const notAfter = Math.floor(now / 1000) + (spec.expired ? -30 * 24 * 3600 : year);
  const notBefore = Math.floor(now / 1000) - year;
  const fmt = (ts: number): string => {
    const d = new Date(ts * 1000);
    const p = (n: number) => String(n).padStart(2, "0");
    return (
      String(d.getUTCFullYear()).slice(2) +
      p(d.getUTCMonth() + 1) +
      p(d.getUTCDate()) +
      p(d.getUTCHours()) +
      p(d.getUTCMinutes()) +
      p(d.getUTCSeconds()) +
      "Z"
    );
  };
  return buildDerCertificate({
    cn: spec.cn,
    sanDns: spec.selfSigned ? [spec.cn, "wrong.example.org"] : [spec.cn],
    issuerCn: spec.selfSigned ? spec.cn : "Demo Root CA",
    notBeforeStr: fmt(notBefore),
    notAfterStr: fmt(notAfter),
    keyBits: spec.weakKey ? 1024 : 2048,
    sigAlg: spec.sha1 ? "sha1WithRSAEncryption" : "sha256WithRSAEncryption",
    serial: 7,
    isCa: false,
  });
}

export const SCENARIOS: ScenarioDef[] = [
  {
    id: "secure-smtp",
    label: "Secure session",
    description:
      "SMTP with STARTTLS upgrading to TLS 1.3 with an AEAD suite and a valid certificate.",
    expectedFindings: [],
    expectedRisk: "healthy",
    build: (t0) => {
      const cert = certFor({ cn: "mail.example.local" });
      const tlsSpec: TlsSpec = {
        version: 4,
        cipherHex: 0x1302,
        includeCert: false,
        offerVersions: [4],
      };
      const seq = smtpStarttlsSequence("mail.example.local");
      return [
        {
          clientIp: CLIENT_IP,
          serverIp: SMTP_SERVER_IP,
          clientPort: 43812,
          serverPort: 587,
          clientLines: [...seq.client, "QUIT"],
          serverLines: [...seq.server, "221 Bye"],
          clientTlsStream: buildClientTlsStream(tlsSpec),
          serverTlsStream: buildServerTlsStream({ ...tlsSpec, includeCert: false }),
          t0,
          finishWith: "fin",
        },
      ];
    },
  },
  {
    id: "expired-cert",
    label: "Expired certificate",
    description:
      "SMTP over implicit TLS (port 465) presenting a certificate that expired before the capture.",
    expectedFindings: ["CERT-001"],
    expectedRisk: "high",
    build: (t0) => {
      const cert = certFor({ cn: "mail.example.local", expired: true });
      const tlsSpec: TlsSpec = {
        version: 3,
        cipherHex: 0xc02f,
        includeCert: true,
        cert,
      };
      return [
        {
          clientIp: CLIENT_IP,
          serverIp: SMTP_SERVER_IP,
          clientPort: 43814,
          serverPort: 465,
          clientLines: [],
          serverLines: [],
          clientTlsStream: buildClientTlsStream(tlsSpec),
          serverTlsStream: buildServerTlsStream(tlsSpec),
          t0,
          finishWith: "fin",
        },
      ];
    },
  },
  {
    id: "deprecated-tls",
    label: "Deprecated TLS",
    description:
      "IMAP session negotiating TLS 1.0 with a CBC+SHA1 cipher suite.",
    expectedFindings: ["TLS-001", "TLS-002"],
    expectedRisk: "high",
    build: (t0) => {
      const cert = certFor({ cn: "imap.example.local" });
      const tlsSpec: TlsSpec = {
        version: 1,
        cipherHex: 0x002f,
        includeCert: true,
        cert,
      };
      return [
        {
          clientIp: CLIENT_IP,
          serverIp: IMAP_SERVER_IP,
          clientPort: 49200,
          serverPort: 993,
          clientLines: [],
          serverLines: [],
          clientTlsStream: buildClientTlsStream(tlsSpec),
          serverTlsStream: buildServerTlsStream(tlsSpec),
          t0,
          finishWith: "fin",
        },
      ];
    },
  },
  {
    id: "weak-cipher",
    label: "Weak cipher",
    description:
      "SMTP implicit TLS negotiating 3DES (0x000A) — deprecated block cipher.",
    expectedFindings: ["TLS-002"],
    expectedRisk: "high",
    build: (t0) => {
      const cert = certFor({ cn: "mail.example.local" });
      const tlsSpec: TlsSpec = {
        version: 3,
        cipherHex: 0x000a,
        includeCert: true,
        cert,
      };
      return [
        {
          clientIp: CLIENT_IP,
          serverIp: SMTP_SERVER_IP,
          clientPort: 43816,
          serverPort: 465,
          clientLines: [],
          serverLines: [],
          clientTlsStream: buildClientTlsStream(tlsSpec),
          serverTlsStream: buildServerTlsStream(tlsSpec),
          t0,
          finishWith: "fin",
        },
      ];
    },
  },
  {
    id: "starttls-issue",
    label: "STARTTLS issue",
    description:
      "STARTTLS advertised and requested, but TLS never established and the session continued in plaintext.",
    expectedFindings: ["STARTTLS-001", "PROTO-001"],
    expectedRisk: "critical",
    build: (t0) => {
      const seq = smtpStarttlsSequence("mail.example.local");
      return [
        {
          clientIp: CLIENT_IP,
          serverIp: SMTP_SERVER_IP,
          clientPort: 43818,
          serverPort: 587,
          clientLines: [...seq.client, "MAIL FROM:<user@client.local>", "QUIT"],
          serverLines: [...seq.server, "250 OK", "221 Bye"],
          t0,
          finishWith: "fin",
        },
      ];
    },
  },
  {
    id: "self-signed",
    label: "Untrusted certificate",
    description:
      "POP3 over implicit TLS presenting a self-signed certificate.",
    expectedFindings: ["CERT-002"],
    expectedRisk: "medium",
    build: (t0) => {
      const cert = certFor({ cn: "pop.example.local", selfSigned: true });
      const tlsSpec: TlsSpec = {
        version: 3,
        cipherHex: 0xc02f,
        includeCert: true,
        cert,
      };
      return [
        {
          clientIp: CLIENT_IP,
          serverIp: POP3_SERVER_IP,
          clientPort: 49300,
          serverPort: 995,
          clientLines: [],
          serverLines: [],
          clientTlsStream: buildClientTlsStream(tlsSpec),
          serverTlsStream: buildServerTlsStream(tlsSpec),
          t0,
          finishWith: "fin",
        },
      ];
    },
  },
  {
    id: "weak-cert-key",
    label: "Weak certificate key",
    description:
      "IMAP over implicit TLS presenting a 1024-bit RSA certificate signed with SHA-1.",
    expectedFindings: ["CERT-003"],
    expectedRisk: "high",
    build: (t0) => {
      const cert = certFor({ cn: "imap.example.local", weakKey: true, sha1: true });
      const tlsSpec: TlsSpec = {
        version: 3,
        cipherHex: 0xc02f,
        includeCert: true,
        cert,
      };
      return [
        {
          clientIp: CLIENT_IP,
          serverIp: IMAP_SERVER_IP,
          clientPort: 49310,
          serverPort: 993,
          clientLines: [],
          serverLines: [],
          clientTlsStream: buildClientTlsStream(tlsSpec),
          serverTlsStream: buildServerTlsStream(tlsSpec),
          t0,
          finishWith: "fin",
        },
      ];
    },
  },
  {
    id: "plaintext-pop3",
    label: "Plaintext POP3",
    description:
      "Full POP3 session with credentials on an unencrypted channel.",
    expectedFindings: ["PROTO-001"],
    expectedRisk: "high",
    build: (t0) => {
      return [
        {
          clientIp: CLIENT_IP,
          serverIp: POP3_SERVER_IP,
          clientPort: 49320,
          serverPort: 110,
          clientLines: ["USER alice", "PASS hunter2", "STAT", "QUIT"],
          serverLines: [
            "+OK POP3 server ready",
            "+OK",
            "+OK Logged in.",
            "+OK 0 0",
            "+OK Signing off",
          ],
          t0,
          finishWith: "fin",
        },
      ];
    },
  },
  {
    id: "mixed-enterprise",
    label: "Mixed enterprise capture",
    description:
      "Combination capture: secure SMTP, expired certificate, deprecated TLS and a plaintext POP3 session.",
    expectedFindings: ["TLS-001", "CERT-001", "PROTO-001"],
    expectedRisk: "critical",
    build: (t0) => {
      const goodCert = certFor({ cn: "mail.example.local" });
      const expired = certFor({ cn: "mail.example.local", expired: true });
      const tlsGood: TlsSpec = { version: 4, cipherHex: 0x1302, includeCert: false, offerVersions: [4] };
      const tlsExpired: TlsSpec = { version: 3, cipherHex: 0xc02f, includeCert: true, cert: expired };
      const tlsOld: TlsSpec = { version: 1, cipherHex: 0x002f, includeCert: true, cert: goodCert };
      const seq = smtpStarttlsSequence("mail.example.local");
      return [
        {
          clientIp: CLIENT_IP,
          serverIp: SMTP_SERVER_IP,
          clientPort: 43820,
          serverPort: 587,
          clientLines: [...seq.client, "QUIT"],
          serverLines: [...seq.server, "221 Bye"],
          clientTlsStream: buildClientTlsStream(tlsGood),
          serverTlsStream: buildServerTlsStream({ ...tlsGood, includeCert: false }),
          t0,
          finishWith: "fin",
        },
        {
          clientIp: CLIENT_IP,
          serverIp: SMTP_SERVER_IP,
          clientPort: 43822,
          serverPort: 465,
          clientLines: [],
          serverLines: [],
          clientTlsStream: buildClientTlsStream(tlsExpired),
          serverTlsStream: buildServerTlsStream(tlsExpired),
          t0: t0 + 10,
          finishWith: "fin",
        },
        {
          clientIp: CLIENT_IP,
          serverIp: IMAP_SERVER_IP,
          clientPort: 49340,
          serverPort: 993,
          clientLines: [],
          serverLines: [],
          clientTlsStream: buildClientTlsStream(tlsOld),
          serverTlsStream: buildServerTlsStream(tlsOld),
          t0: t0 + 20,
          finishWith: "fin",
        },
        {
          clientIp: CLIENT_IP,
          serverIp: POP3_SERVER_IP,
          clientPort: 49342,
          serverPort: 110,
          clientLines: ["USER bob", "PASS s3cret", "QUIT"],
          serverLines: ["+OK POP3 ready", "+OK", "+OK", "+OK bye"],
          t0: t0 + 30,
          finishWith: "fin",
        },
      ];
    },
  },
];

export interface ScenarioRunResult {
  scenario: ScenarioDef;
  pcapBytes: Uint8Array;
  result: PipelineResult | null;
  error: string | null;
  detected: string[];
  missed: string[];
  extra: string[];
  riskLevel: string | null;
  riskMatches: boolean | null;
}

/** Build PCAP for a scenario and run the REAL pipeline over it. */
export async function runScenario(
  scenario: ScenarioDef,
  onStage?: (update: { stageId: string; done: boolean }) => void,
): Promise<ScenarioRunResult> {
  const t0 = Math.floor(Date.now() / 1000) - 600;
  const exchanges = scenario.build(t0);
  const pcap = buildPcap(exchanges);
  try {
    const result = await runPipeline(
      pcap.bytes.buffer.slice(
        pcap.bytes.byteOffset,
        pcap.bytes.byteOffset + pcap.bytes.byteLength,
      ) as ArrayBuffer,
      scenario.id + ".pcap",
      onStage ?? (() => {}),
    );
    const detected = [...new Set(result.findings.map((f) => f.ruleId))];
    const missed = scenario.expectedFindings.filter((r) => !detected.includes(r));
    const extra = detected.filter((r) => !scenario.expectedFindings.includes(r));
    const riskLevel = result.sessions.length
      ? (result.riskBySession[result.sessions[0].id]?.level ?? null)
      : null;
    return {
      scenario,
      pcapBytes: pcap.bytes,
      result,
      error: null,
      detected,
      missed,
      extra,
      riskLevel,
      riskMatches: riskLevel === scenario.expectedRisk,
    };
  } catch (e) {
    return {
      scenario,
      pcapBytes: pcap.bytes,
      result: null,
      error: e instanceof Error ? e.message : String(e),
      detected: [],
      missed: [...scenario.expectedFindings],
      extra: [],
      riskLevel: null,
      riskMatches: null,
    };
  }
}

export interface TestLabReport {
  scenarios: number;
  completed: number;
  deterministicChecks: number;
  expectedFindings: number;
  detectedFindings: number;
  missed: number;
  falsePositives: number;
  rows: Array<{
    id: string;
    label: string;
    detected: string[];
    missed: string[];
    extra: string[];
    riskLevel: string | null;
    riskMatches: boolean | null;
    error: string | null;
  }>;
}

/** Aggregate evaluation across all scenarios — metrics computed, not asserted. */
export function aggregateTestLab(rows: ScenarioRunResult[]): TestLabReport {
  const completed = rows.filter((r) => r.result !== null).length;
  let expected = 0;
  let detected = 0;
  let missed = 0;
  let fp = 0;
  for (const r of rows) {
    expected += r.scenario.expectedFindings.length;
    detected += r.scenario.expectedFindings.length - r.missed.length;
    missed += r.missed.length;
    fp += r.extra.length;
  }
  return {
    scenarios: rows.length,
    completed,
    deterministicChecks: rows.reduce((acc, r) => acc + (r.result?.findings.length ?? 0), 0),
    expectedFindings: expected,
    detectedFindings: detected,
    missed,
    falsePositives: fp,
    rows: rows.map((r) => ({
      id: r.scenario.id,
      label: r.scenario.label,
      detected: r.detected,
      missed: r.missed,
      extra: r.extra,
      riskLevel: r.riskLevel,
      riskMatches: r.riskMatches,
      error: r.error,
    })),
  };
}

// ---------------------------------------------------------------------------
// Demo mode
// ---------------------------------------------------------------------------

export interface DemoScenario {
  id: string;
  label: string;
  description: string;
  build: (t0: number) => TcpExchange[];
  fileName: string;
}

const DEMO_SCENARIOS: DemoScenario[] = [
  { id: "demo-secure-smtp", label: "DEMO 01 — Secure SMTP", description: "Healthy SMTP STARTTLS session.", build: (t0) => SCENARIOS[0].build(t0), fileName: "demo-secure-smtp.pcap" },
  { id: "demo-expired", label: "DEMO 02 — Expired Certificate", description: "SMTP implicit TLS with expired certificate.", build: (t0) => SCENARIOS[1].build(t0), fileName: "demo-expired-cert.pcap" },
  { id: "demo-weak-tls", label: "DEMO 03 — Weak TLS Configuration", description: "IMAP negotiating TLS 1.0 / CBC-SHA1.", build: (t0) => SCENARIOS[2].build(t0), fileName: "demo-weak-tls.pcap" },
  { id: "demo-starttls", label: "DEMO 04 — STARTTLS Issue", description: "STARTTLS requested, TLS never established.", build: (t0) => SCENARIOS[4].build(t0), fileName: "demo-starttls-issue.pcap" },
  { id: "demo-mixed", label: "DEMO 05 — Mixed Enterprise Capture", description: "Four sessions: secure, expired cert, deprecated TLS, plaintext POP3.", build: (t0) => SCENARIOS[8].build(t0), fileName: "demo-mixed-enterprise.pcap" },
];

export function listDemoScenarios(): DemoScenario[] {
  return DEMO_SCENARIOS;
}

/** Generate the mixed demo capture bytes (labeled DEMO DATA in the UI). */
export function buildDemoPcap(demo: DemoScenario): { bytes: Uint8Array; fileName: string } {
  const t0 = Math.floor(Date.now() / 1000) - 900;
  const exchanges = demo.build(t0);
  const pcap = buildPcap(exchanges);
  return { bytes: pcap.bytes, fileName: demo.fileName };
}

export function sessionProtocolSummary(sessions: Session[]): Record<string, number> {
  const out: Record<string, number> = {};
  for (const s of sessions) {
    out[s.protocol] = (out[s.protocol] ?? 0) + 1;
  }
  return out;
}

export function findingTitlesFor(findings: Finding[]): string[] {
  return findings.map((f) => f.ruleId + " " + f.title);
}
