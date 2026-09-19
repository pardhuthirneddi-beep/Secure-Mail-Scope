/**
 * Per-rule evaluation. Each function inspects ONLY extracted evidence and
 * returns a fired/not-fired result with an evidence summary.
 */

import type { EvidenceState, Severity } from "./theme";
import type { Session } from "./types";
import type { RuleDefinition } from "./rule-definitions";

export interface CertEvidence {
  subject: string;
  issuer: string;
  notBefore: number;
  notAfter: number;
  sigAlgName: string;
  pkAlgName: string;
  keyBits: number | null;
  keyBitsState: "verified" | "unavailable";
  sanDnsNames: string[];
  cn: string | null;
  isSelfSigned: boolean;
  chainState: "verified" | "requires-investigation" | "unavailable";
  chainNote: string;
}

export interface RuleInput {
  session: Session;
  captureEndTs: number;
  hostnameHint: string;
  tls: {
    negotiatedVersion: string | null;
    negotiatedCipherHex: string | null;
    negotiatedCipherName: string | null;
    keyExchange: string | null;
    forwardSecrecy: boolean | null;
    clientHelloOfferedVersions: string[];
    alertDescription: number | null;
  };
  starttls: {
    advertised: boolean;
    requested: boolean;
    accepted: boolean;
    tlsEstablished: boolean;
    transition: string;
  } | null;
  certificate: CertEvidence | null;
}

export interface RuleResult {
  fired: boolean;
  evidenceSummary: string;
  whyItMatters: string;
  severity: Severity | null;
  confidence: number;
  state: EvidenceState;
}

const NOT_FIRED: RuleResult = {
  fired: false,
  evidenceSummary: "",
  whyItMatters: "",
  severity: null,
  confidence: 0,
  state: "verified",
};

function versionRank(x: string): number {
  if (x === "TLS 1.3") return 4;
  if (x === "TLS 1.2") return 3;
  if (x === "TLS 1.1") return 2;
  if (x === "TLS 1.0") return 1;
  if (x === "SSL 3.0") return 0;
  return -1;
}

function matchesHost(certName: string, host: string): boolean {
  const h = host.toLowerCase();
  const c = certName.toLowerCase();
  if (c === h) return true;
  if (c.startsWith("*.")) {
    const rest = c.slice(2);
    if (h.endsWith(rest) && h !== rest) {
      const head = h.slice(0, h.length - rest.length - 1);
      return head.indexOf(".") === -1;
    }
    return false;
  }
  return false;
}

function certHostnameMismatch(input: RuleInput): string | null {
  const cert = input.certificate;
  if (!cert) return null;
  const server = input.hostnameHint;
  if (!server) return null;
  const candidates = [cert.cn, ...cert.sanDnsNames].filter(Boolean) as string[];
  if (candidates.length === 0) return null;
  for (const c of candidates) {
    if (matchesHost(c, server)) return null;
  }
  return "SAN/CN (" + candidates.join(", ") + ") does not match contacted server hostname " + server;
}

function isoDate(ts: number): string {
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

export function evaluateRule(
  rule: RuleDefinition,
  input: RuleInput,
): RuleResult {
  const tls = input.tls;
  const cert = input.certificate;

  switch (rule.id) {
    case "TLS-001": {
      const v = tls.negotiatedVersion;
      if (!v) return NOT_FIRED;
      const deprecated = v === "SSL 3.0" || v === "TLS 1.0" || v === "TLS 1.1";
      if (!deprecated) return NOT_FIRED;
      return {
        fired: true,
        evidenceSummary: v + " negotiated",
        whyItMatters:
          "Obsolete TLS versions do not meet modern cryptographic policy and are subject to known protocol attacks.",
        severity: "high",
        confidence: 0.95,
        state: "verified",
      };
    }
    case "TLS-002": {
      const hex = tls.negotiatedCipherHex;
      const name = tls.negotiatedCipherName;
      if (!hex) return NOT_FIRED;
      if (tls.negotiatedVersion === "TLS 1.3") return NOT_FIRED;
      if (!name) {
        return {
          fired: true,
          evidenceSummary: "Unknown cipher suite " + hex + " negotiated",
          whyItMatters:
            "The suite is not in the IANA registry snapshot; strength cannot be verified from evidence.",
          severity: "medium",
          confidence: 0.6,
          state: "requires-investigation",
        };
      }
      const u = name.toUpperCase();
      if (u.indexOf("RC4") !== -1) {
        return {
          fired: true,
          evidenceSummary: name + " negotiated",
          whyItMatters: "RC4 is cryptographically broken and prohibited for TLS.",
          severity: "high",
          confidence: 0.95,
          state: "verified",
        };
      }
      if (u.indexOf("3DES") !== -1) {
        return {
          fired: true,
          evidenceSummary: name + " negotiated",
          whyItMatters: "3DES has a 64-bit block size (Sweet32) and is deprecated.",
          severity: "high",
          confidence: 0.95,
          state: "verified",
        };
      }
      if (
        u.indexOf("CBC") !== -1 &&
        u.indexOf("SHA") !== -1 &&
        u.indexOf("SHA256") === -1 &&
        u.indexOf("SHA384") === -1
      ) {
        return {
          fired: true,
          evidenceSummary: name + " negotiated",
          whyItMatters: "CBC with SHA1 MAC is deprecated (Lucky13-class timing weaknesses).",
          severity: "medium",
          confidence: 0.85,
          state: "verified",
        };
      }
      return NOT_FIRED;
    }
    case "TLS-003": {
      if (tls.forwardSecrecy !== false) return NOT_FIRED;
      if (tls.negotiatedVersion === "TLS 1.3") return NOT_FIRED;
      return {
        fired: true,
        evidenceSummary:
          "Key exchange " + (tls.keyExchange ?? "unknown") + " provides no forward secrecy",
        whyItMatters:
          "Future compromise of the server static key would expose captured traffic retroactively.",
        severity: "medium",
        confidence: 0.9,
        state: "derived",
      };
    }
    case "TLS-004": {
      const offered = tls.clientHelloOfferedVersions;
      const negotiated = tls.negotiatedVersion;
      if (offered.length === 0 || !negotiated) return NOT_FIRED;
      const best = versionRank(offered[0]);
      if (versionRank(negotiated) < best) {
        return {
          fired: true,
          evidenceSummary:
            "Client offered " + offered.join(", ") + " but server negotiated " + negotiated,
          whyItMatters:
            "Negotiating below the offered maximum indicates forced downgrade or misconfiguration; active attacks cannot be excluded from passive evidence.",
          severity: "high",
          confidence: 0.7,
          state: "requires-investigation",
        };
      }
      return NOT_FIRED;
    }
    case "CERT-001": {
      if (!cert) return NOT_FIRED;
      if (input.captureEndTs <= cert.notAfter) return NOT_FIRED;
      return {
        fired: true,
        evidenceSummary:
          "Certificate expired " + isoDate(cert.notAfter) + ", before capture end " + isoDate(input.captureEndTs),
        whyItMatters:
          "Clients cannot validate an expired certificate; warning-override habits increase interception risk.",
        severity: "high",
        confidence: 0.98,
        state: "verified",
      };
    }
    case "CERT-002": {
      if (!cert) return NOT_FIRED;
      const parts: string[] = [];
      if (cert.chainState === "unavailable") {
        parts.push("certificate chain absent or incomplete in capture");
      }
      if (cert.isSelfSigned) parts.push("certificate appears self-signed");
      const mismatch = certHostnameMismatch(input);
      if (mismatch) parts.push(mismatch);
      if (parts.length === 0) return NOT_FIRED;
      const hard = cert.isSelfSigned || !!mismatch;
      return {
        fired: true,
        evidenceSummary: parts.join("; "),
        whyItMatters:
          "Clients would show certificate warnings or fail validation, increasing interception risk.",
        severity: hard ? "medium" : "low",
        confidence: hard ? 0.85 : 0.5,
        state: hard ? "verified" : "requires-investigation",
      };
    }
    case "CERT-003": {
      if (!cert) return NOT_FIRED;
      const weakKey =
        cert.keyBitsState === "verified" && cert.keyBits !== null && cert.keyBits < 2048;
      const weakSig =
        cert.sigAlgName.indexOf("sha1") !== -1 || cert.sigAlgName.indexOf("md5") !== -1;
      if (!weakKey && !weakSig) return NOT_FIRED;
      const parts: string[] = [];
      if (weakKey) parts.push(cert.keyBits + "-bit " + cert.pkAlgName + " public key");
      if (weakSig) parts.push(cert.sigAlgName + " signature algorithm");
      return {
        fired: true,
        evidenceSummary: parts.join(", "),
        whyItMatters:
          "Small RSA keys are factorable; SHA-1/MD5 signatures are vulnerable to collision attacks.",
        severity: "high",
        confidence: 0.95,
        state: "verified",
      };
    }
    case "STARTTLS-001": {
      const st = input.starttls;
      if (!st) return NOT_FIRED;
      const failedUpgrade = st.requested && !st.tlsEstablished;
      const fallback = st.transition === "fallback-to-plaintext";
      if (!failedUpgrade && !fallback) return NOT_FIRED;
      return {
        fired: true,
        evidenceSummary: failedUpgrade
          ? "STARTTLS/STLS requested but TLS never established"
          : "STARTTLS was advertised but the session remained plaintext",
        whyItMatters:
          "Email content and credentials traversed the network without TLS protection.",
        severity: "high",
        confidence: 0.9,
        state: "verified",
      };
    }
    case "PROTO-001": {
      const s = input.session;
      if (tls.negotiatedVersion) return NOT_FIRED;
      if (s.protocol === "OTHER" || s.byteCount < 32) return NOT_FIRED;
      return {
        fired: true,
        evidenceSummary: "No TLS record layer observed in either stream direction",
        whyItMatters: "Email protocol data crossed the network unencrypted.",
        severity: "high",
        confidence: 0.9,
        state: "verified",
      };
    }
    default:
      return NOT_FIRED;
  }
}
