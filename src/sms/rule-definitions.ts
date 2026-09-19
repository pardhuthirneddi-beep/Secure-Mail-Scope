/**
 * Detection rule registry. Pure metadata — evaluation lives in rule-eval.ts.
 */

export interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  evidenceRequired: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  reason: string;
  recommendation: string;
  limitations: string;
  category: "TLS" | "Certificate" | "STARTTLS" | "Anomaly" | "Protocol";
}

export const RULES: RuleDefinition[] = [
  {
    id: "TLS-001",
    name: "Deprecated TLS version",
    description: "Negotiated TLS version is obsolete (SSL 3.0, TLS 1.0, TLS 1.1).",
    evidenceRequired: "ServerHello version field parsed from handshake records.",
    severity: "high",
    reason:
      "Obsolete TLS versions lack modern AEAD support and are subject to known protocol attacks (POODLE, BEAST-era CBC weaknesses, downgrade techniques).",
    recommendation:
      "Disable obsolete TLS versions on the mail service and require TLS 1.2+ (prefer TLS 1.3).",
    limitations:
      "Assessment applies to the observed connection only; the server may negotiate better versions with other clients.",
    category: "TLS",
  },
  {
    id: "TLS-002",
    name: "Weak or deprecated cipher suite",
    description:
      "Negotiated cipher provides insufficient confidentiality (RC4, 3DES, CBC+SHA1) or is not in the IANA registry.",
    evidenceRequired: "ServerHello cipher suite field parsed from handshake records.",
    severity: "high",
    reason:
      "RC4 is cryptographically broken, 3DES has a 64-bit block size (Sweet32), and CBC+SHA1 combinations have Lucky13-class timing weaknesses.",
    recommendation:
      "Configure AEAD cipher suites (AES-GCM or CHACHA20_POLY1305) and remove RC4/3DES/CBC-SHA1 suites from server configuration.",
    limitations:
      "Privately defined suites cannot be classified and are reported as requiring review.",
    category: "TLS",
  },
  {
    id: "TLS-003",
    name: "Missing forward secrecy",
    description:
      "Key exchange does not provide forward secrecy (static RSA or static DH/ECDH).",
    evidenceRequired: "Key-exchange component of the negotiated cipher suite name.",
    severity: "medium",
    reason:
      "Without ephemeral key exchange, recorded traffic can be decrypted in the future if the server static key is compromised.",
    recommendation:
      "Enable ECDHE or DHE cipher suites; prefer TLS 1.3 where every suite provides forward secrecy.",
    limitations:
      "Derived from the negotiated suite name; TLS 1.3 key exchanges are encrypted and cannot be directly observed.",
    category: "TLS",
  },
  {
    id: "TLS-004",
    name: "Suspicious TLS negotiation",
    description:
      "Server negotiated a TLS version below the maximum the client offered.",
    evidenceRequired:
      "ClientHello supported_versions extension and ServerHello version.",
    severity: "high",
    reason:
      "Negotiating below the offered maximum can indicate server misconfiguration or an active downgrade; passive evidence cannot distinguish between the two.",
    recommendation:
      "Verify server TLS configuration and investigate the negotiation path for middlebox interference.",
    limitations:
      "A passive capture cannot prove an active downgrade attack.",
    category: "TLS",
  },
  {
    id: "CERT-001",
    name: "Expired certificate",
    description: "Certificate validity period ended before the capture end time.",
    evidenceRequired: "notAfter field parsed from the certificate DER.",
    severity: "high",
    reason:
      "An expired certificate fails baseline X.509 validation and typically indicates operational neglect.",
    recommendation: "Renew the certificate and redeploy it with a complete chain.",
    limitations: "Validity is evaluated at capture time, not current wall-clock time.",
    category: "Certificate",
  },
  {
    id: "CERT-002",
    name: "Certificate validation issue",
    description:
      "Self-signed certificate, hostname mismatch, or a chain that is absent from the capture.",
    evidenceRequired:
      "Certificate subject/issuer/SAN and chain composition in the Certificate message.",
    severity: "medium",
    reason:
      "Clients would show certificate warnings or fail validation, increasing interception risk.",
    recommendation:
      "Deploy a publicly trusted certificate matching the served hostname, with a complete chain.",
    limitations:
      "Full trust-chain validation requires a trust store and DNS checks that passive capture cannot provide; absence of chain evidence is not proof of misconfiguration.",
    category: "Certificate",
  },
  {
    id: "CERT-003",
    name: "Weak certificate key or signature",
    description: "RSA key below 2048 bits or SHA-1/MD5 signature algorithm.",
    evidenceRequired: "SPKI key size and signature algorithm OID from the certificate DER.",
    severity: "high",
    reason:
      "RSA keys below 2048 bits are factorable with modest resources; SHA-1 and MD5 signatures are collision-prone.",
    recommendation:
      "Reissue the certificate with RSA 2048+ bits or ECDSA, signed with SHA-256 or stronger.",
    limitations: "Key size is recovered for RSA keys only; EC key sizes are not parsed.",
    category: "Certificate",
  },
  {
    id: "STARTTLS-001",
    name: "Unsafe STARTTLS transition",
    description:
      "STARTTLS/STLS was requested but TLS was never established, or the session fell back to plaintext despite an advertised upgrade path.",
    evidenceRequired:
      "Plaintext command/response sequence and the TLS record-layer boundary.",
    severity: "high",
    reason:
      "Fallback or failed upgrade means email traversed the network unencrypted despite advertised capability.",
    recommendation:
      "Enforce TLS on the mail service (implicit TLS ports or policy-required STARTTLS) and investigate why the upgrade failed.",
    limitations:
      "Passive evidence cannot distinguish an active downgrade attack from simple misconfiguration.",
    category: "STARTTLS",
  },
  {
    id: "PROTO-001",
    name: "Plaintext email session",
    description:
      "Email session carried protocol traffic with no TLS record layer observed in either direction.",
    evidenceRequired:
      "Protocol identification plus absence of a TLS record boundary in both streams.",
    severity: "high",
    reason:
      "Unencrypted email transport exposes content and credentials to anyone on path.",
    recommendation: "Enforce TLS on all mail sessions (implicit TLS ports or required STARTTLS).",
    limitations:
      "Only applies to sessions with enough data to classify the protocol with reasonable confidence.",
    category: "Protocol",
  },
  {
    id: "ANOM-001",
    name: "Anomalous TLS behavior",
    description:
      "Isolation Forest model scored this session TLS feature vector as unusual compared with the capture population.",
    evidenceRequired: "Deterministic TLS feature vector produced by the pipeline.",
    severity: "medium",
    reason:
      "Unusual TLS patterns may indicate downgrade tooling, probing, or non-standard clients; this is not proof of attack.",
    recommendation:
      "Open the session timeline, compare with peer sessions, and investigate the endpoint configuration.",
    limitations:
      "The model flags statistical unusualness only; an anomaly is never an attack claim.",
    category: "Anomaly",
  },
];

export function ruleById(id: string): RuleDefinition | undefined {
  return RULES.find((r) => r.id === id);
}
