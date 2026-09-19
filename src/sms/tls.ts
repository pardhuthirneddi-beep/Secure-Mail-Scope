/**
 * TLS record + handshake parsing from TCP byte streams.
 * Locates the record-layer boundary in STARTTLS sessions, parses
 * ClientHello / ServerHello / Certificate / Alert messages, and derives
 * cipher properties (key exchange, forward secrecy) from suite names.
 * If evidence is missing, fields are null — never guessed.
 */

export interface TlsRecordInfo {
  type: number; // 20 CCS, 21 alert, 22 handshake, 23 appdata
  versionMajor: number;
  versionMinor: number;
  length: number;
}

export interface ClientHelloInfo {
  recordVersionMajor: number;
  recordVersionMinor: number;
  offeredVersions: string[]; // from supported_versions ext when present
  offeredCipherHexes: string[];
  randomHex: string;
}

export interface ServerHelloInfo {
  recordVersionMajor: number;
  recordVersionMinor: number;
  cipherHex: string;
  versionMajor: number;
  versionMinor: number;
  randomHex: string;
  isTls13: boolean;
}

export interface CertDer {
  der: Uint8Array;
}

export interface NegotiatedTls {
  version: string;
  versionMajor: number;
  versionMinor: number;
  cipherHex: string;
  cipherName: string | null;
  keyExchange: string | null;
  authMethod: string | null;
  bulkCipher: string | null;
  hashMac: string | null;
  forwardSecrecy: boolean | null;
}

export interface TlsAnalysis {
  present: boolean;
  boundaryClient: number | null;
  boundaryServer: number | null;
  recordCount: number;
  clientHello: ClientHelloInfo | null;
  serverHello: ServerHelloInfo | null;
  negotiated: NegotiatedTls | null;
  certDers: CertDer[]; // leaf first
  alert: { level: number; description: number } | null;
  extractionState: "complete" | "partial" | "none";
  extractionNote: string;
}

const HS_CLIENT_HELLO = 1;
const HS_SERVER_HELLO = 2;
const HS_CERTIFICATE = 11;
export function looksLikeTlsRecord(b: Uint8Array, off: number): boolean {
  if (off + 5 > b.length) return false;
  const t = b[off];
  if (t < 20 || t > 23) return false;
  if (b[off + 1] !== 3) return false;
  const minor = b[off + 2];
  if (minor > 4) return false;
  const len = (b[off + 3] << 8) | b[off + 4];
  return len >= 1 && len <= 18432;
}

function parseRecords(
  b: Uint8Array,
  start: number,
): TlsRecordInfo[] | null {
  const out: TlsRecordInfo[] = [];
  let off = start;
  while (off < b.length) {
    if (off + 5 > b.length) {
      // trailing partial record (capture cut) — tolerate at end
      if (out.length > 0) break;
      return null;
    }
    const t = b[off];
    if (t < 20 || t > 23) return out.length > 0 ? out : null;
    const major = b[off + 1];
    const minor = b[off + 2];
    const len = (b[off + 3] << 8) | b[off + 4];
    if (major !== 3 || minor > 4 || len > 18432) return out.length > 0 ? out : null;
    if (off + 5 + len > b.length) {
      // sliced final record — tolerate
      if (out.length === 0) return null;
      break;
    }
    out.push({ type: t, versionMajor: major, versionMinor: minor, length: len });
    off += 5 + len;
  }
  return out;
}

/** Parse handshake messages out of concatenated handshake record bodies. */
function parseHandshakeBodies(bodies: Uint8Array[]): Array<{
  type: number;
  body: Uint8Array;
}> {
  const msgs: Array<{ type: number; body: Uint8Array }> = [];
  for (const body of bodies) {
    let off = 0;
    while (off + 4 <= body.length) {
      const type = body[off];
      const len = (body[off + 1] << 16) | (body[off + 2] << 8) | body[off + 3];
      if (off + 4 + len > body.length) break; // fragmented/sliced
      msgs.push({ type, body: body.subarray(off + 4, off + 4 + len) });
      off += 4 + len;
    }
  }
  return msgs;
}

export function analyzeTls(
  clientStream: Uint8Array,
  serverStream: Uint8Array,
): TlsAnalysis {
  const result: TlsAnalysis = {
    present: false,
    boundaryClient: null,
    boundaryServer: null,
    recordCount: 0,
    clientHello: null,
    serverHello: null,
    negotiated: null,
    certDers: [],
    alert: null,
    extractionState: "none",
    extractionNote: "No TLS record layer was observed in either direction.",
  };

  const bc = findBoundary(clientStream);
  if (bc === null) return result;
  result.boundaryClient = bc.client;
  result.boundaryServer = bc.server;
  result.present = true;

  const cRecs = parseRecords(clientStream, bc.client) ?? [];
  const sRecs = parseRecords(serverStream, bc.server) ?? [];
  result.recordCount = cRecs.length + sRecs.length;
  if (result.recordCount === 0) {
    result.extractionState = "none";
    result.extractionNote =
      "TLS boundary detected but records could not be parsed (sliced capture?).";
    return result;
  }

  // ClientHello
  const cBodies = handshakeBodiesFromRecords(cRecs, clientStream, bc.client);
  const sBodies = handshakeBodiesFromRecords(sRecs, serverStream, bc.server);
  const cMsgs = parseHandshakeBodies(cBodies);
  const sMsgs = parseHandshakeBodies(sBodies);

  const chMsg = cMsgs.find((m) => m.type === HS_CLIENT_HELLO);
  if (chMsg) result.clientHello = parseClientHello(chMsg.body, cRecs);

  const shMsg = sMsgs.find((m) => m.type === HS_SERVER_HELLO);
  if (shMsg) result.serverHello = parseServerHello(shMsg.body, sRecs);

  // Certificate message (TLS 1.2 and below — plaintext in the capture)
  const certMsg = sMsgs.find((m) => m.type === HS_CERTIFICATE);
  if (certMsg) {
    result.certDers = parseCertificateList(certMsg.body);
  }

  // Alert
  const alertRec = [...cRecs, ...sRecs].find((r) => r.type === 21);
  if (alertRec) {
    const dir = cRecs.includes(alertRec) ? clientStream : serverStream;
    const start = cRecs.includes(alertRec) ? bc.client : bc.server;
    const off = recordBodyOffset(dir, start, alertRec);
    if (off !== null && off + 2 <= dir.length) {
      result.alert = { level: dir[off], description: dir[off + 1] };
    }
  }

  // Negotiated summary
  if (result.serverHello) {
    const sh = result.serverHello;
    result.negotiated = summarize(sh.cipherHex, sh.versionMajor, sh.versionMinor);
  } else if (result.clientHello) {
    result.extractionState = "partial";
    result.extractionNote =
      "ClientHello observed but no ServerHello present in the capture; negotiated parameters cannot be determined.";
    return result;
  }

  if (result.negotiated) {
    const haveCert = result.certDers.length > 0;
    const isTls13 = result.negotiated.version === "TLS 1.3";
    if (isTls13 && !haveCert) {
      result.extractionState = "partial";
      result.extractionNote =
        "TLS 1.3 encrypts the server certificate; certificate details are not recoverable from a passive capture.";
    } else if (haveCert) {
      result.extractionState = "complete";
      result.extractionNote = "Handshake and certificate extracted from records.";
    } else {
      result.extractionState = "partial";
      result.extractionNote =
        "Negotiated parameters extracted; no Certificate message present in the capture.";
    }
  }
  return result;
}

function handshakeBodiesFromRecords(
  recs: TlsRecordInfo[],
  stream: Uint8Array,
  boundary: number | null,
): Uint8Array[] {
  const bodies: Uint8Array[] = [];
  let off = boundary;
  for (const r of recs) {
    if (r.type === 22 && off !== null && off + 5 <= stream.length) {
      bodies.push(stream.subarray(off + 5, off + 5 + r.length));
    }
    off = off === null ? null : off + 5 + r.length;
  }
  return bodies;
}

function recordBodyOffset(
  stream: Uint8Array,
  boundary: number | null,
  target: TlsRecordInfo,
): number | null {
  let off = boundary;
  for (const r of iterateRecords(stream, boundary)) {
    if (r === target && off !== null) return off + 5;
    off = off === null ? null : off + 5 + r.length;
  }
  return null;
}

function* iterateRecords(
  stream: Uint8Array,
  boundary: number | null,
): Generator<TlsRecordInfo> {
  const recs = boundary === null ? [] : parseRecords(stream, boundary) ?? [];
  yield* recs;
}

function findBoundary(
  clientStream: Uint8Array,
): { client: number; server: number } | null {
  // Implicit TLS: record layer at offset 0.
  if (looksLikeTlsRecord(clientStream, 0)) {
    const sRecs = parseRecords(clientStream, 0);
    if (sRecs && sRecs.length > 0) return { client: 0, server: 0 };
  }
  // STARTTLS: scan for the last clean record-layer parse.
  for (let i = 0; i + 5 <= clientStream.length; i++) {
    if (!looksLikeTlsRecord(clientStream, i)) continue;
    const recs = parseRecords(clientStream, i);
    if (recs && recs.length >= 1) {
      // Heuristic: require the ClientHello handshake to start here for the
      // first record (type 22, first byte of body == 1).
      if (recs[0].type === 22) {
        const body = clientStream.subarray(i + 5, i + 5 + recs[0].length);
        if (body.length >= 4 && body[0] === HS_CLIENT_HELLO) {
          return { client: i, server: i };
        }
      }
    }
  }
  return null;
}

function parseClientHello(
  body: Uint8Array,
  recs: TlsRecordInfo[],
): ClientHelloInfo | null {
  if (body.length < 35) return null;
  let off = 0;
  const recVersionMajor = recs[0]?.versionMajor ?? 3;
  const recVersionMinor = recs[0]?.versionMinor ?? 3;
  off += 2; // legacy version
  off += 32; // random
  const sidLen = body[off];
  off += 1 + sidLen;
  if (off + 2 > body.length) return null;
  const csLen = (body[off] << 8) | body[off + 1];
  off += 2;
  const offeredCipherHexes: string[] = [];
  for (let i = 0; i + 1 < csLen && off + i + 1 < body.length; i += 2) {
    offeredCipherHexes.push(hex2(body[off + i], body[off + i + 1]));
  }
  off += csLen;
  if (off >= body.length) {
    return {
      recordVersionMajor: recVersionMajor,
      recordVersionMinor: recVersionMinor,
      offeredVersions: [],
      offeredCipherHexes,
      randomHex: hexOf(body.subarray(2, 34)),
    };
  }
  const compLen = body[off];
  off += 1 + compLen;
  const offeredVersions: string[] = [];
  let randomHex = hexOf(body.subarray(2, 34));
  if (off + 2 <= body.length) {
    const extLen = (body[off] << 8) | body[off + 1];
    off += 2;
    const extEnd = Math.min(off + extLen, body.length);
    while (off + 4 <= extEnd) {
      const extType = (body[off] << 8) | body[off + 1];
      const extLen2 = (body[off + 2] << 8) | body[off + 3];
      const extBody = body.subarray(off + 4, Math.min(off + 4 + extLen2, extEnd));
      if (extType === 43 && extBody.length >= 1) {
        const n = extBody[0];
        for (let i = 1; i + 1 < 1 + n && i + 1 < extBody.length; i += 2) {
          offeredVersions.push(versionString(3, extBody[i + 1]));
        }
      }
      off += 4 + extLen2;
    }
  }
  void randomHex;
  return {
    recordVersionMajor: recVersionMajor,
    recordVersionMinor: recVersionMinor,
    offeredVersions,
    offeredCipherHexes,
    randomHex: hexOf(body.subarray(2, 34)),
  };
}

function parseServerHello(
  body: Uint8Array,
  recs: TlsRecordInfo[],
): ServerHelloInfo | null {
  if (body.length < 38) return null;
  const recVersionMajor = recs[0]?.versionMajor ?? 3;
  const recVersionMinor = recs[0]?.versionMinor ?? 3;
  let off = 0;
  const verMajor = body[off];
  const verMinor = body[off + 1];
  off += 2 + 32;
  const sidLen = body[off];
  off += 1 + sidLen;
  if (off + 3 > body.length) return null;
  const cipherHex = hex2(body[off], body[off + 1]);
  off += 2 + 1; // cipher + compression
  let isTls13 = verMajor === 3 && verMinor === 4;
  if (off + 2 <= body.length) {
    const extLen = (body[off] << 8) | body[off + 1];
    off += 2;
    const extEnd = Math.min(off + extLen, body.length);
    while (off + 4 <= extEnd) {
      const extType = (body[off] << 8) | body[off + 1];
      const elen = (body[off + 2] << 8) | body[off + 3];
      if (extType === 43 && elen >= 2) {
        const v = body[off + 6]; // 2-byte list, take first... actually supported_versions in SH is a single version (2 bytes)
        const vm = body[off + 4];
        const vn = body[off + 5];
        if (vm === 3 && vn === 4) isTls13 = true;
        void v;
      }
      off += 4 + elen;
    }
  }
  return {
    recordVersionMajor: recVersionMajor,
    recordVersionMinor: recVersionMinor,
    cipherHex,
    versionMajor: isTls13 ? 3 : verMajor,
    versionMinor: isTls13 ? 4 : verMinor,
    randomHex: hexOf(body.subarray(2, 34)),
    isTls13,
  };
}

function parseCertificateList(body: Uint8Array): CertDer[] {
  if (body.length < 3) return [];
  const listLen = (body[0] << 16) | (body[1] << 8) | body[2];
  const end = Math.min(3 + listLen, body.length);
  const out: CertDer[] = [];
  let off = 3;
  while (off + 3 <= end) {
    const certLen = (body[off] << 16) | (body[off + 1] << 8) | body[off + 2];
    off += 3;
    if (certLen === 0 || off + certLen > end) break;
    out.push({ der: body.subarray(off, off + certLen) });
    off += certLen;
  }
  return out;
}

export function versionString(major: number, minor: number): string {
  if (major === 3) {
    if (minor === 0) return "SSL 3.0";
    if (minor === 1) return "TLS 1.0";
    if (minor === 2) return "TLS 1.1";
    if (minor === 3) return "TLS 1.2";
    if (minor === 4) return "TLS 1.3";
  }
  if (major === 2) return "SSL 2.0";
  return `SSL/TLS 0x${major.toString(16)}0${minor.toString(16)}`;
}

// ---------------------------------------------------------------------------
// Cipher suite interpretation
// ---------------------------------------------------------------------------

const CIPHER_NAMES: Record<string, string> = {
  "0x002F": "TLS_RSA_WITH_AES_128_CBC_SHA",
  "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
  "0x003C": "TLS_RSA_WITH_AES_128_CBC_SHA256",
  "0x003D": "TLS_RSA_WITH_AES_256_CBC_SHA256",
  "0x009C": "TLS_RSA_WITH_AES_128_GCM_SHA256",
  "0x009D": "TLS_RSA_WITH_AES_256_GCM_SHA384",
  "0x0004": "TLS_RSA_WITH_RC4_128_MD5",
  "0x0005": "TLS_RSA_WITH_RC4_128_SHA",
  "0x000A": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
  "0x002B": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
  "0x002C": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
  "0xC013": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
  "0xC014": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
  "0xC023": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
  "0xC027": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
  "0xC02B": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "0xC02C": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "0xC02F": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "0xC030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "0x0067": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
  "0x006B": "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
  "0x009E": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
  "0x009F": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
  "0x1301": "TLS_AES_128_GCM_SHA256",
  "0x1302": "TLS_AES_256_GCM_SHA384",
  "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
  "0xCCA9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  "0xCCA8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  "0xC007": "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
  "0xC011": "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
  "0x008C": "TLS_PSK_WITH_AES_128_CBC_SHA",
  "0x00AA": "TLS_DHE_RSA_WITH_AES_128_CCM",
};

export function cipherName(hex: string): string | null {
  return CIPHER_NAMES[hex.toUpperCase()] ?? null;
}

/** Decompose a suite name into properties. Returns nulls when unknown. */
export function cipherProps(
  hex: string,
  name: string | null,
  tlsVersion: string,
): {
  keyExchange: string | null;
  authMethod: string | null;
  bulkCipher: string | null;
  hashMac: string | null;
  forwardSecrecy: boolean | null;
} {
  if (tlsVersion === "TLS 1.3") {
    return {
      keyExchange: "(ephemeral) ECDHE",
      authMethod: null,
      bulkCipher: name?.includes("CHACHA20")
        ? "CHACHA20_POLY1305"
        : name?.includes("256")
          ? "AES_256_GCM"
          : "AES_128_GCM",
      hashMac: name?.includes("384") ? "SHA384" : "SHA256",
      forwardSecrecy: true,
    };
  }
  if (!name) {
    const h = hex.toUpperCase();
    // A few well-known prefixes for unnamed suites
    if (h.startsWith("0xC0")) {
      return {
        keyExchange: null,
        authMethod: null,
        bulkCipher: null,
        hashMac: null,
        forwardSecrecy: null,
      };
    }
    return {
      keyExchange: null,
      authMethod: null,
      bulkCipher: null,
      hashMac: null,
      forwardSecrecy: null,
    };
  }
  const withoutPrefix = name.replace(/^TLS_|^SSL_/, "");
  const withIdx = withoutPrefix.indexOf("_WITH_");
  if (withIdx === -1) {
    return {
      keyExchange: null,
      authMethod: null,
      bulkCipher: null,
      hashMac: null,
      forwardSecrecy: null,
    };
  }
  const left = withoutPrefix.slice(0, withIdx);
  const right = withoutPrefix.slice(withIdx + 6);
  const kxAuth = left.split("_");
  const keRaw = kxAuth[0];
  const auth = kxAuth.length > 1 ? kxAuth[kxAuth.length - 1] : null;
  const keyExchange =
    keRaw === "ECDHE" || keRaw === "DHE" || keRaw === "ECDHE_PSK" || keRaw === "DHE_PSK"
      ? keRaw
      : keRaw === "ECDH" || keRaw === "DH"
        ? `${keRaw} (static)`
        : keRaw === "RSA"
          ? "RSA"
          : keRaw;
  const parts = right.split("_");
  const hash = parts[parts.length - 1];
  const bulk = parts
    .slice(0, parts.length - 1)
    .join("_")
    .replace(/_/g, " ");
  const forwardSecrecy =
    keRaw === "ECDHE" || keRaw === "DHE" || keRaw.includes("PSK")
      ? true
      : keRaw === "RSA" || keRaw === "ECDH" || keRaw === "DH"
        ? false
        : null;
  return { keyExchange, authMethod: auth, bulkCipher: bulk, hashMac: hash, forwardSecrecy };
}

function summarize(
  cipherHex: string,
  verMajor: number,
  verMinor: number,
): NegotiatedTls {
  const version = versionString(verMajor, verMinor);
  const name = cipherName(cipherHex);
  const props = cipherProps(cipherHex, name, version);
  return {
    version,
    versionMajor: verMajor,
    versionMinor: verMinor,
    cipherHex,
    cipherName: name,
    ...props,
  };
}

function hex2(a: number, b: number): string {
  return `0x${((a << 8) | b).toString(16).toUpperCase().padStart(4, "0")}`;
}

function hexOf(b: Uint8Array): string {
  return Array.from(b.subarray(0, 32))
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

