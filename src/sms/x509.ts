/**
 * Minimal X.509 certificate DER parser.
 * Extracts subject, issuer, validity, signature algorithm, public key info,
 * SANs, and self-signed status directly from DER bytes found in the capture.
 * Field presence is honest: when a field cannot be parsed, it is marked
 * unavailable rather than guessed.
 */

export interface CertInfo {
  subject: string;
  issuer: string;
  serialHex: string;
  notBefore: number; // epoch seconds
  notAfter: number;
  sigAlgName: string;
  pkAlgName: string;
  keyBits: number | null;
  keyBitsState: "verified" | "unavailable";
  sanDnsNames: string[];
  cn: string | null;
  isSelfSigned: boolean;
  parseOk: boolean;
}

const OID_CN = "2.5.4.3";
const OID_SAN = "2.5.29.17";

const SIG_ALGS: Record<string, string> = {
  "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
  "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
  "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
  "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
  "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
  "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
  "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
  "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
  "1.2.840.10045.4.1": "ecdsa-with-SHA1",
};

const PK_ALGS: Record<string, string> = {
  "1.2.840.113549.1.1.1": "RSA",
  "1.2.840.10045.2.1": "EC",
  "1.2.840.10045.4.3.2": "EC",
};

interface DerNode {
  tag: number;
  start: number; // content start
  end: number; // content end
  fullStart: number; // including header
  children: DerNode[] | null;
}

function readTagLen(b: Uint8Array, off: number): { tag: number; len: number; headerLen: number } | null {
  if (off + 2 > b.length) return null;
  const tag = b[off];
  let len = b[off + 1];
  let headerLen = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || off + 2 + n > b.length) return null;
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[off + 2 + i];
    headerLen = 2 + n;
  }
  return { tag, len, headerLen };
}

function parseStructure(b: Uint8Array, start: number, end: number, depth: number): DerNode | null {
  const head = readTagLen(b, start);
  if (!head) return null;
  const contentStart = start + head.headerLen;
  const contentEnd = contentStart + head.len;
  if (contentEnd > end) return null;
  const node: DerNode = {
    tag: head.tag,
    start: contentStart,
    end: contentEnd,
    fullStart: start,
    children: null,
  };
  const isConstructed = (head.tag & 0x20) !== 0;
  if (isConstructed && depth < 12) {
    node.children = [];
    let off = contentStart;
    while (off < contentEnd) {
      const child = parseStructure(b, off, contentEnd, depth + 1);
      if (!child) break;
      node.children.push(child);
      off = child.end;
    }
  }
  return node;
}

function oidToString(b: Uint8Array, s: number, e: number): string {
  const parts: number[] = [];
  let first = b[s];
  parts.push(Math.floor(first / 40), first % 40);
  let val = 0;
  for (let i = s + 1; i < e; i++) {
    val = (val << 7) | (b[i] & 0x7f);
    if (!(b[i] & 0x80)) {
      parts.push(val);
      val = 0;
    }
  }
  return parts.join(".");
}

function decodeString(b: Uint8Array, s: number, e: number): string {
  let out = "";
  for (let i = s; i < e; i++) out += String.fromCharCode(b[i]);
  return out;
}

function decodeUtcTime(b: Uint8Array, s: number, e: number): number {
  const str = decodeString(b, s, e);
  // YYMMDDHHMMSSZ
  const yy = parseInt(str.slice(0, 2), 10);
  const year = yy < 50 ? 2000 + yy : 1900 + yy;
  return makeEpoch(
    year,
    parseInt(str.slice(2, 4), 10),
    parseInt(str.slice(4, 6), 10),
    parseInt(str.slice(6, 8), 10),
    parseInt(str.slice(8, 10), 10),
    parseInt(str.slice(10, 12), 10),
  );
}

function decodeGeneralTime(b: Uint8Array, s: number, e: number): number {
  const str = decodeString(b, s, e);
  return makeEpoch(
    parseInt(str.slice(0, 4), 10),
    parseInt(str.slice(4, 6), 10),
    parseInt(str.slice(6, 8), 10),
    parseInt(str.slice(8, 10), 10),
    parseInt(str.slice(10, 12), 10),
    parseInt(str.slice(12, 14), 10),
  );
}

function makeEpoch(y: number, mo: number, d: number, h: number, mi: number, sec: number): number {
  return Math.floor(Date.UTC(y, mo - 1, d, h, mi, sec) / 1000);
}

function findOidNode(parent: DerNode, oid: string, b: Uint8Array): DerNode | null {
  if (!parent.children) return null;
  for (const c of parent.children) {
    if (c.children && c.children.length >= 2) {
      const oidNode = c.children[0];
      if (oidNode.tag === 6) {
        const got = oidToString(b, oidNode.start, oidNode.end);
        if (got === oid) return c;
      }
    }
  }
  return null;
}

export function parseCertificateDer(der: Uint8Array): CertInfo {
  const fail: CertInfo = {
    subject: "",
    issuer: "",
    serialHex: "",
    notBefore: 0,
    notAfter: 0,
    sigAlgName: "",
    pkAlgName: "",
    keyBits: null,
    keyBitsState: "unavailable",
    sanDnsNames: [],
    cn: null,
    isSelfSigned: false,
    parseOk: false,
  };

  const root = parseStructure(der, 0, der.length, 0);
  if (!root || !root.children || root.children.length < 3) return fail;

  const tbs = root.children[0];
  if (!tbs.children || tbs.children.length < 6) return fail;

  // serial
  const serial = tbs.children[1];
  if (serial.tag !== 2) return fail;
  let serialHex = "";
  for (let i = serial.start; i < serial.end; i++) {
    serialHex += der[i].toString(16).padStart(2, "0");
  }

  // signature algorithm (tbs)
  const sigAlgNode = tbs.children[2];
  let sigAlgName = "";
  if (sigAlgNode.children && sigAlgNode.children.length >= 1 && sigAlgNode.children[0].tag === 6) {
    const oid = oidToString(der, sigAlgNode.children[0].start, sigAlgNode.children[0].end);
    sigAlgName = SIG_ALGS[oid] ?? `OID ${oid}`;
  }

  // issuer
  const issuerNode = tbs.children[3];
  const issuer = rdnSequenceToString(der, issuerNode);

  // validity
  const validity = tbs.children[4];
  if (!validity.children || validity.children.length < 2) return fail;
  const nbNode = validity.children[0];
  const naNode = validity.children[1];
  const notBefore =
    nbNode.tag === 23 ? decodeUtcTime(der, nbNode.start, nbNode.end) : decodeGeneralTime(der, nbNode.start, nbNode.end);
  const notAfter =
    naNode.tag === 23 ? decodeUtcTime(der, naNode.start, naNode.end) : decodeGeneralTime(der, naNode.start, naNode.end);

  // subject
  const subjectNode = tbs.children[5];
  const subject = rdnSequenceToString(der, subjectNode);

  // SPKI
  const spki = tbs.children[6];
  let pkAlgName = "";
  let keyBits: number | null = null;
  if (spki.children && spki.children.length >= 2) {
    const algNode = spki.children[0];
    if (algNode.children && algNode.children.length >= 1 && algNode.children[0].tag === 6) {
      const oid = oidToString(der, algNode.children[0].start, algNode.children[0].end);
      pkAlgName = PK_ALGS[oid] ?? `OID ${oid}`;
      if (pkAlgName === "RSA" && spki.children[1].tag === 3) {
        // BIT STRING containing RSAPublicKey SEQUENCE
        const bit = spki.children[1];
        // first content byte = unused bits count
        const inner = parseStructure(der, bit.start + 1, bit.end, 0);
        if (inner && inner.children && inner.children.length >= 2) {
          const mod = inner.children[0];
          const bits = (mod.end - mod.start) * 8;
          keyBits = bits;
        }
      }
    }
  }

  // extensions
  const sanDnsNames: string[] = [];
  let isSelfSigned = subject === issuer && subject !== "";
  // extensions may be at tbs.children[7] when present
  const extParent = tbs.children.length >= 8 ? tbs.children[7] : null;
  if (extParent && extParent.tag === 0xa3 && extParent.children) {
    const exts = extParent.children[0];
    if (exts.children) {
      for (const ext of exts.children) {
        if (!ext.children || ext.children.length < 2) continue;
        const oidNode = ext.children[0];
        if (oidNode.tag !== 6) continue;
        const oid = oidToString(der, oidNode.start, oidNode.end);
        if (oid === OID_SAN) {
          const val = ext.children[ext.children.length - 1];
          // OCTET STRING wrapping a SEQUENCE of GeneralNames
          const inner = parseStructure(der, val.start, val.end, 0);
          if (inner && inner.tag === 4 && inner.children === null) {
            const seq = parseStructure(der, inner.start, inner.end, 0);
            if (seq && seq.children) {
              for (const gn of seq.children) {
                if (gn.tag === 0x82) {
                  sanDnsNames.push(decodeString(der, gn.start, gn.end));
                }
              }
            }
          } else if (seqChildrenOf(inner)) {
            const seq = inner;
            for (const gn of seq.children ?? []) {
              if (gn.tag === 0x82) {
                sanDnsNames.push(decodeString(der, gn.start, gn.end));
              }
            }
          }
        }
      }
    }
  }

  const cn = extractCn(subject);

  return {
    subject,
    issuer,
    serialHex,
    notBefore,
    notAfter,
    sigAlgName,
    pkAlgName,
    keyBits,
    keyBitsState: keyBits === null ? "unavailable" : "verified",
    sanDnsNames,
    cn,
    isSelfSigned,
    parseOk: true,
  };
}

function seqChildrenOf(n: DerNode | null): n is DerNode & { children: DerNode[] } {
  return !!n && n.tag === 4 && Array.isArray(n.children);
}

function rdnSequenceToString(b: Uint8Array, node: DerNode): string {
  if (!node.children) return "";
  const parts: string[] = [];
  for (const rdn of node.children) {
    if (!rdn.children) continue;
    for (const atv of rdn.children) {
      if (!atv.children || atv.children.length < 2) continue;
      const oidNode = atv.children[0];
      const valNode = atv.children[1];
      if (oidNode.tag !== 6) continue;
      const oid = oidToString(b, oidNode.start, oidNode.end);
      const val = decodeString(b, valNode.start, valNode.end);
      const label =
        oid === OID_CN
          ? "CN"
          : oid === "2.5.4.6" ? "C"
          : oid === "2.5.4.7" ? "L"
          : oid === "2.5.4.8" ? "ST"
          : oid === "2.5.4.10" ? "O"
          : oid === "2.5.4.11" ? "OU"
          : oid === "1.2.840.113549.1.9.1" ? "emailAddress"
          : `OID ${oid}`;
      parts.push(`${label}=${val}`);
    }
  }
  return parts.join(", ");
}

function extractCn(subject: string): string | null {
  const m = /(?:^|, )CN=([^,]+)/.exec(subject);
  return m ? m[1] : null;
}
