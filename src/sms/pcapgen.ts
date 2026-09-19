/**
 * Synthetic PCAP generator for the Test Lab and Demo mode.
 * Builds real libpcap files in-memory: Ethernet/IPv4/TCP frames carrying
 * SMTP/IMAP/POP3 plaintext phases and genuine TLS record-layer handshakes
 * with DER-encoded certificates. Demo scenarios run through the exact same
 * pipeline as uploaded files — no prewritten dashboard values.
 */

// ---------------------------------------------------------------------------
// Byte builders
// ---------------------------------------------------------------------------

class ByteWriter {
  private chunks: number[] = [];
  push(...bytes: number[]): ByteWriter {
    for (const b of bytes) this.chunks.push(b & 0xff);
    return this;
  }
  pushBytes(b: ArrayLike<number>): ByteWriter {
    for (let i = 0; i < b.length; i++) this.chunks.push(b[i] & 0xff);
    return this;
  }
  u16(v: number): ByteWriter {
    return this.push((v >> 8) & 0xff, v & 0xff);
  }
  u16le(v: number): ByteWriter {
    return this.push(v & 0xff, (v >> 8) & 0xff);
  }
  u32(v: number): ByteWriter {
    return this.push((v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
  }
  u32le(v: number): ByteWriter {
    return this.push(v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >> 24) & 0xff);
  }
  ascii(s: string): ByteWriter {
    for (let i = 0; i < s.length; i++) this.chunks.push(s.charCodeAt(i) & 0xff);
    return this;
  }
  length(): number {
    return this.chunks.length;
  }
  toUint8(): Uint8Array {
    return new Uint8Array(this.chunks);
  }
}

function ipToBytes(ip: string): number[] {
  return ip.split(".").map((x) => parseInt(x, 10) & 0xff);
}

// ---------------------------------------------------------------------------
// DER encoder (certificates)
// ---------------------------------------------------------------------------

function derLen(len: number): number[] {
  if (len < 0x80) return [len];
  if (len < 0x100) return [0x81, len];
  return [0x82, (len >> 8) & 0xff, len & 0xff];
}

function derTag(tag: number, content: number[]): number[] {
  return [tag, ...derLen(content.length), ...content];
}

function derSeq(...items: number[][]): number[] {
  return derTag(0x30, items.flat());
}

function derSet(...items: number[][]): number[] {
  return derTag(0x31, items.flat());
}

function derOid(oid: string): number[] {
  const parts = oid.split(".").map((x) => parseInt(x, 10));
  const out: number[] = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i++) {
    let v = parts[i];
    if (v < 0x80) {
      out.push(v);
      continue;
    }
    const bytes: number[] = [];
    while (v > 0) {
      bytes.unshift((v & 0x7f) | (bytes.length ? 0x80 : 0));
      v >>= 7;
    }
    out.push(...bytes);
  }
  return derTag(0x06, out);
}

function derUtf8(s: string): number[] {
  // reserved for future extension encoding
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i) & 0xff);
  return derTag(0x0c, bytes);
}

function derPrintable(s: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i) & 0xff);
  return derTag(0x13, bytes);
}

function derUtcTime(s: string): number[] {
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) bytes.push(s.charCodeAt(i) & 0xff);
  return derTag(0x17, bytes);
}

function derInteger(v: number): number[] {
  return derTag(0x02, [v & 0x7f]);
}

function derBitString(content: number[]): number[] {
  return derTag(0x03, [0, ...content]);
}

function derOctetString(content: number[]): number[] {
  return derTag(0x04, content);
}

function derNull(): number[] {
  return [0x05, 0x00];
}

export interface CertSpec {
  cn: string;
  sanDns: string[];
  issuerCn: string;
  notBeforeStr: string; // "YYMMDDHHMMSSZ"
  notAfterStr: string;
  keyBits: 512 | 1024 | 2048 | 3072;
  sigAlg: "sha1WithRSAEncryption" | "sha256WithRSAEncryption";
  serial: number;
  isCa: boolean;
}

/** Build a DER certificate (structurally valid X.509 v3, non-functional signature). */
export function buildDerCertificate(spec: CertSpec): Uint8Array {
  const tbsVersion = derTag(0xa0, derInteger(2)); // [0] EXPLICIT v3
  const serial = derInteger(spec.serial & 0x7f);
  const sigOid =
    spec.sigAlg === "sha256WithRSAEncryption"
      ? "1.2.840.113549.1.1.11"
      : "1.2.840.113549.1.1.5";
  const sigAlg = derSeq(derOid(sigOid), derNull());
  const name = (cn: string) =>
    derSeq(derSet(derSeq(derOid("2.5.4.3"), derPrintable(cn))));
  const issuer = name(spec.issuerCn);
  const validity = derSeq(derUtcTime(spec.notBeforeStr), derUtcTime(spec.notAfterStr));
  const subject = name(spec.cn);
  const rsaOid = derOid("1.2.840.113549.1.1.1");
  const spkiInner = derSeq(derInteger(0x10001), derBitString(new Array(Math.ceil(spec.keyBits / 8)).fill(0x6b)));
  const spki = derSeq(rsaOid, derNull(), derBitString(spkiInner));
  const sanNames = spec.sanDns.map((d) => derTag(0x82, strBytes(d)));
  const san = derSeq(
    derOid("2.5.29.17"),
    derOctetString(derSeq(...sanNames)),
  );
  const bc = derSeq(
    derOid("2.5.29.19"),
    derOctetString(derSeq(spec.isCa ? derTagBool(true) : derTagBool(false))),
  );
  const extensions = derTag(0xa3, derSeq(san, bc));
  const tbs = derSeq(
    tbsVersion,
    serial,
    sigAlg,
    issuer,
    validity,
    subject,
    spki,
    extensions,
  );
  const outerSig = derBitString(new Array(128).fill(0x42));
  const cert = derSeq(tbs, sigAlg, outerSig);
  return new Uint8Array(cert);
}

function derTagBool(v: boolean): number[] {
  return derTag(0x01, [v ? 0xff : 0x00]);
}

function strBytes(s: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xff);
  return out;
}

// ---------------------------------------------------------------------------
// TLS handshake construction
// ---------------------------------------------------------------------------

export interface TlsSpec {
  version: 0 | 1 | 2 | 3 | 4; // SSL3.0, TLS1.0, TLS1.1, TLS1.2, TLS1.3
  cipherHex: number; // e.g. 0x002f
  offerVersions?: number[]; // supported_versions entries (minor numbers)
  includeCert: boolean;
  cert?: Uint8Array;
  includeAlert?: { level: number; description: number };
  recordCount?: number;
}

function handshakeMsg(type: number, body: number[]): number[] {
  const len = body.length;
  return [type, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff, ...body];
}

function record(type: number, minor: number, body: number[]): number[] {
  const len = body.length;
  return [type, 3, minor, (len >> 8) & 0xff, len & 0xff, ...body];
}

function buildClientHello(spec: TlsSpec): number[] {
  const random = new Array(32).fill(0x11);
  const sessionId = [0];
  const suites = [0, spec.cipherHex];
  const comp = [1, 0];
  let body = [3, Math.min(spec.version, 3), ...random, ...sessionId, ...suites, ...comp];
  if (spec.offerVersions && spec.offerVersions.length > 0) {
    const listLen = spec.offerVersions.length * 2;
    const svBody = [listLen, ...spec.offerVersions.flatMap((m) => [3, m])];
    const svExt = [0, 43, 0, svBody.length, ...svBody];
    const extLen = svExt.length;
    body = [...body, (extLen >> 8) & 0xff, extLen & 0xff, ...svExt];
  }
  return handshakeMsg(1, body);
}

function buildServerHello(spec: TlsSpec): number[] {
  const random = new Array(32).fill(0x22);
  const sessionId = [0];
  const cipher = [(spec.cipherHex >> 8) & 0xff, spec.cipherHex & 0xff];
  let body = [
    3,
    Math.min(spec.version, 3),
    ...random,
    ...sessionId,
    ...cipher,
    0,
  ];
  if (spec.version === 4) {
    const svExt = [43, 0, 2, 3, 4];
    body = [...body, 0, 4, ...svExt];
  }
  return handshakeMsg(2, body);
}

function buildCertificateMsg(certs: Uint8Array[]): number[] {
  let list: number[] = [];
  for (const c of certs) {
    list = [...list, (c.length >> 16) & 0xff, (c.length >> 8) & 0xff, c.length & 0xff, ...c];
  }
  const body = [
    (list.length >> 16) & 0xff,
    (list.length >> 8) & 0xff,
    list.length & 0xff,
    ...list,
  ];
  return handshakeMsg(11, body);
}

function buildServerHelloDone(): number[] {
  return handshakeMsg(14, []);
}

function buildClientKeyExchange(): number[] {
  // minimal RSA kx payload
  return handshakeMsg(16, [0, 2, 0x6b, 0x6b]);
}

function buildChangeCipherSpec(): number[] {
  return record(20, 3, [1]);
}

function buildEncryptedHandshake(): number[] {
  return record(22, 3, new Array(64).fill(0x77));
}

function buildAppData(n: number): number[] {
  return record(23, 3, new Array(n).fill(0x99));
}

function buildAlert(level: number, description: number, minor: number): number[] {
  return record(21, minor, [level, description]);
}

/** Build the client-side TLS byte stream (what the client sent after STARTTLS). */
export function buildClientTlsStream(spec: TlsSpec): Uint8Array {
  const out = new ByteWriter();
  out.pushBytes(record(22, 3, buildClientHello(spec)));
  out.pushBytes(buildClientKeyExchange());
  out.pushBytes(buildChangeCipherSpec());
  out.pushBytes(buildEncryptedHandshake());
  out.pushBytes(buildAppData(64));
  return out.toUint8();
}

/** Build the server-side TLS byte stream. */
export function buildServerTlsStream(spec: TlsSpec): Uint8Array {
  const out = new ByteWriter();
  out.pushBytes(record(22, 3, buildServerHello(spec)));
  if (spec.includeCert && spec.cert) {
    out.pushBytes(record(22, 3, buildCertificateMsg([spec.cert])));
  }
  out.pushBytes(record(22, 3, buildServerHelloDone()));
  out.pushBytes(buildChangeCipherSpec());
  out.pushBytes(buildEncryptedHandshake());
  out.pushBytes(buildAppData(96));
  if (spec.includeAlert) {
    out.pushBytes(buildAlert(spec.includeAlert.level, spec.includeAlert.description, 3));
  }
  return out.toUint8();
}

// ---------------------------------------------------------------------------
// TCP / IP / Ethernet frame assembly
// ---------------------------------------------------------------------------

interface PcapPacketSpec {
  srcIp: string;
  dstIp: string;
  srcPort: number;
  dstPort: number;
  seq: number;
  ack: number;
  flags: number;
  payload?: Uint8Array;
  ts: number;
}

function tcpChecksumPlaceholder(): number[] {
  return [0, 0];
}

function buildEthernetFrame(ipPacket: number[]): number[] {
  const dst = [0x02, 0x00, 0x00, 0x00, 0x00, 0x02];
  const src = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
  const ethertype = [0x08, 0x00];
  return [...dst, ...src, ...ethertype, ...ipPacket];
}

function buildIpPacket(srcIp: string, dstIp: string, proto: number, tcpSegment: number[], ident: number): number[] {
  const totalLen = 20 + tcpSegment.length;
  const header: number[] = [
    0x45,
    0,
    (totalLen >> 8) & 0xff,
    totalLen & 0xff,
    (ident >> 8) & 0xff,
    ident & 0xff,
    0x40,
    0,
    64,
    proto,
    0,
    0,
    0,
    0,
    ...ipToBytes(srcIp),
    ...ipToBytes(dstIp),
  ];
  return [...header, ...tcpSegment];
}

function buildTcpSegment(p: PcapPacketSpec): number[] {
  const dataOffset = 5; // 20 bytes, no options
  const flagsByte = p.flags;
  const seg: number[] = [
    (p.srcPort >> 8) & 0xff,
    p.srcPort & 0xff,
    (p.dstPort >> 8) & 0xff,
    p.dstPort & 0xff,
    (p.seq >>> 24) & 0xff,
    (p.seq >>> 16) & 0xff,
    (p.seq >>> 8) & 0xff,
    p.seq & 0xff,
    (p.ack >>> 24) & 0xff,
    (p.ack >>> 16) & 0xff,
    (p.ack >>> 8) & 0xff,
    p.ack & 0xff,
    (dataOffset << 4) & 0xff,
    flagsByte,
    0x20,
    0x00,
    ...tcpChecksumPlaceholder(),
    0,
    0,
  ];
  if (p.payload) {
    for (let i = 0; i < p.payload.length; i++) seg.push(p.payload[i]);
  }
  return seg;
}

export interface TcpExchange {
  clientIp: string;
  serverIp: string;
  clientPort: number;
  serverPort: number;
  clientLines: string[]; // plaintext client messages (before TLS)
  serverLines: string[];
  clientTlsStream?: Uint8Array;
  serverTlsStream?: Uint8Array;
  t0: number; // start epoch seconds
  finishWith?: "fin" | "rst" | "none";
}

const FLAG_FIN = 0x01;
const FLAG_SYN = 0x02;
const FLAG_RST = 0x04;
const FLAG_PSH = 0x08;
const FLAG_ACK = 0x10;

export interface GeneratedPcap {
  bytes: Uint8Array;
  packetCount: number;
  startTs: number;
  endTs: number;
}

/** Build a full libpcap file from one or more TCP exchanges. */
export function buildPcap(exchanges: TcpExchange[]): GeneratedPcap {
  const packets: Array<{ ts: number; frame: number[] }> = [];
  let ident = 1;

  for (const ex of exchanges) {
    const cSeqStart = 1000;
    const sSeqStart = 5000;
    let cSeq = cSeqStart;
    let sSeq = sSeqStart;
    let cAck = sSeqStart;
    let sAck = cSeqStart;
    let t = ex.t0;

    const add = (
      src: "c" | "s",
      flags: number,
      payload: Uint8Array | undefined,
      ts: number,
    ) => {
      const spec: PcapPacketSpec =
        src === "c"
          ? {
              srcIp: ex.clientIp,
              dstIp: ex.serverIp,
              srcPort: ex.clientPort,
              dstPort: ex.serverPort,
              seq: cSeq,
              ack: sAck,
              flags,
              payload,
              ts,
            }
          : {
              srcIp: ex.serverIp,
              dstIp: ex.clientIp,
              srcPort: ex.serverPort,
              dstPort: ex.clientPort,
              seq: sSeq,
              ack: cAck,
              flags,
              payload,
              ts,
            };
      const seg = buildTcpSegment(spec);
      const ip = buildIpPacket(spec.srcIp, spec.dstIp, 6, seg, ident++);
      packets.push({ ts, frame: buildEthernetFrame(ip) });
      const plen = payload ? payload.length : 0;
      if (src === "c") {
        cSeq += plen;
        sAck = cSeq;
      } else {
        sSeq += plen;
        cAck = sSeq;
      }
    };

    // handshake
    add("c", FLAG_SYN, undefined, t);
    t += 0.001;
    add("s", FLAG_SYN | FLAG_ACK, undefined, t);
    t += 0.001;
    add("c", FLAG_ACK, undefined, t);
    t += 0.002;

    // interleaved application data
    const maxLen = Math.max(ex.clientLines.length, ex.serverLines.length);
    for (let i = 0; i < maxLen; i++) {
      if (i < ex.clientLines.length) {
        const line = ex.clientLines[i];
        add("c", FLAG_PSH | FLAG_ACK, new Uint8Array(strBytes(line)), t);
        t += 0.01;
      }
      if (i < ex.serverLines.length) {
        const line = ex.serverLines[i];
        add("s", FLAG_PSH | FLAG_ACK, new Uint8Array(strBytes(line)), t);
        t += 0.01;
      }
    }

    // TLS streams (single packets)
    if (ex.clientTlsStream) {
      add("c", FLAG_PSH | FLAG_ACK, ex.clientTlsStream, t);
      t += 0.02;
    }
    if (ex.serverTlsStream) {
      add("s", FLAG_PSH | FLAG_ACK, ex.serverTlsStream, t);
      t += 0.02;
    }

    if (ex.finishWith === "fin") {
      add("c", FLAG_FIN | FLAG_ACK, undefined, t);
      t += 0.005;
      add("s", FLAG_FIN | FLAG_ACK, undefined, t);
      t += 0.005;
    } else if (ex.finishWith === "rst") {
      add("s", FLAG_RST | FLAG_ACK, undefined, t);
      t += 0.005;
    }
  }

  // pcap global header
  const out = new ByteWriter();
  out.u32le(0xa1b2c3d4);
  out.u16le(2);
  out.u16le(4);
  out.u32le(0);
  out.u32le(0);
  out.u32le(262144);
  out.u32le(1); // Ethernet
  for (const p of packets) {
    const sec = Math.floor(p.ts);
    const usec = Math.round((p.ts - sec) * 1e6);
    out.u32le(sec);
    out.u32le(usec);
    out.u32le(p.frame.length);
    out.u32le(p.frame.length);
    out.pushBytes(p.frame);
  }
  let endTs = 0;
  let startTs = Infinity;
  for (const p of packets) {
    if (p.ts < startTs) startTs = p.ts;
    if (p.ts > endTs) endTs = p.ts;
  }
  return { bytes: out.toUint8(), packetCount: packets.length, startTs, endTs };
}
