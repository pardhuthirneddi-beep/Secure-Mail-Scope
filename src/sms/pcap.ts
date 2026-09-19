/**
 * PCAP / PCAPNG container parsing, Ethernet/IPv4/IPv6/TCP/UDP decode.
 * Pure TypeScript — runs entirely in the browser, no server round-trip.
 */

export interface PcapPacket {
  index: number;
  ts: number; // epoch seconds (float)
  data: Uint8Array; // link-layer frame
}

export interface PcapParseResult {
  packets: PcapPacket[];
  linkType: number;
  parseWarnings: string[];
  format: "libpcap" | "pcapng";
}

const PCAP_MAGIC_LE = 0xa1b2c3d4;
const PCAP_MAGIC_BE = 0xd4c3b2a1;
const PCAP_MAGIC_NANO_LE = 0xa1b23c4d;
const PCAP_MAGIC_NANO_BE = 0x4d3cb2a1;

const LINKTYPE_ETHERNET = 1;
const LINKTYPE_RAW = 101;
const LINKTYPE_LINUX_SLL = 113;
const LINKTYPE_LINUX_SLL2 = 276;
const LINKTYPE_NULL = 0;

export class PcapParseError extends Error {
  reason: string;
  constructor(reason: string) {
    super(reason);
    this.reason = reason;
  }
}

function u16At(b: Uint8Array, off: number, le: boolean): number {
  return le ? b[off] | (b[off + 1] << 8) : (b[off] << 8) | b[off + 1];
}

function u32At(b: Uint8Array, off: number, le: boolean): number {
  return le
    ? (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0
    : ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
}

/** Parse classic libpcap and pcapng containers. */
export function parseCapture(buf: ArrayBuffer): PcapParseResult {
  const b = new Uint8Array(buf);
  if (b.length < 24) {
    throw new PcapParseError(
      "File is too small to be a valid capture (minimum 24 bytes).",
    );
  }

  const magic = u32At(b, 0, true);
  if (
    magic === PCAP_MAGIC_LE ||
    magic === PCAP_MAGIC_BE ||
    magic === PCAP_MAGIC_NANO_LE ||
    magic === PCAP_MAGIC_NANO_BE
  ) {
    return parseLibpcap(b, magic);
  }
  if (magic === 0x0a0d0d0a) {
    return parsePcapng(b);
  }
  throw new PcapParseError(
    "Unsupported capture format. Expected a libpcap (.pcap) or pcapng (.pcapng) file.",
  );
}

function parseLibpcap(b: Uint8Array, magic: number): PcapParseResult {
  const le = magic === PCAP_MAGIC_LE || magic === PCAP_MAGIC_NANO_LE;
  const nanos =
    magic === PCAP_MAGIC_NANO_LE || magic === PCAP_MAGIC_NANO_BE;
  const versionMajor = u16At(b, 4, le);
  const linkType = u32At(b, 20, le);
  const warnings: string[] = [];

  const packets: PcapPacket[] = [];
  let off = 24;
  let index = 0;
  while (off + 16 <= b.length) {
    const tsSec = u32At(b, off, le);
    const tsFrac = u32At(b, off + 4, le);
    const inclLen = u32At(b, off + 8, le);
    const origLen = u32At(b, off + 12, le);
    off += 16;
    if (inclLen > 0x400000 || off + inclLen > b.length) {
      warnings.push(
        `Truncated packet record at index ${index}; remaining bytes skipped.`,
      );
      break;
    }
    if (origLen > inclLen) {
      warnings.push(
        `Packet ${index} was captured with snaplen ${inclLen} < original ${origLen} bytes (sliced capture).`,
      );
    }
    const ts = nanos ? tsSec + tsFrac / 1e9 : tsSec + tsFrac / 1e6;
    packets.push({ index, ts, data: b.subarray(off, off + inclLen) });
    off += inclLen;
    index++;
  }

  if (versionMajor > 2 || versionMajor === 0) {
    warnings.push(`Unusual libpcap version ${versionMajor}.x reported by header.`);
  }
  if (packets.length === 0) {
    throw new PcapParseError("Capture contains zero readable packet records.");
  }
  return { packets, linkType, parseWarnings: warnings, format: "libpcap" };
}

function parsePcapng(b: Uint8Array): PcapParseResult {
  const warnings: string[] = [];
  const packets: PcapPacket[] = [];
  let linkType = LINKTYPE_ETHERNET;
  let linkTypeSeen = false;
  let ifaces: Array<{ linkType: number; tsResol: number }> = [];
  let off = 0;
  let index = 0;

  while (off + 12 <= b.length) {
    const blockType = u32At(b, off, true);
    const blockLen = u32At(b, off + 4, true);
    if (blockLen < 12 || off + blockLen > b.length) {
      warnings.push(`Malformed pcapng block at byte ${off}; stopping.`);
      break;
    }
    if (blockType === 0x0a0d0d0a) {
      // SHB — endian check via byte-order magic inside
      const bom = u32At(b, off + 8, true);
      if (bom !== 0x1a2b3c4d) {
        // big-endian SHB; we bail — rare, keep simple but honest
        warnings.push("Big-endian pcapng is not supported; packets may be skipped.");
      }
    } else if (blockType === 0x00000001) {
      // IDB
      const lt = u16At(b, off + 8, true);
      const tsResol = b[off + 14] === 0 ? 6 : b[off + 14] & 0x03; // simplified
      ifaces.push({ linkType: lt, tsResol });
      if (!linkTypeSeen) {
        linkType = lt;
        linkTypeSeen = true;
      }
    } else if (blockType === 0x00000006) {
      // EPB
      const ifaceId = u32At(b, off + 8, true);
      const tsHigh = u32At(b, off + 12, true);
      const tsLow = u32At(b, off + 16, true);
      const capLen = u32At(b, off + 20, true);
      const iface = ifaces[ifaceId] ?? { linkType, tsResol: 6 };
      const ts =
        ((tsHigh * 4294967296 + tsLow) * microResol(iface.tsResol)) / 1e6;
      const dataOff = off + 28;
      if (dataOff + capLen > off + blockLen) {
        warnings.push(`Packet ${index} exceeds block bounds; skipped.`);
      } else {
        packets.push({ index, ts, data: b.subarray(dataOff, dataOff + capLen) });
      }
      index++;
    }
    off += blockLen;
  }

  if (packets.length === 0) {
    throw new PcapParseError("pcapng contains zero readable Enhanced Packet Blocks.");
  }
  return { packets, linkType, parseWarnings: warnings, format: "pcapng" };
}

function microResol(tsResol: number): number {
  // if_tsresol: lower 6 bits = power; default 6 => microseconds
  const power = (tsResol & 0x0f) === 0 ? 6 : tsResol & 0x0f;
  return Math.pow(10, -power) * 1e6 / 1e6 * 1e6 === 0 ? 1 : Math.pow(10, power);
}

// ---------------------------------------------------------------------------
// L2/L3/L4 decode
// ---------------------------------------------------------------------------

export interface IpEndpoint {
  ip: string;
  port: number;
}

export interface DecodedPacket {
  index: number;
  ts: number;
  linkType: number;
  srcIp: string;
  dstIp: string;
  ipProto: number;
  srcPort: number;
  dstPort: number;
  tcpSeq: number;
  tcpAck: number;
  tcpFlags: number;
  payload: Uint8Array | null; // TCP/UDP payload
  ipPayloadLength: number;
  decodeState: "ok" | "no-ip" | "no-tcp-udp" | "no-payload";
}

export const TCP_FLAGS = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20,
};

export function decodePacket(p: PcapPacket, linkType: number): DecodedPacket {
  const base: DecodedPacket = {
    index: p.index,
    ts: p.ts,
    linkType,
    srcIp: "",
    dstIp: "",
    ipProto: 0,
    srcPort: 0,
    dstPort: 0,
    tcpSeq: 0,
    tcpAck: 0,
    tcpFlags: 0,
    payload: null,
    ipPayloadLength: 0,
    decodeState: "no-ip",
  };

  const l3 = stripLinkLayer(p.data, linkType);
  if (!l3) return base;
  const ethertypeOrProto = l3.next;
  const d = l3.data;

  let ipOff = 0;
  let version = 0;
  if (ethertypeOrProto === 0x0800) {
    version = d[0] >> 4;
    if (version !== 4) return { ...base, decodeState: "no-ip" };
  } else if (ethertypeOrProto === 0x86dd) {
    version = 6;
  } else {
    return { ...base, decodeState: "no-ip" };
  }

  let srcIp = "";
  let dstIp = "";
  let ipProto = 0;
  let protoOff = 0;
  let ipPayloadLength = 0;

  if (version === 4) {
    if (d.length < 20) return { ...base, decodeState: "no-ip" };
    const ihl = (d[0] & 0x0f) * 4;
    if (ihl < 20 || d.length < ihl) return { ...base, decodeState: "no-ip" };
    ipProto = d[9];
    srcIp = `${d[12]}.${d[13]}.${d[14]}.${d[15]}`;
    dstIp = `${d[16]}.${d[17]}.${d[18]}.${d[19]}`;
    protoOff = ihl;
    const totalLen = (d[2] << 8) | d[3];
    ipPayloadLength = totalLen >= ihl ? totalLen - ihl : d.length - ihl;
  } else {
    if (d.length < 40) return { ...base, decodeState: "no-ip" };
    ipProto = d[6];
    srcIp = ipv6ToString(d, 8);
    dstIp = ipv6ToString(d, 24);
    protoOff = 40;
    ipPayloadLength = (d[4] << 8) | d[5];
    if (ipPayloadLength === 0) ipPayloadLength = d.length - protoOff; // jumbograph-less guess
  }

  const out: DecodedPacket = {
    ...base,
    srcIp,
    dstIp,
    ipProto,
    ipPayloadLength,
  };

  if (ipProto === 6 && protoOff + 20 <= d.length) {
    out.srcPort = (d[protoOff] << 8) | d[protoOff + 1];
    out.dstPort = (d[protoOff + 2] << 8) | d[protoOff + 3];
    out.tcpSeq = u32At(d, protoOff + 4, false);
    out.tcpAck = u32At(d, protoOff + 8, false);
    const dataOffset = ((d[protoOff + 12] >> 4) & 0x0f) * 4;
    out.tcpFlags = d[protoOff + 13];
    const payloadStart = protoOff + Math.max(20, dataOffset);
    if (payloadStart < d.length) {
      const segLen = Math.min(d.length - payloadStart, Math.max(0, ipPayloadLength - Math.max(20, dataOffset)));
      out.payload =
        segLen > 0 ? d.subarray(payloadStart, payloadStart + segLen) : null;
    }
    out.decodeState = out.payload ? "ok" : "no-payload";
  } else if (ipProto === 17 && protoOff + 8 <= d.length) {
    out.srcPort = (d[protoOff] << 8) | d[protoOff + 1];
    out.dstPort = (d[protoOff + 2] << 8) | d[protoOff + 3];
    const payloadStart = protoOff + 8;
    out.payload =
      payloadStart < d.length ? d.subarray(payloadStart) : null;
    out.decodeState = out.payload ? "ok" : "no-payload";
  } else {
    out.decodeState = "no-tcp-udp";
  }
  return out;
}

/** Return the L3 (IP) datagram and its ethertype based on link type. */
function stripLinkLayer(
  frame: Uint8Array,
  linkType: number,
): { data: Uint8Array; next: number } | null {
  switch (linkType) {
    case LINKTYPE_ETHERNET: {
      if (frame.length < 14) return null;
      const ethertype = (frame[12] << 8) | frame[13];
      if (ethertype === 0x8100 || ethertype === 0x88a8) {
        // VLAN / QinQ — skip 4 bytes per tag
        let off = 14;
        let et = 0;
        for (let i = 0; i < 2; i++) {
          if (off + 4 > frame.length) return null;
          et = (frame[off + 2] << 8) | frame[off + 3];
          if (et === 0x8100 || et === 0x88a8) off += 4;
          else break;
        }
        if (et === 0) et = (frame[off] << 8) | frame[off + 1];
        return { data: frame.subarray(off + 2), next: et };
      }
      return { data: frame.subarray(14), next: ethertype };
    }
    case LINKTYPE_RAW:
      return { data: frame, next: frame[0] >> 4 === 4 ? 0x0800 : 0x86dd };
    case LINKTYPE_LINUX_SLL: {
      if (frame.length < 16) return null;
      const proto = (frame[14] << 8) | frame[15];
      return { data: frame.subarray(16), next: proto };
    }
    case LINKTYPE_LINUX_SLL2: {
      if (frame.length < 20) return null;
      const proto = (frame[0] << 8) | frame[1];
      return { data: frame.subarray(20), next: proto };
    }
    case LINKTYPE_NULL: {
      if (frame.length < 4) return null;
      const af = u32At(frame, 0, true);
      return {
        data: frame.subarray(4),
        next: af === 2 ? 0x0800 : 0x86dd,
      };
    }
    default:
      // Unknown link type — try Ethernet as best effort
      return stripLinkLayer(frame, LINKTYPE_ETHERNET);
  }
}

export function ipv6ToString(d: Uint8Array, off: number): string {
  const groups: string[] = [];
  for (let i = 0; i < 8; i++) {
    groups.push(((d[off + i * 2] << 8) | d[off + i * 2 + 1]).toString(16));
  }
  // compress longest zero run
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === "0") {
      if (curStart < 0) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return groups.join(":");
  const head = groups.slice(0, bestStart).join(":");
  const tail = groups.slice(bestStart + bestLen).join(":");
  return `${head}::${tail}`;
}
