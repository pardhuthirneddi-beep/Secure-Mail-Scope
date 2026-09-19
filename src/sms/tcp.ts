/**
 * TCP session (flow) reconstruction from decoded packets.
 * Bidirectional flows, seq-normalized stream reassembly, connection status.
 */

import { TCP_FLAGS, type DecodedPacket, type PcapParseResult } from "./pcap";

export interface TcpSegment {
  seq: number;
  offset: number; // normalized byte offset within the direction stream
  payload: Uint8Array;
  ts: number;
  packetIndex: number;
}

export interface ReconstructedFlow {
  key: string;
  aIp: string;
  aPort: number;
  bIp: string;
  bPort: number;
  startTs: number;
  endTs: number;
  firstPacketIndex: number;
  lastPacketIndex: number;
  packetCount: number;
  byteCount: number;
  clientToServer: TcpSegment[]; // initiator -> responder (merged stream)
  serverToClient: TcpSegment[]; // responder -> initiator (merged stream)
  sawSyn: boolean;
  sawFin: boolean;
  sawRst: boolean;
  sawData: boolean;
  status: "completed" | "reset" | "truncated";
  initiatorIp: string;
  initiatorPort: number;
  responderIp: string;
  responderPort: number;
}

export function reconstructSessions(
  parsed: PcapParseResult,
  packets: DecodedPacket[],
): ReconstructedFlow[] {
  void parsed;
  const map = new Map<string, ReconstructedFlow>();

  for (const p of packets) {
    if (p.ipProto !== 6) continue;
    const ckey = canonicalKey(p.srcIp, p.srcPort, p.dstIp, p.dstPort);
    let flow = map.get(ckey);
    if (!flow) {
      flow = {
        key: ckey,
        aIp: p.srcIp,
        aPort: p.srcPort,
        bIp: p.dstIp,
        bPort: p.dstPort,
        startTs: p.ts,
        endTs: p.ts,
        firstPacketIndex: p.index,
        lastPacketIndex: p.index,
        packetCount: 0,
        byteCount: 0,
        clientToServer: [],
        serverToClient: [],
        sawSyn: false,
        sawFin: false,
        sawRst: false,
        sawData: false,
        status: "truncated",
        initiatorIp: "",
        initiatorPort: 0,
        responderIp: "",
        responderPort: 0,
      };
      map.set(ckey, flow);
    }

    flow.packetCount++;
    if (p.payload) flow.byteCount += p.payload.length;
    flow.endTs = p.ts;
    flow.lastPacketIndex = p.index;
    if (p.tcpFlags & TCP_FLAGS.SYN) flow.sawSyn = true;
    if (p.tcpFlags & TCP_FLAGS.FIN) flow.sawFin = true;
    if (p.tcpFlags & TCP_FLAGS.RST) flow.sawRst = true;

    // First side to transmit payload data is treated as the client/initiator.
    if (flow.initiatorIp === "" && p.payload && p.payload.length > 0) {
      flow.initiatorIp = p.srcIp;
      flow.initiatorPort = p.srcPort;
      flow.responderIp = p.dstIp;
      flow.responderPort = p.dstPort;
    }

    if (p.payload && p.payload.length > 0) {
      const isClient =
        p.srcIp === flow.initiatorIp && p.srcPort === flow.initiatorPort;
      const seg: TcpSegment = {
        seq: p.tcpSeq,
        offset: -1,
        payload: p.payload,
        ts: p.ts,
        packetIndex: p.index,
      };
      if (isClient) flow.clientToServer.push(seg);
      else flow.serverToClient.push(seg);
      flow.sawData = true;
    }
  }

  for (const flow of map.values()) {
    // No payload anywhere: use first packet seen as initiator (best evidence).
    if (flow.initiatorIp === "") {
      flow.initiatorIp = flow.aIp;
      flow.initiatorPort = flow.aPort;
      flow.responderIp = flow.bIp;
      flow.responderPort = flow.bPort;
    }
    flow.clientToServer = normalizeSegments(flow.clientToServer);
    flow.serverToClient = normalizeSegments(flow.serverToClient);
    flow.status = flow.sawRst ? "reset" : flow.sawFin ? "completed" : "truncated";
  }

  return [...map.values()].sort(
    (a, b) => a.firstPacketIndex - b.firstPacketIndex,
  );
}

/**
 * Normalize raw segments into a single contiguous stream segment using
 * TCP sequence numbers. Overlaps are resolved first-write-wins.
 */
function normalizeSegments(segs: TcpSegment[]): TcpSegment[] {
  if (segs.length === 0) return [];
  let base = segs[0].seq;
  for (const s of segs) {
    const delta = s.seq - base;
    if (delta < -0x80000000 || delta > 0x7fffffff) {
      base = s.seq; // sequence wrapped or unordered capture; reset base
    }
  }
  let minSeq = Infinity;
  for (const s of segs) {
    let rel = s.seq - base;
    rel = ((rel % 4294967296) + 4294967296) % 4294967296;
    if (rel < minSeq) minSeq = rel;
  }
  for (const s of segs) {
    let rel = s.seq - base;
    rel = ((rel % 4294967296) + 4294967296) % 4294967296;
    s.offset = rel - minSeq;
  }
  segs.sort((a, b) => a.offset - b.offset);

  let total = 0;
  for (const s of segs) {
    const end = s.offset + s.payload.length;
    if (end > total) total = end;
  }
  const stream = new Uint8Array(total);
  for (const s of segs) {
    stream.set(s.payload, s.offset);
  }
  const merged: TcpSegment = {
    seq: base + minSeq,
    offset: 0,
    payload: stream,
    ts: segs[0].ts,
    packetIndex: segs[0].packetIndex,
  };
  return [merged];
}

export function canonicalKey(
  a: string,
  ap: number,
  b: string,
  bp: number,
): string {
  const fwd = `${a}:${ap}>${b}:${bp}`;
  const rev = `${b}:${bp}>${a}:${ap}`;
  return fwd < rev ? fwd : rev;
}
