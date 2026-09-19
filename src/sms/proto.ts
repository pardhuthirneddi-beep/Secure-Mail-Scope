/**
 * Email protocol classification (SMTP / IMAP / POP3) from observed bytes,
 * and STARTTLS lifecycle tracking per session.
 * Ports are used as corroborating hints only — banners decide.
 */

import type { TcpSegment } from "./tcp";

export type EmailProtocol = "SMTP" | "IMAP" | "POP3" | "OTHER";

export interface ProtoGuess {
  protocol: EmailProtocol;
  confidence: number; // 0..1
  reasons: string[];
  clientBanner: string | null;
  serverBanner: string | null;
}

const SMTP_GREETING = /^220[ -]/;
const IMAP_GREETING = /^\* (OK|PREAUTH|BYE)\b/i;
const POP3_GREETING = /^\+OK\b/;

const SMTP_CMD =
  /^(EHLO|HELO|MAIL FROM:|RCPT TO:|DATA|QUIT|RSET|NOOP|VRFY|AUTH |STARTTLS)\b/i;
const IMAP_CMD =
  /^[A-Za-z0-9+._-]{1,64} (CAPABILITY|STARTTLS|LOGIN|AUTHENTICATE|ID |NAMESPACE|LIST|SELECT|FETCH|LOGOUT|ENABLE)\b/i;
const POP3_CMD =
  /^(USER |PASS |APOP |STAT|LIST|RETR |DELE |NOOP|RSET|QUIT|TOP |UIDL|CAPA|STLS)\b/i;

export function classifyProtocol(flow: {
  clientToServer: TcpSegment[];
  serverToClient: TcpSegment[];
  serverPort: number;
}): ProtoGuess {
  const serverBytes = concatSegments(flow.serverToClient, 2048);
  const clientBytes = concatSegments(flow.clientToServer, 2048);
  const c = toAscii(clientBytes);
  const s = toAscii(serverBytes);
  const reasons: string[] = [];
  let confidence = 0;
  let protocol: EmailProtocol = "OTHER";

  const smtpGreeting = SMTP_GREETING.test(s);
  const imapGreeting = IMAP_GREETING.test(s);
  const pop3Greeting = POP3_GREETING.test(s);
  const smtpCmd = SMTP_CMD.test(c);
  const imapCmd = IMAP_CMD.test(c);
  const pop3Cmd = POP3_CMD.test(c);
  const noClient = clientBytes.length === 0;

  if (smtpGreeting && (smtpCmd || noClient)) {
    protocol = "SMTP";
    confidence = 0.95;
    reasons.push("Server greeting matched SMTP 220 pattern");
    if (smtpCmd) reasons.push("Client commands matched SMTP verb set");
  } else if (imapGreeting && (imapCmd || noClient)) {
    protocol = "IMAP";
    confidence = 0.95;
    reasons.push("Server greeting matched IMAP '* OK' pattern");
    if (imapCmd) reasons.push("Client sent IMAP-tagged commands");
  } else if (pop3Greeting && (pop3Cmd || noClient)) {
    protocol = "POP3";
    confidence = 0.95;
    reasons.push("Server greeting matched POP3 '+OK' pattern");
    if (pop3Cmd) reasons.push("Client sent POP3 commands");
  } else if (smtpCmd || imapCmd || pop3Cmd) {
    protocol = pop3Cmd ? "POP3" : smtpCmd ? "SMTP" : "IMAP";
    confidence = 0.5;
    reasons.push("Client command patterns matched");
  } else {
    const portProto = portGuess(flow.serverPort);
    if (portProto) {
      protocol = portProto;
      confidence = 0.3;
      reasons.push(
        `No banner signature matched; assigned from well-known port ${flow.serverPort} (low confidence)`,
      );
    }
  }
  return {
    protocol,
    confidence,
    reasons,
    clientBanner: c ? c.split("\n")[0].slice(0, 120) : null,
    serverBanner: s ? s.split("\n")[0].slice(0, 120) : null,
  };
}

function portGuess(port: number): EmailProtocol | null {
  if (port === 25 || port === 587 || port === 465 || port === 2525) return "SMTP";
  if (port === 143 || port === 993) return "IMAP";
  if (port === 110 || port === 995) return "POP3";
  return null;
}

export function concatSegments(
  segs: Array<{ payload: Uint8Array }>,
  max: number,
): Uint8Array {
  let len = 0;
  for (const s of segs) {
    len += s.payload.length;
    if (len >= max) break;
  }
  const out = new Uint8Array(Math.min(len, max));
  let off = 0;
  for (const s of segs) {
    const take = Math.min(s.payload.length, max - off);
    out.set(s.payload.subarray(0, take), off);
    off += take;
    if (off >= max) break;
  }
  return out;
}

export function toAscii(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i < b.length; i++) {
    const ch = b[i];
    if (ch === 0x0d) continue;
    if (ch === 0x0a) out += "\n";
    else if (ch >= 32 && ch < 127) out += String.fromCharCode(ch);
    else out += ".";
  }
  return out;
}

// ---------------------------------------------------------------------------
// STARTTLS lifecycle per flow
// ---------------------------------------------------------------------------

export interface StarttlsEvent {
  phase: "advertised" | "requested" | "accepted" | "rejected" | "failed";
  detail: string;
}

export interface StarttlsTrace {
  advertised: boolean;
  requested: boolean;
  accepted: boolean;
  tlsEstablished: boolean;
  transition:
    | "normal"
    | "unused"
    | "fallback-to-plaintext"
    | "starttls-failed"
    | "unavailable";
  events: StarttlsEvent[];
  state: "verified" | "unavailable";
  note: string;
}

/** Locate the server response that immediately follows a client command. */
function serverResponseAfterLastCommand(
  cText: string,
  sText: string,
  commandPattern: RegExp,
): string {
  const matches = [...cText.matchAll(commandPattern)];
  if (matches.length === 0) return "";
  const last = matches[matches.length - 1];
  const cmdEnd = last.index + last[0].length;
  // The client bytes after the command include everything until TLS took over;
  // server responses are interleaved in the server stream. Approximate the
  // server reply position by counting commands before this one.
  const cmdsBefore = matches.length - 1;
  const sLines = sText.split("\n");
  // Walk server lines skipping the greeting and one response per prior command.
  let i = 0;
  let skipped = 0;
  while (i < sLines.length && skipped < cmdsBefore + 1) {
    if (sLines[i].length > 0) skipped++;
    i++;
  }
  void cmdEnd;
  return sLines.slice(i - 1, i + 2).join("\n");
}

export function detectStarttls(flow: {
  protocol: EmailProtocol;
  clientToServer: TcpSegment[];
  serverToClient: TcpSegment[];
  preTlsBoundary: number | null; // client stream offset where TLS record layer starts
  tlsEstablished: boolean;
}): StarttlsTrace {
  const cBytes = concatSegments(flow.clientToServer, 65536);
  const sBytes = concatSegments(flow.serverToClient, 65536);
  const cText = toAscii(cBytes);
  const sText = toAscii(sBytes);
  const events: StarttlsEvent[] = [];
  let advertised = false;
  let requested = false;
  let accepted = false;
  let rejected = false;
  let tail = "";

  if (flow.protocol === "SMTP") {
    if (/^250[ -][^\n]*STARTTLS/im.test(sText) || /250[^\n]*STARTTLS/i.test(sText)) {
      advertised = true;
      events.push({
        phase: "advertised",
        detail: "Server EHLO response advertised STARTTLS",
      });
    }
    if (/STARTTLS\r?\n/i.test(cText)) {
      requested = true;
      events.push({ phase: "requested", detail: "Client issued STARTTLS" });
      tail = serverResponseAfterLastCommand(cText, sText, /STARTTLS\r?\n/gi);
      if (/^220[ -]/m.test(tail)) {
        accepted = true;
        events.push({
          phase: "accepted",
          detail: "Server accepted STARTTLS (220)",
        });
      } else if (/^[45]\d\d[ -]/m.test(tail)) {
        rejected = true;
        events.push({ phase: "rejected", detail: "Server declined STARTTLS" });
      }
    }
  } else if (flow.protocol === "IMAP") {
    if (/CAPABILITY[^\n]*STARTTLS/i.test(sText)) {
      advertised = true;
      events.push({
        phase: "advertised",
        detail: "Server CAPABILITY response advertised STARTTLS",
      });
    }
    const m = /^([A-Za-z0-9+._-]+) STARTTLS\r?\n/im.exec(cText);
    if (m) {
      requested = true;
      events.push({ phase: "requested", detail: `Client sent ${m[1]} STARTTLS` });
      const respRe = new RegExp(`^${m[1]} (OK|NO|BAD)`, "im");
      const rm = respRe.exec(sText);
      if (rm) {
        if (rm[1] === "OK") {
          accepted = true;
          events.push({ phase: "accepted", detail: "Server accepted (tagged OK)" });
        } else {
          rejected = true;
          events.push({ phase: "rejected", detail: `Server replied ${rm[1]}` });
        }
      }
    }
  } else if (flow.protocol === "POP3") {
    const capa = /^CAPA\r?\n([\s\S]{0,512}?)\.\r?\n/.exec(cText);
    if (capa && /STLS/i.test(capa[1])) {
      advertised = true;
      events.push({
        phase: "advertised",
        detail: "Server CAPA response advertised STLS",
      });
    }
    if (/STLS\r?\n/i.test(cText)) {
      requested = true;
      events.push({ phase: "requested", detail: "Client issued STLS" });
      const after = serverResponseAfterLastCommand(cText, sText, /STLS\r?\n/gi);
      if (/^\+OK/.test(after)) {
        accepted = true;
        events.push({ phase: "accepted", detail: "Server accepted (+OK)" });
      } else if (/^-ERR/.test(after)) {
        rejected = true;
        events.push({ phase: "rejected", detail: "Server declined (-ERR)" });
      }
    }
  }

  if (flow.tlsEstablished) {
    return {
      advertised,
      requested,
      accepted,
      tlsEstablished: true,
      transition: "normal",
      events,
      state: "verified",
      note: "Plaintext upgrade command observed; TLS record layer followed.",
    };
  }
  if (requested && !accepted) {
    return {
      advertised,
      requested,
      accepted,
      tlsEstablished: false,
      transition: "starttls-failed",
      events,
      state: "verified",
      note: "STARTTLS/STLS was requested but the server did not accept it and no TLS followed.",
    };
  }
  if (flow.preTlsBoundary === null) {
    return {
      advertised,
      requested,
      accepted,
      tlsEstablished: false,
      transition: requested ? "starttls-failed" : "unused",
      events,
      state: "verified",
      note: requested
        ? "Upgrade command observed but no TLS followed."
        : "No TLS upgrade attempted; session remained plaintext.",
    };
  }
  return {
    advertised,
    requested,
    accepted,
    tlsEstablished: false,
    transition: "fallback-to-plaintext",
    events,
    state: "verified",
    note: "TLS upgrade path was available but the session stayed plaintext.",
  };
}
