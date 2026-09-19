import { useMemo, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import {
  Disclosure,
  EvidenceChip,
  FlushPanel,
  KeyValue,
  Panel,
  RiskDot,
  SeverityBadge,
  StatStrip,
} from "@/components/sms-ui";
import { Button } from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { parseCapturePayload } from "@/lib/sms-format";
import {
  buildJsonExport,
  buildMarkdownReport,
  downloadText,
  evidenceForSession,
  findingsForSession,
  safeFileStem,
  sessionTitle,
} from "@/lib/sms-format";
import { cn } from "@/lib/utils";
import type { Evidence, Finding, Session } from "@/sms/types";
import type { RiskLevel } from "@/sms/theme";
import { FileDown, FileJson, Loader2, Trash2 } from "lucide-react";
import { Link, useNavigate, useParams } from "react-router";
import { toast } from "sonner";

const RISK_ORDER: RiskLevel[] = ["critical", "high", "medium", "low", "healthy"];

interface RiskSummary {
  level: RiskLevel;
  score: number;
  rationale: string;
}

function formatTime(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toISOString().slice(11, 19) + "Z";
}

/* ------------------------------------------------------------------ badges */

const SEV_BG = {
  critical: "bg-(--sms-critical)",
  high: "bg-(--sms-high)",
  medium: "bg-(--sms-medium)",
  low: "bg-(--sms-low)",
  info: "bg-muted",
} as const;

function FindingCard({ f }: { f: Finding }) {
  return (
    <div className="border-border/70 group hover:border-border rounded-sm border transition-colors">
      <div className="flex items-start gap-3 px-3 py-2.5">
        <span className={cn("mt-1 h-3.5 w-0.5 shrink-0 rounded-full", SEV_BG[f.severity])} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className="sms-mono text-[11px] font-semibold">{f.ruleId}</span>
            <span className="text-xs font-medium">{f.title}</span>
            <SeverityBadge severity={f.severity} className="ml-auto" />
          </div>
          <p className="text-muted-foreground mt-1.5 text-xs leading-relaxed">
            <span className="text-foreground/80 font-medium">Evidence </span>
            {f.evidenceSummary}
          </p>
          <p className="text-muted-foreground mt-1 text-xs leading-relaxed">{f.whyItMatters}</p>
          <p className="text-primary mt-1.5 text-xs">
            <span className="sms-label text-primary/70 mr-1.5">Action</span>
            {f.recommendedAction}
          </p>
        </div>
      </div>
    </div>
  );
}

function EvidenceItem({ ev }: { ev: Evidence }) {
  return (
    <Disclosure
      id={ev.id}
      title={ev.label}
      meta={undefined}
      chip={<EvidenceChip state={ev.state} />}
    >
      <p className="text-muted-foreground text-xs leading-relaxed">{ev.summary}</p>
      {ev.raw && (
        <pre className="sms-mono bg-background text-muted-foreground mt-2 overflow-x-auto rounded-sm border border-border/50 p-2 text-[10px] leading-relaxed">
          {ev.raw}
        </pre>
      )}
    </Disclosure>
  );
}

/* ------------------------------------------------------------ session view */

function SessionView({
  session,
  findings,
  evidence,
  risk,
}: {
  session: Session;
  findings: Finding[];
  evidence: Evidence[];
  risk: RiskSummary | null;
}) {
  const tls = session.tls;
  return (
    <div className="space-y-4">
      <div className="grid gap-3 lg:grid-cols-3">
        {/* Risk panel */}
        <div className="border-border/80 bg-card/40 rounded-sm border p-3.5">
          <div className="flex items-center justify-between">
            <span className="sms-label text-muted-foreground">Assessed risk</span>
            {risk && (
              <span className="sms-mono text-muted-foreground text-[11px] tabular-nums">
                {risk.score}/100
              </span>
            )}
          </div>
          <div className="mt-2.5 flex items-center gap-2">
            {risk && <RiskDot level={risk.level} className="size-2" />}
            <span
              className={cn(
                "sms-mono text-lg leading-none font-semibold tracking-tight",
                risk &&
                  ({
                    healthy: "text-(--sms-healthy)",
                    low: "text-(--sms-low)",
                    medium: "text-(--sms-medium)",
                    high: "text-(--sms-high)",
                    critical: "text-(--sms-critical)",
                  }[risk.level]),
              )}
            >
              {risk ? risk.level.toUpperCase() : "UNKNOWN"}
            </span>
          </div>
          {risk && (
            <>
              <div className="bg-muted mt-3 h-1 w-full overflow-hidden rounded-[1px]">
                <div
                  className={cn(
                    "h-full transition-[width] duration-500",
                    ({
                      healthy: "bg-(--sms-healthy)",
                      low: "bg-(--sms-low)",
                      medium: "bg-(--sms-medium)",
                      high: "bg-(--sms-high)",
                      critical: "bg-(--sms-critical)",
                    }[risk.level]),
                  )}
                  style={{ width: risk.score + "%" }}
                />
                {/* score fills left-to-right; color encodes band */}
              </div>
              <p className="text-muted-foreground mt-2.5 text-[11px] leading-relaxed">
                {risk.rationale}
              </p>
            </>
          )}
        </div>

        {/* Transport panel */}
        <div className="border-border/80 bg-card/40 rounded-sm border p-3.5">
          <span className="sms-label text-muted-foreground">Transport</span>
          {tls ? (
            <div className="mt-2">
              <div className="sms-mono truncate text-sm font-semibold">
                {tls.version} · {tls.cipherName ?? tls.cipherHex}
              </div>
              <KeyValue
                className="mt-2"
                rows={[
                  { k: "KX", v: tls.keyExchange ?? "—" },
                  {
                    k: "FS",
                    v: tls.forwardSecrecy === null ? "unknown" : tls.forwardSecrecy ? "yes" : "no",
                  },
                  { k: "Records", v: String(tls.handshakeBytes) },
                  {
                    k: "Alert",
                    v: tls.hasAlert ? String(tls.alertDescription) : "none",
                  },
                ]}
              />
              {tls.extractionState === "partial" && (
                <p className="text-muted-foreground mt-1.5 text-[11px] leading-relaxed italic">
                  {tls.extractionNote}
                </p>
              )}
            </div>
          ) : (
            <div className="mt-2.5">
              <div className="text-(--sms-critical) sms-mono text-sm font-semibold">
                No TLS layer
              </div>
              <p className="text-muted-foreground mt-1.5 text-[11px] leading-relaxed">
                No TLS record boundary in either stream direction.
              </p>
            </div>
          )}
        </div>

        {/* Certificate panel */}
        <div className="border-border/80 bg-card/40 rounded-sm border p-3.5">
          <span className="sms-label text-muted-foreground">Certificate</span>
          {tls?.certificate ? (
            <div className="mt-2">
              <div className="sms-mono truncate text-sm font-semibold" title={tls.certificate.subject}>
                {tls.certificate.subject}
              </div>
              <KeyValue
                className="mt-2"
                rows={[
                  { k: "Issuer", v: tls.certificate.issuer },
                  {
                    k: "Valid to",
                    v: new Date(tls.certificate.notAfter * 1000).toISOString().slice(0, 10),
                  },
                  {
                    k: "Key",
                    v: tls.certificate.keyBits
                      ? tls.certificate.keyBits + "-bit " + tls.certificate.pkAlgName
                      : tls.certificate.pkAlgName,
                  },
                  { k: "Signature", v: tls.certificate.sigAlgName },
                ]}
              />
            </div>
          ) : (
            <div className="mt-2.5 text-muted-foreground sms-mono text-sm">—</div>
          )}
        </div>
      </div>

      {/* Timeline + findings + evidence */}
      <div className="grid gap-4 lg:grid-cols-5">
        <div className="lg:col-span-2">
          <span className="sms-label text-muted-foreground mb-2 block">Session timeline</span>
          <ol>
            {session.timeline.map((ev, i) => {
              const adverse =
                ev.kind.includes("failed") || ev.kind === "plaintext-after-failed-starttls";
              return (
                <li key={i} className="border-border/60 relative border-l pb-3.5 pl-4 last:pb-0">
                  <span
                    className={cn(
                      "absolute top-[3px] left-[-4px] size-1.5 rounded-[1px]",
                      adverse ? "bg-(--sms-critical)" : "bg-primary/70",
                    )}
                  />
                  <div className="text-xs leading-snug font-medium">{ev.label}</div>
                  <div className="sms-mono text-muted-foreground/70 mt-0.5 text-[10px]">
                    {formatTime(ev.ts)}
                  </div>
                </li>
              );
            })}
          </ol>
        </div>

        <div className="space-y-4 lg:col-span-3">
          <div>
            <div className="sms-label text-muted-foreground mb-2 flex items-center gap-2">
              Findings
              <span className="sms-mono text-muted-foreground/50 normal-case">
                {findings.length === 0 ? "none raised" : String(findings.length)}
              </span>
            </div>
            {findings.length === 0 ? (
              <div className="border-border/70 text-muted-foreground rounded-sm border border-dashed px-3 py-4 text-center text-xs">
                The observed configuration produced no rule matches.
              </div>
            ) : (
              <div className="space-y-2">
                {findings.map((f) => (
                  <FindingCard key={f.id} f={f} />
                ))}
              </div>
            )}
          </div>

          <div>
            <div className="sms-label text-muted-foreground mb-2 flex items-center gap-2">
              Evidence
              <span className="sms-mono text-muted-foreground/50 normal-case">
                {evidence.length} item{evidence.length === 1 ? "" : "s"}
              </span>
            </div>
            {evidence.length === 0 ? (
              <p className="text-muted-foreground text-xs">No evidence items recorded.</p>
            ) : (
              <div className="space-y-1.5">
                {evidence.map((ev) => (
                  <EvidenceItem key={ev.id} ev={ev} />
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------- page */

export default function CaptureDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const capture = useQuery(api.captures.getCapture, id ? { id: id as never } : "skip");
  const removeCapture = useMutation(api.captures.deleteCapture);

  const payload = useMemo(
    () => (capture ? parseCapturePayload(capture.reportJson, capture.sessionsJson) : null),
    [capture],
  );

  const [selectedSession, setSelectedSession] = useState<string | null>(null);

  const sessionsSorted = useMemo(() => {
    if (!payload) return [];
    return [...payload.sessions].sort((a, b) => {
      const ra = payload.report.riskBySession[a.id]?.level ?? "healthy";
      const rb = payload.report.riskBySession[b.id]?.level ?? "healthy";
      return RISK_ORDER.indexOf(ra) - RISK_ORDER.indexOf(rb);
    });
  }, [payload]);

  if (capture === undefined) {
    return (
      <AppShell title="Capture" subtitle="Loading capture record…">
        <Loader2 className="text-muted-foreground mt-16 size-6 animate-spin" />
      </AppShell>
    );
  }
  if (!capture || !payload) {
    return (
      <AppShell title="Capture" subtitle="Not found">
        <p className="text-muted-foreground text-sm">
          This capture does not exist or has been removed.{" "}
          <Link to="/captures" className="text-primary underline">
            Back to captures
          </Link>
        </p>
      </AppShell>
    );
  }

  const { report } = payload;
  const current = sessionsSorted.find((s) => s.id === selectedSession) ?? sessionsSorted[0] ?? null;
  const currentRisk: RiskSummary | null = current
    ? (() => {
        const r = report.riskBySession[current.id];
        return r ? { level: r.level, score: r.score, rationale: r.rationale } : null;
      })()
    : null;

  const exportMarkdown = () => {
    downloadText(
      safeFileStem(capture.name) + "-posture-report.md",
      buildMarkdownReport(report, capture.name, {
        sizeBytes: capture.sizeBytes,
        packetCount: capture.packetCount,
        durationSec: capture.durationSec,
        isDemo: capture.isDemo,
      }),
      "text/markdown",
    );
    toast.success("Markdown report downloaded");
  };
  const exportJson = () => {
    downloadText(
      safeFileStem(capture.name) + "-evidence.json",
      buildJsonExport(report, payload.sessions, payload.evidence),
      "application/json",
    );
    toast.success("JSON evidence bundle downloaded");
  };

  const handleDelete = async () => {
    await removeCapture({ id: capture._id });
    toast.success("Capture deleted");
    navigate("/captures");
  };

  return (
    <AppShell
      title={capture.name}
      subtitle={
        (capture.isDemo ? "Generated demonstration capture · " : "") +
        report.sessionCount +
        " sessions · " +
        report.findings.length +
        " findings"
      }
      actions={
        <>
          <Button size="sm" variant="outline" className="gap-2" onClick={exportMarkdown}>
            <FileDown className="size-3.5" />
            Report
          </Button>
          <Button size="sm" variant="outline" className="gap-2" onClick={exportJson}>
            <FileJson className="size-3.5" />
            JSON
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button size="sm" variant="ghost" className="text-destructive" aria-label="Delete capture">
                <Trash2 className="size-3.5" />
              </Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>Delete this capture?</AlertDialogTitle>
                <AlertDialogDescription>
                  The analysis record and its stored evidence will be permanently removed.
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>Cancel</AlertDialogCancel>
                <AlertDialogAction onClick={handleDelete}>Delete</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </>
      }
    >
      <StatStrip
        items={[
          { label: "Sessions", value: String(report.sessionCount), tone: "info" },
          {
            label: "Findings",
            value: String(report.findings.length),
            tone: report.findings.length > 0 ? "warning" : "good",
          },
          {
            label: "High",
            value: String(report.highRiskCount),
            tone: report.highRiskCount > 0 ? "danger" : "good",
          },
          {
            label: "Critical",
            value: String(report.criticalCount),
            tone: report.criticalCount > 0 ? "danger" : "good",
          },
        ]}
      />

      <div className="mt-4 grid gap-4 lg:grid-cols-5">
        {/* Session rail */}
        <FlushPanel
          label="Sessions"
          meta="sorted by risk"
          className="lg:col-span-2"
          bodyClassName="max-h-[620px] overflow-y-auto"
        >
          <ul className="divide-border/70 divide-y">
            {sessionsSorted.map((s) => {
              const risk = payload.report.riskBySession[s.id];
              const active = current?.id === s.id;
              return (
                <li key={s.id}>
                  <button
                    onClick={() => setSelectedSession(s.id)}
                    className={cn(
                      "relative w-full px-3.5 py-2.5 text-left transition-colors",
                      active ? "bg-primary/10" : "hover:bg-accent/50",
                    )}
                  >
                    <span
                      className={cn(
                        "absolute top-1 bottom-1 left-0 w-0.5 rounded-full transition-opacity",
                        active ? "bg-primary opacity-100" : "opacity-0",
                      )}
                    />
                    <div className="flex items-center justify-between gap-2">
                      <span className="sms-mono flex items-center gap-1.5 text-xs font-semibold">
                        <RiskDot level={risk?.level ?? "healthy"} />
                        {s.id}
                      </span>
                      <span className="sms-mono text-muted-foreground text-[10px] tracking-tight">
                        {s.tls ? s.tls.version : "PLAINTEXT"}
                      </span>
                    </div>
                    <div className="text-muted-foreground sms-mono mt-0.5 truncate text-[11px]">
                      {s.protocol} · {s.srcIp}:{s.srcPort} → {s.dstIp}:{s.dstPort}
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        </FlushPanel>

        {/* Session detail */}
        <div className="lg:col-span-3">
          {current ? (
            <Panel
              label={current.id}
              meta={sessionTitle(current).split(" · ").slice(1).join(" · ")}
              actions={
                <span className="sms-mono text-muted-foreground text-[10px]">
                  {current.packetCount} pkts · {(current.byteCount / 1024).toFixed(1)} KB ·{" "}
                  {current.connectionStatus}
                </span>
              }
            >
              <SessionView
                session={current}
                findings={findingsForSession(report.findings, current.id)}
                evidence={evidenceForSession(payload.evidence, current.id)}
                risk={currentRisk}
              />
            </Panel>
          ) : (
            <Panel label="Session" meta="none">
              <p className="text-muted-foreground py-10 text-center text-sm">
                No email sessions were reconstructed from this capture.
              </p>
            </Panel>
          )}
        </div>
      </div>

      {/* Remediation */}
      <div className="mt-4">
        <Panel
          label="Prioritized remediation"
          meta={
            report.recommendations.length === 0
              ? "nothing required"
              : String(report.recommendations.length) + " items"
          }
        >
          {report.recommendations.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              No remediation required — no findings were raised for this capture.
            </p>
          ) : (
            <ol className="space-y-2">
              {report.recommendations.map((rec) => (
                <li
                  key={rec.id}
                  className="border-border/70 hover:border-border flex items-start gap-3 rounded-sm border px-3 py-2.5 transition-colors"
                >
                  <span className="sms-mono text-muted-foreground/70 mt-0.5 w-6 shrink-0 text-[11px]">
                    #{String(rec.rank).padStart(2, "0")}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="text-xs font-semibold">{rec.title}</span>
                      <SeverityBadge severity={rec.severity} />
                      <span className="sms-mono text-muted-foreground ml-auto text-[10px]">
                        {rec.affectedSessions.length} session
                        {rec.affectedSessions.length === 1 ? "" : "s"} · {rec.affectedSessions.join(" ")}
                      </span>
                    </div>
                    <p className="text-muted-foreground mt-1 text-xs leading-relaxed">{rec.why}</p>
                    <p className="text-primary mt-1 text-xs">
                      <span className="sms-label text-primary/70 mr-1.5">Action</span>
                      {rec.action}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </Panel>
      </div>
    </AppShell>
  );
}
