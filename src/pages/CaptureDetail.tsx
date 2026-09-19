import { useMemo, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import {
  EvidenceStateChip,
  RiskBadge,
  SeverityBadge,
  StatTile,
} from "@/components/sms-ui";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
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
import type { Finding, Session } from "@/sms/types";
import type { RiskLevel } from "@/sms/theme";
import {
  ChevronRight,
  Download,
  FileDown,
  FileJson,
  Loader2,
  ShieldAlert,
  Trash2,
} from "lucide-react";
import { Link, useNavigate, useParams } from "react-router";
import { toast } from "sonner";

const RISK_ORDER: RiskLevel[] = ["critical", "high", "medium", "low", "healthy"];

interface RiskSummary {
  level: RiskLevel;
  score: number;
  rationale: string;
}

function SessionDetail({
  session,
  findings,
  evidence,
  risk,
}: {
  session: Session;
  findings: Finding[];
  evidence: ReturnType<typeof evidenceForSession>;
  risk: RiskSummary | null;
}) {
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="border-border/70 bg-card/60 rounded-md border px-4 py-3">
          <div className="text-muted-foreground text-[11px] uppercase tracking-wider">
            Assessed risk
          </div>
          <div className="mt-1.5 flex items-center gap-2">
            <RiskBadge level={risk?.level ?? "healthy"} />
            {risk && (
              <span className="sms-mono text-muted-foreground text-xs">
                {risk.score}/100
              </span>
            )}
          </div>
          {risk && (
            <p className="text-muted-foreground mt-2 text-xs leading-relaxed">
              {risk.rationale}
            </p>
          )}
        </div>
        <div className="border-border/70 bg-card/60 rounded-md border px-4 py-3">
          <div className="text-muted-foreground text-[11px] uppercase tracking-wider">
            Transport security
          </div>
          {session.tls ? (
            <>
              <div className="sms-mono mt-1.5 text-sm font-semibold">
                {session.tls.version} · {session.tls.cipherName ?? session.tls.cipherHex}
              </div>
              <div className="text-muted-foreground mt-1 text-xs">
                Key exchange: {session.tls.keyExchange ?? "—"} · Forward secrecy:{" "}
                {session.tls.forwardSecrecy === null
                  ? "unknown"
                  : session.tls.forwardSecrecy
                    ? "yes"
                    : "no"}
              </div>
              {session.tls.extractionState === "partial" && (
                <p className="text-muted-foreground mt-1 text-xs italic">
                  {session.tls.extractionNote}
                </p>
              )}
            </>
          ) : (
            <div className="text-[--sms-critical] mt-1.5 text-sm font-medium">
              No TLS record layer observed
            </div>
          )}
        </div>
        <div className="border-border/70 bg-card/60 rounded-md border px-4 py-3">
          <div className="text-muted-foreground text-[11px] uppercase tracking-wider">
            Certificate
          </div>
          {session.tls?.certificate ? (
            <>
              <div className="sms-mono mt-1.5 truncate text-sm font-semibold">
                {session.tls.certificate.subject}
              </div>
              <div className="text-muted-foreground mt-1 text-xs">
                Issued by {session.tls.certificate.issuer} · valid until{" "}
                {new Date(session.tls.certificate.notAfter * 1000)
                  .toISOString()
                  .slice(0, 10)}
              </div>
              <div className="text-muted-foreground mt-1 text-xs">
                {session.tls.certificate.keyBits
                  ? session.tls.certificate.keyBits + "-bit " + session.tls.certificate.pkAlgName
                  : session.tls.certificate.pkAlgName}{" "}
                · {session.tls.certificate.sigAlgName}
              </div>
            </>
          ) : (
            <div className="text-muted-foreground mt-1.5 text-sm">
              {session.tls ? "Not presented in capture" : "—"}
            </div>
          )}
        </div>
      </div>

      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider">
          Session timeline
        </h4>
        <ol className="border-border/70 space-y-0">
          {session.timeline.map((ev, i) => (
            <li key={i} className="border-border/40 relative border-l pb-3 pl-4 last:pb-0">
              <span
                className={cn(
                  "absolute top-1 left-[-4.5px] size-2 rounded-full border",
                  ev.kind.includes("failed") || ev.kind === "plaintext-after-failed-starttls"
                    ? "border-[--sms-critical] bg-[--sms-critical]/40"
                    : "border-primary/60 bg-primary/20",
                )}
              />
              <div className="text-xs font-medium">{ev.label}</div>
              <div className="text-muted-foreground sms-mono text-[11px]">{formatTime(ev.ts)}</div>
            </li>
          ))}
        </ol>
      </div>

      {findings.length > 0 && (
        <div>
          <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider">
            Findings on this session
          </h4>
          <div className="space-y-2">
            {findings.map((f) => (
              <div key={f.id} className="border-border/70 rounded-sm border px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <span className="sms-mono text-xs font-medium">{f.ruleId}</span>
                  <span className="text-sm font-medium">{f.title}</span>
                  {f.detectedBy === "ml" && <Badge variant="outline" className="h-5 text-[10px]">ML</Badge>}
                </div>
                <p className="text-muted-foreground mt-1.5 text-xs">
                  <span className="font-medium text-foreground">Evidence:</span>{" "}
                  {f.evidenceSummary}
                </p>
                <p className="text-muted-foreground mt-1 text-xs">{f.whyItMatters}</p>
                <p className="text-primary mt-1 text-xs">
                  <span className="font-medium">Action:</span> {f.recommendedAction}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <h4 className="mb-2 text-xs font-semibold uppercase tracking-wider">
          Captured evidence ({evidence.length})
        </h4>
        {evidence.length === 0 ? (
          <p className="text-muted-foreground text-sm">No evidence items recorded.</p>
        ) : (
          <div className="space-y-2">
            {evidence.map((ev) => (
              <details
                key={ev.id}
                className="border-border/70 group rounded-sm border px-3 py-2"
              >
                <summary className="flex cursor-pointer list-none items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <ChevronRight className="text-muted-foreground size-3 transition-transform group-open:rotate-90" />
                      <span className="sms-mono text-xs font-medium">{ev.id}</span>
                      <span className="text-xs">{ev.label}</span>
                    </div>
                    <div className="text-muted-foreground mt-0.5 line-clamp-1 text-xs">
                      {ev.summary}
                    </div>
                  </div>
                  <EvidenceStateChip state={ev.state} />
                </summary>
                <div className="mt-2 space-y-1.5 border-t border-border/50 pt-2">
                  <p className="text-muted-foreground text-xs leading-relaxed">{ev.summary}</p>
                  {ev.raw && (
                    <pre className="bg-background sms-mono text-muted-foreground overflow-x-auto rounded-sm border border-border/50 p-2 text-[10px] leading-relaxed">
                      {ev.raw}
                    </pre>
                  )}
                </div>
              </details>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function formatTime(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toISOString().slice(11, 19) + " UTC";
}

export default function CaptureDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const capture = useQuery(api.captures.getCapture, id ? { id: id as never } : "skip");
  const removeCapture = useMutation(api.captures.deleteCapture);

  const payload = useMemo(
    () =>
      capture
        ? parseCapturePayload(capture.reportJson, capture.sessionsJson)
        : null,
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
  const current =
    sessionsSorted.find((s) => s.id === selectedSession) ?? sessionsSorted[0] ?? null;
  const currentRisk: RiskSummary | null = current
    ? (() => {
        const r = report.riskBySession[current.id];
        return r
          ? { level: r.level, score: r.score, rationale: r.rationale }
          : null;
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
            <FileDown className="size-4" />
            Report
          </Button>
          <Button size="sm" variant="outline" className="gap-2" onClick={exportJson}>
            <FileJson className="size-4" />
            Evidence JSON
          </Button>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button size="sm" variant="ghost" className="gap-2 text-destructive">
                <Trash2 className="size-4" />
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
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Sessions" value={String(report.sessionCount)} tone="info" />
        <StatTile
          label="Findings"
          value={String(report.findings.length)}
          tone={report.findings.length > 0 ? "warning" : "good"}
        />
        <StatTile
          label="High risk"
          value={String(report.highRiskCount)}
          tone={report.highRiskCount > 0 ? "danger" : "good"}
        />
        <StatTile
          label="Critical"
          value={String(report.criticalCount)}
          tone={report.criticalCount > 0 ? "danger" : "good"}
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-5">
        <Card className="border-border/70 shadow-none lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Sessions by risk</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <ul className="divide-border/70 max-h-[560px] divide-y overflow-y-auto">
              {sessionsSorted.map((s) => {
                const risk = payload.report.riskBySession[s.id];
                return (
                  <li key={s.id}>
                    <button
                      onClick={() => setSelectedSession(s.id)}
                      className={cn(
                        "w-full px-4 py-2.5 text-left transition-colors",
                        current?.id === s.id ? "bg-primary/10" : "hover:bg-accent/50",
                      )}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="sms-mono text-xs font-semibold">{s.id}</span>
                        <RiskBadge level={risk?.level ?? "healthy"} />
                      </div>
                      <div className="text-muted-foreground mt-0.5 truncate text-[11px]">
                        {s.protocol} · {s.srcIp}:{s.srcPort} → {s.dstIp}:{s.dstPort}
                        {s.tls ? " · " + s.tls.version : " · plaintext"}
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          </CardContent>
        </Card>

        <div className="lg:col-span-3">
          {current ? (
            <Card className="border-border/70 shadow-none">
              <CardHeader className="pb-2">
                <CardTitle className="sms-mono text-sm">{sessionTitle(current)}</CardTitle>
                <p className="text-muted-foreground text-xs">
                  {current.packetCount} packets ·{" "}
                  {(current.byteCount / 1024).toFixed(1)} KB transferred ·{" "}
                  {current.connectionStatus}
                  {current.protocolReasons.length > 0 &&
                    " · " + current.protocolReasons[0].toLowerCase()}
                </p>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="assessment">
                  <TabsList className="mb-3 h-8">
                    <TabsTrigger value="assessment" className="text-xs">
                      Assessment
                    </TabsTrigger>
                    <TabsTrigger value="evidence" className="text-xs">
                      Evidence ({evidenceForSession(payload.evidence, current.id).length})
                    </TabsTrigger>
                    <TabsTrigger value="findings" className="text-xs">
                      Findings ({findingsForSession(report.findings, current.id).length})
                    </TabsTrigger>
                  </TabsList>
                  <TabsContent value="assessment" className="mt-0">
                    <SessionDetail
                      session={current}
                      findings={findingsForSession(report.findings, current.id)}
                      evidence={evidenceForSession(payload.evidence, current.id)}
                      risk={currentRisk}
                    />
                  </TabsContent>
                  <TabsContent value="evidence" className="mt-0">
                    <EvidenceList evidence={evidenceForSession(payload.evidence, current.id)} />
                  </TabsContent>
                  <TabsContent value="findings" className="mt-0">
                    <FindingsList findings={findingsForSession(report.findings, current.id)} />
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          ) : (
            <Card className="border-border/70 shadow-none">
              <CardContent className="text-muted-foreground py-10 text-center text-sm">
                No email sessions were reconstructed from this capture.
              </CardContent>
            </Card>
          )}
        </div>
      </div>

      <Card className="border-border/70 mt-4 shadow-none">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <ShieldAlert className="text-primary size-4" />
            Prioritized remediation
          </CardTitle>
        </CardHeader>
        <CardContent>
          {report.recommendations.length === 0 ? (
            <p className="text-muted-foreground text-sm">
              No remediation required — no findings were raised for this capture.
            </p>
          ) : (
            <ol className="space-y-2">
              {report.recommendations.map((rec) => (
                <li
                  key={rec.id}
                  className="border-border/70 flex items-start gap-3 rounded-sm border px-3 py-2.5"
                >
                  <span className="sms-mono text-muted-foreground mt-0.5 text-xs">
                    #{rec.rank}
                  </span>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-medium">{rec.title}</span>
                      <SeverityBadge severity={rec.severity} />
                      <span className="text-muted-foreground text-[11px]">
                        {rec.affectedSessions.length} session
                        {rec.affectedSessions.length === 1 ? "" : "s"}
                      </span>
                    </div>
                    <p className="text-muted-foreground mt-1 text-xs">{rec.why}</p>
                    <p className="text-primary mt-0.5 text-xs">
                      <span className="font-medium">Action:</span> {rec.action}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </CardContent>
      </Card>
    </AppShell>
  );
}

function EvidenceList({ evidence }: { evidence: ReturnType<typeof evidenceForSession> }) {
  if (evidence.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">No evidence items recorded for this session.</p>
    );
  }
  return (
    <div className="space-y-2">
      {evidence.map((ev) => (
        <details key={ev.id} className="border-border/70 group rounded-sm border px-3 py-2">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <ChevronRight className="text-muted-foreground size-3 transition-transform group-open:rotate-90" />
                <span className="sms-mono text-xs font-medium">{ev.id}</span>
                <span className="text-xs">{ev.label}</span>
              </div>
              <div className="text-muted-foreground mt-0.5 line-clamp-1 text-xs">{ev.summary}</div>
            </div>
            <EvidenceStateChip state={ev.state} />
          </summary>
          <div className="mt-2 space-y-1.5 border-t border-border/50 pt-2">
            <p className="text-muted-foreground text-xs leading-relaxed">{ev.summary}</p>
            {ev.raw && (
              <pre className="bg-background sms-mono text-muted-foreground overflow-x-auto rounded-sm border border-border/50 p-2 text-[10px] leading-relaxed">
                {ev.raw}
              </pre>
            )}
          </div>
        </details>
      ))}
    </div>
  );
}

function FindingsList({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <p className="text-muted-foreground text-sm">
        No findings for this session — the observed configuration produced no rule matches.
      </p>
    );
  }
  return (
    <div className="space-y-2">
      {findings.map((f) => (
        <div key={f.id} className="border-border/70 rounded-sm border px-3 py-2.5">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <span className="sms-mono text-xs font-medium">{f.ruleId}</span>
            <span className="text-sm font-medium">{f.title}</span>
          </div>
          <p className="text-muted-foreground mt-1.5 text-xs">
            <span className="font-medium text-foreground">Evidence:</span> {f.evidenceSummary}
          </p>
          <p className="text-muted-foreground mt-1 text-xs">{f.whyItMatters}</p>
          <p className="text-primary mt-1 text-xs">
            <span className="font-medium">Action:</span> {f.recommendedAction}
          </p>
        </div>
      ))}
    </div>
  );
}
