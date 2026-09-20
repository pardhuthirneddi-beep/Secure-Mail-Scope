import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import { TechCorner } from "@/components/sms-brand";
import {
  FlushPanel,
  Panel,
  StageProgress,
  StatStrip,
  CodeChip,
} from "@/components/sms-ui";
import { StepperFlow } from "@/components/sms-stepper";
import { AnimatedList } from "@/components/reactbits/reactbits";
import { Button } from "@/components/ui/button";
import { STAGES, runPipeline, resultToReportSeed, DISCLAIMER } from "@/sms/pipeline";
import { buildDemoPcap, listDemoScenarios } from "@/sms/scenarios";
import { formatBytes, formatDuration, formatDate, parseCapturePayload } from "@/lib/sms-format";
import { cn } from "@/lib/utils";
import {
  Activity,
  ArrowLeftRight,
  ArrowRight,
  FileCheck2,
  FileText,
  FileUp,
  Gauge,
  Layers,
  Loader2,
  Lock,
  Mail,
  Mails,
  Network,
  ShieldAlert,
} from "lucide-react";
import { useNavigate } from "react-router";
import { toast } from "sonner";

type RunState =
  | { phase: "idle" }
  | { phase: "running"; stageIndex: number; label: string }
  | { phase: "error"; message: string };

const RISK_ORDER = ["healthy", "low", "medium", "high", "critical"];

/** Session boot time — computed once at module load so the footer status line
 *  never calls an impure function during render. */
const BOOT_DATE = new Date();

const RISK_DOT_TONE = {
  healthy: "bg-(--sms-healthy)",
  low: "bg-(--sms-low)",
  medium: "bg-(--sms-medium)",
  high: "bg-(--sms-high)",
  critical: "bg-(--sms-critical)",
} as const;

/* ----------------------------------------------------- pipeline visualization */

/**
 * The seven display stages of the analysis chain. Each maps onto the real
 * pipeline stages (STAGES in sms/pipeline.ts) that the app actually reports
 * progress for — nothing here is a fabricated processing step.
 */
const PIPELINE_VIEW = [
  { id: "recon", label: "Session Reconstruction", icon: <Network className="size-4" />, stages: ["parse", "sessions"] },
  { id: "proto", label: "Protocol Identification", icon: <Mail className="size-4" />, stages: ["proto"] },
  { id: "tls", label: "TLS / STARTTLS Analysis", icon: <Lock className="size-4" />, stages: ["starttls", "tls"] },
  { id: "cert", label: "Certificate Inspection", icon: <FileCheck2 className="size-4" />, stages: ["certs"] },
  { id: "crypto", label: "Crypto Weakness Detection", icon: <ShieldAlert className="size-4" />, stages: ["rules"] },
  { id: "ai", label: "AI Risk Assessment", icon: <Activity className="size-4" />, stages: ["ml"] },
  { id: "report", label: "Report Generation", icon: <FileText className="size-4" />, stages: ["findings"] },
];

/**
 * Visual groups fully completed by the real pipeline — every underlying stage
 * in the group has reported done. The stepper visual can never run ahead of
 * this number, and a group is never shown complete while any of its stages
 * (e.g. "sessions" inside Session Reconstruction) is still in flight.
 */
function groupsDone(done: ReadonlySet<string>): number {
  return PIPELINE_VIEW.filter((g) => g.stages.every((s) => done.has(s))).length;
}

/* ---------------------------------------------------------- posture helpers */

const POSTURE_ROWS: Array<{ category: string; label: string }> = [
  { category: "Transport Security", label: "Transport Security" },
  { category: "TLS Configuration", label: "TLS Configuration" },
  { category: "Certificate Security", label: "Certificate" },
  { category: "Protocol Security", label: "STARTTLS" },
  { category: "Anomaly Status", label: "Cryptographic Anomalies" },
];

type PostureStatus = "PASS" | "WARNING" | "CRITICAL" | "UNAVAILABLE";

function postureStatus(score: number | null): PostureStatus {
  if (score === null) return "UNAVAILABLE";
  if (score >= 90) return "PASS";
  if (score >= 50) return "WARNING";
  return "CRITICAL";
}

const POSTURE_STATUS_CLASS: Record<PostureStatus, string> = {
  PASS: "text-(--sms-healthy) border-(--sms-healthy)/40",
  WARNING: "text-(--sms-medium) border-(--sms-medium)/40",
  CRITICAL: "text-(--sms-critical) border-(--sms-critical)/40",
  UNAVAILABLE: "text-muted-foreground border-border",
};

const POSTURE_BAR_CLASS: Record<PostureStatus, string> = {
  PASS: "bg-(--sms-healthy)/70",
  WARNING: "bg-(--sms-medium)",
  CRITICAL: "bg-(--sms-critical)",
  UNAVAILABLE: "bg-transparent",
};

/* -------------------------------------------------------------- investigation
   workflow chain — the "from packets to proof" story, one compact column. */

const WORKFLOW = [
  { label: "PCAP", icon: <FileUp className="size-3" /> },
  { label: "Sessions", icon: <Layers className="size-3" /> },
  { label: "Protocols", icon: <Mails className="size-3" /> },
  { label: "TLS / STARTTLS", icon: <ArrowLeftRight className="size-3" /> },
  { label: "Certificate", icon: <FileCheck2 className="size-3" /> },
  { label: "Weakness", icon: <ShieldAlert className="size-3" /> },
  { label: "Risk", icon: <Gauge className="size-3" /> },
  { label: "Report", icon: <FileText className="size-3" /> },
];

function WorkflowChain({ className }: { className?: string }) {
  return (
    <ol className={cn("relative", className)}>
      {WORKFLOW.map((step, i) => (
        <li key={step.label} className="relative flex items-center gap-2.5 pb-3 last:pb-0">
          {i < WORKFLOW.length - 1 && (
            <span className="bg-(--sms-wave)/25 absolute top-4 bottom-0 left-[7px] w-px" />
          )}
          <span className="border-border/80 bg-card relative z-10 flex size-3.5 shrink-0 items-center justify-center rounded-[2px] border">
            <span className="text-muted-foreground/80">{step.icon}</span>
          </span>
          <span className="sms-mono text-muted-foreground text-[11px]">{step.label}</span>
        </li>
      ))}
    </ol>
  );
}

/* ---------------------------------------------------------------------- page */

export default function Dashboard() {
  const navigate = useNavigate();
  const captures = useQuery(api.captures.listCaptures, {}) ?? [];
  const createCapture = useMutation(api.captures.createCapture);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const [run, setRun] = useState<RunState>({ phase: "idle" });
  const [dragOver, setDragOver] = useState(false);
  const [runId, setRunId] = useState(0); // bumps on every analysis → stepper replay
  const [doneIds, setDoneIds] = useState<Set<string>>(new Set()); // raw stages reported done
  const demos = useMemo(() => listDemoScenarios(), []);

  const totals = useMemo(() => {
    let findings = 0;
    let high = 0;
    let critical = 0;
    let sessions = 0;
    for (const c of captures) {
      findings += c.findingCount;
      high += c.highRiskCount;
      critical += c.criticalCount;
      sessions += c.sessionCount;
    }
    return { findings, high, critical, sessions };
  }, [captures]);

  // Latest analysis — real stored report from the most recent capture.
  const latest = captures[0] ?? null;
  const latestReport = useMemo(
    () => (latest ? parseCapturePayload(latest.reportJson, latest.sessionsJson)?.report ?? null : null),
    [latest],
  );

  const analyze = async (
    buffer: ArrayBuffer,
    fileName: string,
    isDemo: boolean,
    demoId?: string,
  ) => {
    setRunId((n) => n + 1); // reset + replay the stepper sequence
    setDoneIds(new Set());
    setRun({ phase: "running", stageIndex: 0, label: STAGES[0].label });
    try {
      const result = await runPipeline(buffer, fileName, ({ stageId, done }) => {
        if (done) {
          setDoneIds((prev) => {
            if (prev.has(stageId)) return prev;
            const next = new Set(prev);
            next.add(stageId);
            return next;
          });
          const idx = STAGES.findIndex((s) => s.id === stageId);
          const next = Math.min(idx + 1, STAGES.length - 1);
          setRun({ phase: "running", stageIndex: next, label: STAGES[next].label });
        }
      });
      const report = resultToReportSeed(result, demoId ? { scenarioId: demoId } : {});
      const sessionsJson = JSON.stringify({
        sessions: result.sessions,
        evidence: result.evidence,
      });
      const maxRisk = result.sessions.reduce<string>((acc, s) => {
        const lv = result.riskBySession[s.id]?.level ?? "healthy";
        return RISK_ORDER.indexOf(lv) > RISK_ORDER.indexOf(acc) ? lv : acc;
      }, "healthy");
      await createCapture({
        name: fileName,
        sizeBytes: result.capture.sizeBytes,
        packetCount: result.capture.packetCount,
        durationSec: result.capture.durationSec,
        sessionCount: result.sessions.length,
        findingCount: result.findings.length,
        highRiskCount: report.highRiskCount,
        criticalCount: report.criticalCount,
        maxRisk,
        isDemo,
        demoScenarioId: demoId,
        reportJson: JSON.stringify(report),
        sessionsJson,
      });
      setDoneIds(new Set(STAGES.map((s) => s.id))); // every stage measured complete
      setRun({ phase: "idle" });
      toast.success("Analysis complete", {
        description:
          result.sessions.length + " sessions · " + result.findings.length + " findings",
      });
      // Analysis settles on Overview by design: the stored capture is reachable
      // via the Latest Analysis panel, Recent captures, Captures, Findings and
      // Reports — never force-navigated away from the workstation home.
    } catch (e) {
      setRun({ phase: "error", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const handleFile = (file: File) => {
    if (!/\.(pcap|pcapng)$/i.test(file.name)) {
      setRun({
        phase: "error",
        message: "Unsupported file type. Provide a .pcap or .pcapng capture.",
      });
      return;
    }
    if (file.size > 64 * 1024 * 1024) {
      setRun({ phase: "error", message: "Capture exceeds the 64 MB analysis limit." });
      return;
    }
    file.arrayBuffer().then((buf) => analyze(buf, file.name, false));
  };

  const handleDemo = (demoId: string) => {
    const demo = demos.find((d) => d.id === demoId);
    if (!demo) return;
    const { bytes, fileName } = buildDemoPcap(demo);
    const buf = bytes.buffer.slice(
      bytes.byteOffset,
      bytes.byteOffset + bytes.byteLength,
    ) as ArrayBuffer;
    analyze(buf, fileName, true, demoId);
  };

  const running = run.phase === "running";

  return (
    <AppShell
      title="Overview"
      subtitle="Evidence-driven cryptographic posture assessment for email traffic"
      actions={
        <Button
          size="sm"
          className="gap-2"
          disabled={running}
          onClick={() => fileInput.current?.click()}
        >
          <FileUp className="size-3.5" />
          New analysis
        </Button>
      }
    >
      <input
        ref={fileInput}
        type="file"
        accept=".pcap,.pcapng"
        className="hidden"
        onChange={(e) => {
          const f = e.target.files?.[0];
          if (f) handleFile(f);
          e.target.value = "";
        }}
      />

      {/* Forensic status modules — React Bits CountUp animates the real totals */}
      <StatStrip
        items={[
          { label: "Captures", value: String(captures.length), tone: "info" },
          { label: "Sessions", value: String(totals.sessions), hint: "Reconstructed from packets" },
          {
            label: "Findings",
            value: String(totals.findings),
            tone: totals.findings > 0 ? "warning" : "good",
          },
          {
            label: "High / critical",
            value: String(totals.high + totals.critical),
            tone: totals.critical > 0 ? "danger" : totals.high > 0 ? "warning" : "good",
          },
        ]}
      />

      {/* Analysis pipeline — the connected stage chain */}
      <Panel
        label="Analysis pipeline"
        meta={
          running
            ? run.label
            : run.phase === "error"
              ? "stopped · see capture intake"
              : "idle · run a capture to watch the sequence"
        }
        className="relative mt-4 overflow-hidden"
        actions={
          <span className="sms-mono text-muted-foreground/60 hidden text-[10px] sm:block">
            pcap → evidence → session → protocol → tls → finding → risk → report
          </span>
        }
      >
        <TechCorner className="top-0 right-0" />
        <StepperFlow
          className="py-1"
          runId={runId}
          running={running}
          error={run.phase === "error"}
          realDoneCount={groupsDone(doneIds)}
          stages={PIPELINE_VIEW.map((v) => ({ id: v.id, label: v.label, icon: v.icon }))}
        />
        <p className="text-muted-foreground/60 mt-2 text-[10px] leading-relaxed">
          Stages advance one at a time as the pipeline reports them complete; the paced
          sequencing is a visual walkthrough of the real analysis order. Measured processing
          time is reported during the run and stored with each capture record.
        </p>
      </Panel>

      <div className="mt-4 grid gap-4 lg:grid-cols-12">
        {/* Capture intake */}
        <Panel
          label="Capture intake"
          meta=".pcap / .pcapng · ≤ 64 MB"
          className="lg:col-span-7"
        >
          <div
            role="button"
            tabIndex={0}
            onClick={() => !running && fileInput.current?.click()}
            onKeyDown={(e) => {
              if ((e.key === "Enter" || e.key === " ") && !running) fileInput.current?.click();
            }}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const f = e.dataTransfer.files?.[0];
              if (f) handleFile(f);
            }}
            className={cn(
              "relative overflow-hidden rounded-sm border border-dashed px-6 py-8 text-center transition-colors",
              dragOver
                ? "border-primary/70 bg-primary/5"
                : "border-border hover:border-primary/40",
            )}
          >
            {running && (
              <span className="sms-scanline bg-primary/10 pointer-events-none absolute inset-x-0 top-0 h-10" />
            )}
            <p className="text-sm font-medium">
              {dragOver ? "Release to stage the capture" : "Drop a capture here, or click to browse"}
            </p>
            <p className="text-muted-foreground mx-auto mt-1.5 max-w-md text-xs leading-relaxed">
              SMTP, IMAP and POP3 sessions are reconstructed and assessed locally in your browser.
              Packets are never uploaded; only the finished evidence report is stored.
            </p>
          </div>

          {run.phase === "error" && (
            <div className="border-(--sms-critical)/40 bg-(--sms-critical)/10 text-(--sms-critical) mt-3 rounded-sm border px-3 py-2 text-xs">
              {run.message}
            </div>
          )}

          {running && (
            <div className="border-border/70 bg-background/60 mt-3 rounded-sm border p-3">
              <div className="mb-2 flex items-center justify-between">
                <span className="sms-label text-muted-foreground">Pipeline</span>
                <span className="sms-mono text-primary text-[11px]">
                  {run.phase === "running" ? run.label : "…"}
                  <Loader2 className="ml-1.5 inline size-3 animate-spin align-[-2px]" />
                </span>
              </div>
              <StageProgress stages={STAGES} activeIndex={run.phase === "running" ? run.stageIndex : 0} />
            </div>
          )}

          <div className="mt-5">
            <div className="sms-label text-muted-foreground mb-2">
              Reference captures — generated locally, labeled demo
            </div>
            <div className="border-border/70 overflow-hidden rounded-sm border">
              {demos.map((d, i) => (
                <button
                  key={d.id}
                  disabled={running}
                  onClick={() => handleDemo(d.id)}
                  className={cn(
                    "group hover:bg-accent/50 flex w-full items-center gap-3 px-3 py-2 text-left transition-colors disabled:opacity-50",
                    i > 0 && "border-border/70 border-t",
                  )}
                >
                  <span className="sms-mono text-muted-foreground/70 w-5 shrink-0 text-[10px]">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-xs font-medium">
                      {d.label.replace(/^DEMO \d+ — /, "")}
                    </span>
                    <span className="text-muted-foreground block truncate text-[11px]">
                      {d.description}
                    </span>
                  </span>
                  <span className="sms-mono text-muted-foreground/50 group-hover:text-primary shrink-0 text-[10px] transition-colors">
                    run →
                  </span>
                </button>
              ))}
            </div>
          </div>
        </Panel>

        {/* Security posture — real per-capture scores; unavailable when not measurable */}
        <Panel
          label="Security posture"
          meta={latestReport ? "latest capture · score share of sessions" : "no capture analyzed"}
          className="lg:col-span-5"
        >
          <div className="divide-border/60 divide-y">
            {POSTURE_ROWS.map((row) => {
              const real = latestReport?.posture.find((p) => p.category === row.category);
              const status = postureStatus(real ? real.score : null);
              return (
                <div key={row.category} className="py-2.5">
                  <div className="flex items-center justify-between gap-3">
                    <div className="text-xs font-medium">{row.label}</div>
                    <span
                      className={cn(
                        "sms-mono shrink-0 rounded-[2px] border px-1.5 py-px text-[9px] tracking-[0.1em] font-semibold",
                        POSTURE_STATUS_CLASS[status],
                      )}
                    >
                      {status}
                    </span>
                  </div>
                  {/* Meter: only drawn when a real score exists */}
                  <div className="bg-muted/70 mt-1.5 h-1 w-full overflow-hidden rounded-[1px]">
                    <div
                      className={cn(
                        "h-full transition-[width] duration-500",
                        POSTURE_BAR_CLASS[status],
                      )}
                      style={{ width: real ? real.score + "%" : "0%" }}
                    />
                  </div>
                  <div
                    className={cn(
                      "sms-mono mt-1 truncate text-[10px]",
                      real ? "text-muted-foreground/70" : "text-muted-foreground/50",
                    )}
                  >
                    {real
                      ? real.score + "% · " + real.basisCount + " session" + (real.basisCount === 1 ? "" : "s")
                      : latestReport
                        ? "not measurable in this capture"
                        : "awaiting first analysis"}
                  </div>
                </div>
              );
            })}
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-12">
        {/* Latest analysis */}
        <Panel label="Latest analysis" meta={latest ? formatDate(latest.uploadedAt) : "none yet"} className="lg:col-span-5">
          {latest ? (
            <div className="flex items-center gap-3">
              <span className="border-border/80 bg-muted/40 text-muted-foreground flex size-10 shrink-0 items-center justify-center rounded-[3px] border">
                <FileText className="size-4" />
              </span>
              <div className="min-w-0 flex-1">
                <div className="sms-mono flex items-center gap-2 truncate text-xs font-semibold">
                  {latest.name}
                  <span className="text-(--sms-healthy) border-(--sms-healthy)/40 inline-flex shrink-0 items-center gap-1 rounded-[2px] border px-1.5 py-px text-[9px] tracking-[0.1em] uppercase">
                    <span className="bg-(--sms-healthy) size-1 rounded-full" />
                    Analyzed
                  </span>
                </div>
                <div className="text-muted-foreground mt-1 truncate text-[11px]">
                  {latest.sessionCount} session{latest.sessionCount === 1 ? "" : "s"} ·{" "}
                  {latest.findingCount} finding{latest.findingCount === 1 ? "" : "s"} ·{" "}
                  {formatBytes(latest.sizeBytes)} · {formatDuration(latest.durationSec)}
                </div>
              </div>
              <Button
                size="sm"
                variant="outline"
                className="h-7 shrink-0 gap-1.5 text-[11px]"
                onClick={() => navigate("/captures/" + latest._id)}
              >
                Open
                <ArrowRight className="size-3" />
              </Button>
            </div>
          ) : (
            <p className="text-muted-foreground py-4 text-center text-xs">
              No captures analyzed yet — the latest report will appear here.
            </p>
          )}
        </Panel>

        {/* Investigation workflow */}
        <Panel
          label="Investigation workflow"
          meta="from packets to proof"
          className="lg:col-span-3"
        >
          <WorkflowChain />
        </Panel>

        {/* Recent captures — React Bits AnimatedList staggered entrance */}
        <FlushPanel
          label="Recent captures"
          meta={captures.length > 0 ? captures.length + " analyzed" : "empty"}
          className="lg:col-span-4"
          bodyClassName="max-h-[320px] overflow-y-auto"
        >
          {captures.length === 0 ? (
            <p className="text-muted-foreground px-4 py-8 text-center text-xs leading-relaxed">
              No captures analyzed yet.
              <br />
              Upload a PCAP or run a reference capture to begin.
            </p>
          ) : (
            <AnimatedList
              className="divide-border/70 divide-y"
              items={captures.slice(0, 8).map((c) => ({
                key: c._id,
                node: (
                  <button
                    className="hover:bg-accent/50 group w-full px-3.5 py-2.5 text-left transition-colors"
                    onClick={() => navigate("/captures/" + c._id)}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="sms-mono flex min-w-0 items-center gap-1.5 truncate text-xs font-medium">
                        <span
                          className={cn(
                            "size-1.5 shrink-0 rounded-[1px]",
                            RISK_DOT_TONE[c.maxRisk as keyof typeof RISK_DOT_TONE] ?? "bg-muted",
                          )}
                        />
                        {c.isDemo && (
                          <span className="text-(--sms-medium) shrink-0 rounded-[2px] border border-(--sms-medium)/40 px-1 text-[9px] uppercase">
                            demo
                          </span>
                        )}
                        <span className="truncate">{c.name}</span>
                      </span>
                      <span className="sms-mono text-muted-foreground/50 group-hover:text-primary shrink-0 text-[10px] transition-colors">
                        open →
                      </span>
                    </div>
                    <div className="text-muted-foreground mt-1 flex items-center gap-2 text-[11px]">
                      <span>
                        {c.sessionCount} sessions · {c.findingCount} findings
                      </span>
                      <span className="text-muted-foreground/50">·</span>
                      <span>{formatBytes(c.sizeBytes)}</span>
                    </div>
                  </button>
                ),
              }))}
            />
          )}
        </FlushPanel>
      </div>

      <div className="border-border/70 bg-card/40 mt-4 rounded-sm border px-4 py-3">
        <p className="text-muted-foreground text-xs leading-relaxed">
          <span className="sms-label text-foreground mr-2">Scope</span>
          {DISCLAIMER}
        </p>
      </div>
      <div className="sms-mono text-muted-foreground/70 mt-3 flex items-center gap-1.5 text-[10px]">
        <CodeChip>SMS</CodeChip>
        workstation ready · {formatDate(BOOT_DATE.getTime())}
      </div>
    </AppShell>
  );
}
