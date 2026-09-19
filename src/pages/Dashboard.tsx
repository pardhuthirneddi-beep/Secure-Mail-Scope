import { useMemo, useRef, useState } from "react";
import { useMutation, useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import { StatTile, RiskBadge, CaptureMetaLine } from "@/components/sms-ui";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { STAGES, runPipeline, resultToReportSeed, DISCLAIMER } from "@/sms/pipeline";
import { buildDemoPcap, listDemoScenarios } from "@/sms/scenarios";
import { cn } from "@/lib/utils";
import {
  AlertTriangle,
  FileUp,
  FlaskConical,
  Loader2,
  ScanSearch,
  ShieldCheck,
} from "lucide-react";
import { useNavigate } from "react-router";
import { toast } from "sonner";

type RunState =
  | { phase: "idle" }
  | { phase: "running"; stageIndex: number; label: string }
  | { phase: "error"; message: string };

export default function Dashboard() {
  const navigate = useNavigate();
  const captures = useQuery(api.captures.listCaptures, {}) ?? [];
  const createCapture = useMutation(api.captures.createCapture);
  const fileInput = useRef<HTMLInputElement | null>(null);
  const [run, setRun] = useState<RunState>({ phase: "idle" });
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

  const analyze = async (buffer: ArrayBuffer, fileName: string, isDemo: boolean, demoId?: string) => {
    setRun({ phase: "running", stageIndex: 0, label: STAGES[0].label });
    try {
      const result = await runPipeline(buffer, fileName, ({ stageId, done }) => {
        if (done) {
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
      const maxRisk = result.sessions.reduce<string>(
        (acc, s) => {
          const lv = result.riskBySession[s.id]?.level ?? "healthy";
          const order = ["healthy", "low", "medium", "high", "critical"];
          return order.indexOf(lv) > order.indexOf(acc) ? lv : acc;
        },
        "healthy",
      );
      const id = await createCapture({
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
      setRun({ phase: "idle" });
      toast.success("Analysis complete", {
        description:
          result.sessions.length + " sessions · " + result.findings.length + " findings",
      });
      navigate("/captures/" + id);
    } catch (e) {
      setRun({ phase: "error", message: e instanceof Error ? e.message : String(e) });
    }
  };

  const handleFile = (file: File) => {
    if (!/\.(pcap|pcapng)$/i.test(file.name)) {
      setRun({ phase: "error", message: "Unsupported file type. Provide a .pcap or .pcapng capture." });
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
    const buf = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
    analyze(buf, fileName, true, demoId);
  };

  const running = run.phase === "running";

  return (
    <AppShell
      title="Overview"
      subtitle="Evidence-driven cryptographic posture assessment for email traffic"
      actions={
        <Button size="sm" className="gap-2" disabled={running} onClick={() => fileInput.current?.click()}>
          <FileUp className="size-4" />
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

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile label="Captures analyzed" value={String(captures.length)} tone="info" />
        <StatTile label="Email sessions" value={String(totals.sessions)} hint="Reconstructed from packet evidence" />
        <StatTile label="Open findings" value={String(totals.findings)} tone={totals.findings > 0 ? "warning" : "good"} />
        <StatTile
          label="High / critical"
          value={totals.high + totals.critical > 0 ? String(totals.high + totals.critical) : "0"}
          tone={totals.critical > 0 ? "danger" : totals.high > 0 ? "warning" : "good"}
        />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-5">
        <Card className="border-border/70 shadow-none lg:col-span-3">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm">
              <FileUp className="text-primary size-4" />
              Analyze a capture
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div
              className="border-border/70 hover:border-primary/50 sms-grid-bg cursor-pointer rounded-md border border-dashed px-6 py-8 text-center transition-colors"
              onClick={() => !running && fileInput.current?.click()}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                const f = e.dataTransfer.files?.[0];
                if (f) handleFile(f);
              }}
            >
              <ScanSearch className="text-muted-foreground mx-auto mb-2 size-6" />
              <p className="text-sm font-medium">Drop a PCAP here or click to browse</p>
              <p className="text-muted-foreground mt-1 text-xs">
                .pcap / .pcapng up to 64 MB — SMTP, IMAP and POP3 sessions are reconstructed
                locally; nothing leaves your browser except the finished evidence report.
              </p>
            </div>

            {running && (
              <div className="mt-4">
                <div className="text-muted-foreground mb-2 flex items-center gap-2 text-xs">
                  <Loader2 className="size-3.5 animate-spin" />
                  {run.phase === "running" ? run.label : "Working…"}
                </div>
                <Progress
                  value={((run.phase === "running" ? run.stageIndex : 0) + 1) * (100 / STAGES.length)}
                  className="h-1.5"
                />
              </div>
            )}
            {run.phase === "error" && (
              <div className="border-[--sms-critical]/40 bg-[--sms-critical]/10 text-[--sms-critical] mt-4 flex items-start gap-2 rounded-sm border px-3 py-2 text-xs">
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                {run.message}
              </div>
            )}

            <div className="mt-5">
              <div className="text-muted-foreground mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wider">
                <FlaskConical className="size-3.5" />
                Or explore a generated demo capture
              </div>
              <div className="grid gap-2 sm:grid-cols-2">
                {demos.map((d) => (
                  <button
                    key={d.id}
                    disabled={running}
                    onClick={() => handleDemo(d.id)}
                    className="border-border/70 hover:border-primary/50 hover:bg-accent/50 rounded-sm border px-3 py-2 text-left transition-colors disabled:opacity-50"
                  >
                    <div className="text-xs font-medium">{d.label.replace(/^DEMO \d+ — /, "")}</div>
                    <div className="text-muted-foreground mt-0.5 text-[11px] leading-snug">
                      {d.description}
                    </div>
                  </button>
                ))}
              </div>
              <p className="text-muted-foreground mt-2 text-[11px]">
                Demo captures are generated locally and labeled as demonstration data end to end.
              </p>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border/70 shadow-none lg:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Recent captures</CardTitle>
          </CardHeader>
          <CardContent>
            {captures.length === 0 ? (
              <p className="text-muted-foreground text-sm">
                No captures analyzed yet. Upload a PCAP or run a demo capture to see evidence-linked
                findings here.
              </p>
            ) : (
              <ul className="divide-border/70 divide-y">
                {captures.slice(0, 6).map((c) => (
                  <li key={c._id}>
                    <button
                      className={cn(
                        "hover:bg-accent/50 w-full rounded-sm px-2 py-2.5 text-left transition-colors",
                      )}
                      onClick={() => navigate("/captures/" + c._id)}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="sms-mono truncate text-xs font-medium">
                          {c.isDemo && (
                            <span className="text-[--sms-medium] mr-1.5 rounded-sm border border-[--sms-medium]/40 px-1 py-px text-[9px] uppercase">
                              demo
                            </span>
                          )}
                          {c.name}
                        </span>
                        <RiskBadge level={c.maxRisk as never} />
                      </div>
                      <div className="mt-1 flex items-center justify-between">
                        <CaptureMetaLine
                          sizeBytes={c.sizeBytes}
                          packetCount={c.packetCount}
                          durationSec={c.durationSec}
                        />
                        <span className="text-muted-foreground text-[11px]">
                          {c.sessionCount} sessions · {c.findingCount} findings
                        </span>
                      </div>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      <div className="border-border/70 bg-card/40 mt-4 flex items-start gap-3 rounded-md border px-4 py-3">
        <ShieldCheck className="text-[--sms-healthy] mt-0.5 size-4 shrink-0" />
        <p className="text-muted-foreground text-xs leading-relaxed">
          {DISCLAIMER} Analysis runs entirely in your browser: packets are never uploaded, and
          encrypted message content is never decrypted. Every finding links back to packet evidence
          with session identifiers and byte-level excerpts included.
        </p>
      </div>
    </AppShell>
  );
}
