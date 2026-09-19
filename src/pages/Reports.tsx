import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import { FlushPanel, RiskDot } from "@/components/sms-ui";
import { Button } from "@/components/ui/button";
import {
  buildMarkdownReport,
  downloadText,
  parseCapturePayload,
  safeFileStem,
} from "@/lib/sms-format";
import { cn } from "@/lib/utils";
import { FileDown, FileJson } from "lucide-react";
import { Link } from "react-router";
import { toast } from "sonner";

const RISK_DOT_TONE = {
  healthy: "bg-(--sms-healthy)",
  low: "bg-(--sms-low)",
  medium: "bg-(--sms-medium)",
  high: "bg-(--sms-high)",
  critical: "bg-(--sms-critical)",
} as const;

export default function Reports() {
  const captures = useQuery(api.captures.listCaptures, {}) ?? [];

  const downloadMarkdown = (c: (typeof captures)[number]) => {
    const payload = parseCapturePayload(c.reportJson, c.sessionsJson);
    if (!payload) return;
    downloadText(
      safeFileStem(c.name) + "-posture-report.md",
      buildMarkdownReport(payload.report, c.name, {
        sizeBytes: c.sizeBytes,
        packetCount: c.packetCount,
        durationSec: c.durationSec,
        isDemo: c.isDemo,
      }),
      "text/markdown",
    );
    toast.success("Markdown report downloaded");
  };

  const downloadJson = (c: (typeof captures)[number]) => {
    const payload = parseCapturePayload(c.reportJson, c.sessionsJson);
    if (!payload) return;
    downloadText(
      safeFileStem(c.name) + "-evidence.json",
      JSON.stringify(
        {
          report: payload.report,
          sessions: payload.sessions,
          evidence: payload.evidence,
          exportedAt: new Date().toISOString(),
        },
        null,
        2,
      ),
      "application/json",
    );
    toast.success("JSON evidence bundle downloaded");
  };

  return (
    <AppShell
      title="Reports"
      subtitle="Remediation-ready posture reports generated from stored evidence"
    >
      {captures.length === 0 ? (
        <div className="border-border/70 text-muted-foreground rounded-sm border border-dashed px-6 py-14 text-center text-sm">
          No reports yet. Every completed analysis produces a downloadable posture report with
          per-finding evidence citations.{" "}
          <Link to="/dashboard" className="text-primary underline">
            Analyze a capture
          </Link>
          .
        </div>
      ) : (
        <FlushPanel label="Report library" meta={captures.length + " reports"}>
          <ul className="divide-border/70 divide-y">
            {captures.map((c) => {
              const report = parseCapturePayload(c.reportJson, c.sessionsJson)?.report ?? null;
              return (
                <li
                  key={c._id}
                  className="hover:bg-accent/40 flex flex-col gap-3 px-3.5 py-3 transition-colors sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="min-w-0">
                    <div className="sms-mono flex items-center gap-2 text-xs font-medium">
                      <span
                        className={cn(
                          "size-1.5 shrink-0 rounded-[1px]",
                          RISK_DOT_TONE[c.maxRisk as keyof typeof RISK_DOT_TONE] ?? "bg-muted",
                        )}
                      />
                      <span className="truncate">{c.name}</span>
                      {c.isDemo && (
                        <span className="text-(--sms-medium) shrink-0 rounded-[2px] border border-(--sms-medium)/40 px-1 text-[9px] uppercase">
                          demo
                        </span>
                      )}
                    </div>
                    {report && (
                      <p className="text-muted-foreground mt-1 text-[11px]">
                        {report.findings.length} findings · {report.recommendations.length}{" "}
                        remediation items · {report.posture.length} posture categories
                      </p>
                    )}
                  </div>
                  {report && (
                    <div className="flex shrink-0 items-center gap-1.5">
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 gap-1.5 text-[11px]"
                        onClick={() => downloadMarkdown(c)}
                      >
                        <FileDown className="size-3" />
                        Markdown
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 gap-1.5 text-[11px]"
                        onClick={() => downloadJson(c)}
                      >
                        <FileJson className="size-3" />
                        JSON
                      </Button>
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </FlushPanel>
      )}
      <p className="text-muted-foreground mt-3 text-[11px] leading-relaxed">
        Reports are generated client-side from the stored evidence bundle, so every claim in a
        downloaded report can be traced back to the JSON evidence export of the same capture.
      </p>
    </AppShell>
  );
}
