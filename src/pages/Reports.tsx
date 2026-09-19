import { useMemo } from "react";
import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import { RiskBadge } from "@/components/sms-ui";
import { Button } from "@/components/ui/button";
import {
  buildMarkdownReport,
  downloadText,
  parseCapturePayload,
  safeFileStem,
} from "@/lib/sms-format";
import { FileDown, FileJson, FileText } from "lucide-react";
import { Link } from "react-router";
import { toast } from "sonner";

export default function Reports() {
  const captures = useQuery(api.captures.listCaptures, {}) ?? [];

  const summaries = useMemo(
    () =>
      captures.map((c) => {
        const payload = parseCapturePayload(c.reportJson, c.sessionsJson);
        return { capture: c, report: payload?.report ?? null };
      }),
    [captures],
  );

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
        <div className="border-border/70 text-muted-foreground rounded-md border border-dashed px-6 py-12 text-center text-sm">
          No reports yet. Every completed analysis produces a downloadable posture report with
          per-finding evidence citations.{" "}
          <Link to="/dashboard" className="text-primary underline">
            Analyze a capture
          </Link>
          .
        </div>
      ) : (
        <div className="space-y-3">
          {summaries.map(({ capture: c, report }) => (
            <div
              key={c._id}
              className="border-border/70 bg-card/40 flex flex-col gap-3 rounded-md border px-4 py-3.5 sm:flex-row sm:items-center sm:justify-between"
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <FileText className="text-muted-foreground size-4 shrink-0" />
                  <span className="sms-mono truncate text-sm font-medium">{c.name}</span>
                  {report && <RiskBadge level={c.maxRisk as never} />}
                  {c.isDemo && (
                    <span className="text-[--sms-medium] rounded-sm border border-[--sms-medium]/40 px-1 py-px text-[9px] uppercase">
                      demo
                    </span>
                  )}
                </div>
                <p className="text-muted-foreground mt-1 text-xs">
                  {report
                    ? report.findings.length +
                      " findings · " +
                      report.recommendations.length +
                      " remediation items · " +
                      report.posture.length +
                      " posture categories"
                    : "Report payload unavailable"}
                </p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                {report && (
                  <>
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-2"
                      onClick={() => downloadMarkdown(c)}
                    >
                      <FileDown className="size-4" />
                      Markdown
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      className="gap-2"
                      onClick={() => downloadJson(c)}
                    >
                      <FileJson className="size-4" />
                      JSON
                    </Button>
                  </>
                )}
              </div>
            </div>
          ))}
          <p className="text-muted-foreground text-xs">
            Reports are generated client-side from the stored evidence bundle, so every claim in a
            downloaded report can be traced back to the JSON evidence export of the same capture.
          </p>
        </div>
      )}
    </AppShell>
  );
}
