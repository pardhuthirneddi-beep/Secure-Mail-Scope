import { useMemo, useState } from "react";
import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import { FlushPanel, SeverityBadge } from "@/components/sms-ui";
import { Input } from "@/components/ui/input";
import { parseCapturePayload } from "@/lib/sms-format";
import { cn } from "@/lib/utils";
import type { Finding } from "@/sms/types";
import type { Severity } from "@/sms/theme";
import { SEVERITY_ORDER } from "@/sms/theme";
import { Search } from "lucide-react";
import { Link } from "react-router";

interface Row {
  finding: Finding;
  captureId: string;
  captureName: string;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEV_COUNT_CLASS: Record<Severity, string> = {
  critical: "text-(--sms-critical) border-(--sms-critical)/40",
  high: "text-(--sms-high) border-(--sms-high)/40",
  medium: "text-(--sms-medium) border-(--sms-medium)/40",
  low: "text-(--sms-low) border-(--sms-low)/40",
  info: "text-muted-foreground border-border",
};

/** Compact status badge: severity expressed as a small indicator, not a panel. */
function StatusBadge({ severity }: { severity: Severity }) {
  const label =
    severity === "critical" || severity === "high"
      ? severity === "critical"
        ? "CRITICAL"
        : "HIGH"
      : severity === "medium"
        ? "WARNING"
        : severity === "low"
          ? "ADVISORY"
          : "INFO";
  const cls =
    severity === "critical" || severity === "high"
      ? "text-(--sms-critical) border-(--sms-critical)/40"
      : severity === "medium"
        ? "text-(--sms-medium) border-(--sms-medium)/40"
        : severity === "low"
          ? "text-(--sms-low) border-(--sms-low)/40"
          : "text-muted-foreground border-border";
  return (
    <span
      className={cn(
        "sms-mono inline-flex shrink-0 items-center gap-1.5 rounded-[2px] border px-1.5 py-px text-[9px] font-semibold tracking-[0.1em]",
        cls,
      )}
    >
      <span className="bg-current size-1 rounded-full opacity-80" />
      {label}
    </span>
  );
}

export default function Findings() {
  const captures = useQuery(api.captures.listCaptures, {}) ?? [];
  const [severity, setSeverity] = useState<string>("all");
  const [search, setSearch] = useState("");

  const rows = useMemo<Row[]>(() => {
    const out: Row[] = [];
    for (const c of captures) {
      const payload = parseCapturePayload(c.reportJson, c.sessionsJson);
      if (!payload) continue;
      for (const f of payload.report.findings) {
        out.push({ finding: f, captureId: c._id, captureName: c.name });
      }
    }
    out.sort(
      (a, b) => SEVERITY_ORDER[b.finding.severity] - SEVERITY_ORDER[a.finding.severity],
    );
    return out;
  }, [captures]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of SEVERITIES) c[s] = 0;
    for (const r of rows) c[r.finding.severity]++;
    return c;
  }, [rows]);

  const filtered = rows.filter((r) => {
    if (severity !== "all" && r.finding.severity !== severity) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        r.finding.title.toLowerCase().includes(q) ||
        r.finding.ruleId.toLowerCase().includes(q) ||
        r.finding.evidenceSummary.toLowerCase().includes(q) ||
        r.captureName.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <AppShell
      title="Findings"
      subtitle="Every deterministic and ML-assisted finding across your captures, with its evidence"
    >
      {/* Filter bar */}
      <div className="mb-4 flex flex-col gap-2.5 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            onClick={() => setSeverity("all")}
            className={cn(
              "sms-mono rounded-sm border px-2 py-1 text-[10px] tracking-[0.08em] uppercase transition-colors",
              severity === "all"
                ? "border-primary/50 bg-primary/10 text-foreground"
                : "border-border text-muted-foreground hover:border-border hover:text-foreground",
            )}
          >
            all {rows.length}
          </button>
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => setSeverity(s)}
              className={cn(
                "sms-mono rounded-sm border px-2 py-1 text-[10px] tracking-[0.08em] uppercase transition-colors",
                severity === s
                  ? SEV_COUNT_CLASS[s] + " bg-muted/40"
                  : "border-border text-muted-foreground hover:text-foreground",
              )}
            >
              {s} {counts[s] ?? 0}
            </button>
          ))}
        </div>
        <div className="relative lg:w-80">
          <Search className="text-muted-foreground pointer-events-none absolute top-2.5 left-2.5 size-3.5" />
          <Input
            placeholder="Search rule IDs, evidence, captures…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="sms-mono h-8 pl-8 text-xs"
          />
        </div>
      </div>

      {captures.length === 0 ? (
        <div className="border-border/70 text-muted-foreground rounded-sm border border-dashed px-6 py-14 text-center text-sm">
          Analyze a capture first — findings from every capture are collected here.
        </div>
      ) : filtered.length === 0 ? (
        <div className="border-border/70 text-muted-foreground rounded-sm border border-dashed px-6 py-14 text-center text-sm">
          {rows.length === 0
            ? "No findings across your captures — every analyzed session passed the deterministic rule set."
            : "No findings match the current filter."}
        </div>
      ) : (
        <FlushPanel
          label="Finding register"
          meta={filtered.length + " of " + rows.length + " findings"}
          bodyClassName="overflow-x-auto"
        >
          <table className="w-full min-w-[860px] text-sm">
            <thead>
              <tr className="border-border/80 bg-muted/30 border-b">
                <th className="sms-label text-muted-foreground px-3 py-2 text-left">Severity</th>
                <th className="sms-label text-muted-foreground px-3 py-2 text-left">Finding</th>
                <th className="sms-label text-muted-foreground px-3 py-2 text-left">Evidence</th>
                <th className="sms-label text-muted-foreground hidden px-3 py-2 text-left lg:table-cell">
                  Source
                </th>
                <th className="sms-label text-muted-foreground px-3 py-2 text-left">Capture</th>
              </tr>
            </thead>
            <tbody className="divide-border/70 divide-y">
              {filtered.map((r, i) => {
                const isAi = r.finding.detectedBy === "ml";
                return (
                  <tr
                    key={r.captureId + r.finding.id + i}
                    className="group align-top transition-colors hover:bg-accent/40"
                  >
                    <td className="px-3 py-2.5">
                      <div className="flex flex-col items-start gap-1.5">
                        <StatusBadge severity={r.finding.severity} />
                        <SeverityBadge severity={r.finding.severity} className="lg:hidden" />
                      </div>
                    </td>
                    <td className="max-w-[260px] px-3 py-2.5">
                      <div className="sms-mono flex items-center gap-1.5 text-[11px] font-semibold">
                        {r.finding.ruleId}
                        <span
                          className={cn(
                            "sms-mono rounded-[2px] border px-1 text-[8px] tracking-[0.08em] uppercase",
                            isAi
                              ? "border-(--sms-low)/40 text-(--sms-low)"
                              : "border-border text-muted-foreground",
                          )}
                        >
                          {isAi ? "ai-assessed" : "deterministic"}
                        </span>
                      </div>
                      <div className="mt-0.5 truncate text-xs font-medium" title={r.finding.title}>
                        {r.finding.title}
                      </div>
                      <div className="sms-mono text-muted-foreground/70 mt-0.5 text-[10px]">
                        session {r.finding.sessionId} · conf{" "}
                        {Math.round(r.finding.confidence * 100)}%
                      </div>
                    </td>
                    <td className="max-w-[300px] px-3 py-2.5">
                      <p className="text-muted-foreground line-clamp-2 text-[11px] leading-relaxed">
                        {r.finding.evidenceSummary}
                      </p>
                      <p className="text-muted-foreground/70 mt-0.5 line-clamp-1 text-[10px]">
                        {r.finding.recommendedAction}
                      </p>
                    </td>
                    <td className="hidden px-3 py-2.5 lg:table-cell">
                      <span className="sms-mono text-muted-foreground text-[10px] uppercase tracking-[0.08em]">
                        {isAi ? "ML model" : "Rule engine"}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <Link
                        to={"/captures/" + r.captureId}
                        className="sms-mono text-muted-foreground hover:text-primary inline-flex items-center gap-1 text-[11px] transition-colors"
                      >
                        {r.captureName}
                        <span className="opacity-0 transition-opacity group-hover:opacity-100">
                          →
                        </span>
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </FlushPanel>
      )}
      <p className="text-muted-foreground/70 mt-3 text-[11px] leading-relaxed">
        Findings link to the capture record where the full evidence bundle — observed bytes,
        timeline, and per-session risk rationale — can be inspected.
      </p>
    </AppShell>
  );
}
