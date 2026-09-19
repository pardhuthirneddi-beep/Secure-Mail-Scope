import { useMemo, useState } from "react";
import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import { EvidenceChip, SeverityBadge } from "@/components/sms-ui";
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
  critical: "text-[--sms-critical] border-[--sms-critical]/40",
  high: "text-[--sms-high] border-[--sms-high]/40",
  medium: "text-[--sms-medium] border-[--sms-medium]/40",
  low: "text-[--sms-low] border-[--sms-low]/40",
  info: "text-muted-foreground border-border",
};

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
        <div className="space-y-1.5">
          {filtered.map((r, i) => (
            <div
              key={r.captureId + r.finding.id + i}
              className="border-border/70 hover:border-border bg-card/40 rounded-sm border px-3.5 py-2.5 transition-colors"
            >
              <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                <SeverityBadge severity={r.finding.severity} />
                <span className="sms-mono text-[11px] font-semibold">{r.finding.ruleId}</span>
                <span className="text-xs font-medium">{r.finding.title}</span>
                <span className="sms-mono text-muted-foreground text-[10px]">
                  session {r.finding.sessionId}
                </span>
                <EvidenceChip
                  state={r.finding.confidenceState as never}
                  className="ml-auto hidden sm:inline-flex"
                />
              </div>
              <p className="text-muted-foreground mt-1.5 text-xs leading-relaxed">
                <span className="text-foreground/80 font-medium">Evidence </span>
                {r.finding.evidenceSummary}
              </p>
              <div className="mt-1.5 flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                <span className="text-primary text-xs">
                  <span className="sms-label text-primary/70 mr-1.5">Action</span>
                  {r.finding.recommendedAction}
                </span>
                <Link
                  to={"/captures/" + r.captureId}
                  className="sms-mono text-muted-foreground hover:text-primary shrink-0 text-[10px] transition-colors"
                >
                  {r.captureName} →
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}
    </AppShell>
  );
}
