import { useMemo, useState } from "react";
import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import { EvidenceStateChip, SeverityBadge } from "@/components/sms-ui";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { parseCapturePayload } from "@/lib/sms-format";
import { cn } from "@/lib/utils";
import type { Finding } from "@/sms/types";
import type { Severity } from "@/sms/theme";
import { SEVERITY_ORDER } from "@/sms/theme";
import { Loader2 } from "lucide-react";
import { Link } from "react-router";

interface Row {
  finding: Finding;
  captureId: string;
  captureName: string;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

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
    out.sort((a, b) => SEVERITY_ORDER[b.finding.severity] - SEVERITY_ORDER[a.finding.severity]);
    return out;
  }, [captures]);

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

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of SEVERITIES) c[s] = 0;
    for (const r of rows) c[r.finding.severity]++;
    return c;
  }, [rows]);

  return (
    <AppShell
      title="Findings"
      subtitle="Every deterministic and ML-assisted finding across your captures, with its evidence"
    >
      <div className="mb-4 flex flex-col gap-2 sm:flex-row sm:items-center">
        <Input
          placeholder="Search findings, rule IDs, evidence…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="sms-mono h-9 max-w-sm text-xs"
        />
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger className="h-9 w-40 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s.charAt(0).toUpperCase() + s.slice(1)} ({counts[s] ?? 0})
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {captures.length === 0 ? (
        <div className="border-border/70 text-muted-foreground rounded-md border border-dashed px-6 py-12 text-center text-sm">
          Analyze a capture first — findings from every capture are collected here.
        </div>
      ) : filtered.length === 0 ? (
        <div className="border-border/70 text-muted-foreground rounded-md border border-dashed px-6 py-12 text-center text-sm">
          {rows.length === 0
            ? "No findings across your captures — every analyzed session passed the deterministic rule set."
            : "No findings match the current filter."}
        </div>
      ) : (
        <div className="space-y-2">
          {filtered.map((r, i) => (
            <div
              key={r.captureId + r.finding.id + i}
              className={cn(
                "border-border/70 bg-card/40 rounded-sm border px-4 py-3",
              )}
            >
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={r.finding.severity} />
                <span className="sms-mono text-xs font-medium">{r.finding.ruleId}</span>
                <span className="text-sm font-medium">{r.finding.title}</span>
                <span className="text-muted-foreground sms-mono text-[11px]">
                  session {r.finding.sessionId}
                </span>
                <EvidenceStateChip state={r.finding.confidenceState as never} className="ml-auto" />
              </div>
              <p className="text-muted-foreground mt-1.5 text-xs">
                <span className="text-foreground font-medium">Evidence:</span>{" "}
                {r.finding.evidenceSummary}
              </p>
              <p className="text-muted-foreground mt-1 text-xs">{r.finding.whyItMatters}</p>
              <div className="mt-2 flex items-center justify-between gap-2">
                <span className="text-primary text-xs">
                  <span className="font-medium">Action:</span> {r.finding.recommendedAction}
                </span>
                <Link
                  to={"/captures/" + r.captureId}
                  className="text-muted-foreground hover:text-foreground shrink-0 text-[11px] underline"
                >
                  {r.captureName}
                </Link>
              </div>
            </div>
          ))}
        </div>
      )}
      {captures === undefined && (
        <Loader2 className="text-muted-foreground mx-auto mt-10 size-5 animate-spin" />
      )}
    </AppShell>
  );
}
