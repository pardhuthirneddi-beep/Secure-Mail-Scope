import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import { FlushPanel, RiskDot } from "@/components/sms-ui";
import { Button } from "@/components/ui/button";
import { formatBytes, formatDuration } from "@/lib/sms-format";
import { cn } from "@/lib/utils";
import { FileUp } from "lucide-react";
import { useNavigate } from "react-router";

const RISK_DOT_TONE = {
  healthy: "bg-(--sms-healthy)",
  low: "bg-(--sms-low)",
  medium: "bg-(--sms-medium)",
  high: "bg-(--sms-high)",
  critical: "bg-(--sms-critical)",
} as const;

export default function Captures() {
  const captures = useQuery(api.captures.listCaptures, {}) ?? [];
  const navigate = useNavigate();

  return (
    <AppShell
      title="Captures"
      subtitle="Every PCAP analyzed in this workspace, with its evidence-linked findings"
      actions={
        <Button size="sm" className="gap-2" onClick={() => navigate("/dashboard")}>
          <FileUp className="size-3.5" />
          New analysis
        </Button>
      }
    >
      {captures.length === 0 ? (
        <div className="border-border/70 text-muted-foreground rounded-sm border border-dashed px-6 py-14 text-center text-sm">
          No captures yet. Upload a .pcap or run a reference capture from the Overview page.
          <div className="mt-3">
            <Button size="sm" onClick={() => navigate("/dashboard")}>
              Go to Overview
            </Button>
          </div>
        </div>
      ) : (
        <FlushPanel label="Capture register" meta={captures.length + " records"} bodyClassName="overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <thead>
              <tr className="border-border/80 bg-muted/30 border-b">
                <th className="sms-label text-muted-foreground px-3.5 py-2 text-left">Capture</th>
                <th className="sms-label text-muted-foreground hidden px-3.5 py-2 text-left md:table-cell">
                  Size
                </th>
                <th className="sms-label text-muted-foreground px-3.5 py-2 text-left">Sessions</th>
                <th className="sms-label text-muted-foreground px-3.5 py-2 text-left">Findings</th>
                <th className="sms-label text-muted-foreground px-3.5 py-2 text-left">Captured</th>
                <th className="sms-label text-muted-foreground px-3.5 py-2 text-left">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-border/70 divide-y">
              {captures.map((c) => (
                <tr
                  key={c._id}
                  className="group cursor-pointer transition-colors hover:bg-accent/40"
                  onClick={() => navigate("/captures/" + c._id)}
                >
                  <td className="max-w-[280px] px-3.5 py-2.5">
                    <div className="sms-mono flex items-center gap-2 truncate text-xs font-medium">
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
                      <span className="sms-mono text-muted-foreground/0 group-hover:text-primary shrink-0 text-[10px] transition-colors">
                        open →
                      </span>
                    </div>
                    <div className="sms-mono text-muted-foreground mt-0.5 text-[10px] md:hidden">
                      {formatBytes(c.sizeBytes)} · {formatDuration(c.durationSec)}
                    </div>
                  </td>
                  <td className="sms-mono text-muted-foreground hidden px-3.5 py-2.5 text-xs tabular-nums md:table-cell">
                    {formatBytes(c.sizeBytes)}
                  </td>
                  <td className="sms-mono px-3.5 py-2.5 text-xs tabular-nums">{c.sessionCount}</td>
                  <td className="sms-mono px-3.5 py-2.5 text-xs tabular-nums">{c.findingCount}</td>
                  <td className="sms-mono text-muted-foreground hidden px-3.5 py-2.5 text-[11px] md:table-cell">
                    {formatDuration(c.durationSec)}
                  </td>
                  <td className="px-3.5 py-2.5">
                    <span className="sms-mono text-[10px] tracking-[0.08em] uppercase">
                      {String(c.maxRisk)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </FlushPanel>
      )}
    </AppShell>
  );
}
