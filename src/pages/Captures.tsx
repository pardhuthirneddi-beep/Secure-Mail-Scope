import { useQuery } from "convex/react";
import { api } from "@/convex/_generated/api";
import { AppShell } from "@/components/AppShell";
import { CaptureMetaLine, RiskBadge } from "@/components/sms-ui";
import { Button } from "@/components/ui/button";
import { formatBytes } from "@/lib/sms-format";
import { FileUp } from "lucide-react";
import { useNavigate } from "react-router";

export default function Captures() {
  const captures = useQuery(api.captures.listCaptures, {}) ?? [];
  const navigate = useNavigate();

  return (
    <AppShell
      title="Captures"
      subtitle="Every PCAP analyzed in this workspace, with its evidence-linked findings"
      actions={
        <Button size="sm" className="gap-2" onClick={() => navigate("/dashboard")}>
          <FileUp className="size-4" />
          New analysis
        </Button>
      }
    >
      {captures.length === 0 ? (
        <div className="border-border/70 text-muted-foreground rounded-md border border-dashed px-6 py-12 text-center text-sm">
          No captures yet. Upload a .pcap or run a demo capture from the Overview page to begin.
        </div>
      ) : (
        <div className="border-border/70 overflow-hidden rounded-md border">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-card/60 border-border/70 border-b text-left">
                <th className="text-muted-foreground px-4 py-2.5 text-[11px] font-medium uppercase tracking-wider">
                  Capture
                </th>
                <th className="text-muted-foreground hidden px-4 py-2.5 text-[11px] font-medium uppercase tracking-wider md:table-cell">
                  Size
                </th>
                <th className="text-muted-foreground px-4 py-2.5 text-[11px] font-medium uppercase tracking-wider">
                  Sessions
                </th>
                <th className="text-muted-foreground px-4 py-2.5 text-[11px] font-medium uppercase tracking-wider">
                  Findings
                </th>
                <th className="text-muted-foreground px-4 py-2.5 text-[11px] font-medium uppercase tracking-wider">
                  Worst risk
                </th>
              </tr>
            </thead>
            <tbody className="divide-border/70 divide-y">
              {captures.map((c) => (
                <tr
                  key={c._id}
                  className="hover:bg-accent/40 cursor-pointer transition-colors"
                  onClick={() => navigate("/captures/" + c._id)}
                >
                  <td className="max-w-[280px] px-4 py-2.5">
                    <div className="sms-mono flex items-center gap-2 truncate text-xs font-medium">
                      {c.isDemo && (
                        <span className="text-[--sms-medium] shrink-0 rounded-sm border border-[--sms-medium]/40 px-1 py-px text-[9px] uppercase">
                          demo
                        </span>
                      )}
                      <span className="truncate">{c.name}</span>
                    </div>
                    <div className="md:hidden mt-0.5">
                      <CaptureMetaLine
                        sizeBytes={c.sizeBytes}
                        packetCount={c.packetCount}
                        durationSec={c.durationSec}
                      />
                    </div>
                  </td>
                  <td className="text-muted-foreground sms-mono hidden px-4 py-2.5 text-xs md:table-cell">
                    {formatBytes(c.sizeBytes)}
                  </td>
                  <td className="sms-mono px-4 py-2.5 text-xs tabular-nums">{c.sessionCount}</td>
                  <td className="sms-mono px-4 py-2.5 text-xs tabular-nums">{c.findingCount}</td>
                  <td className="px-4 py-2.5">
                    <RiskBadge level={c.maxRisk as never} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </AppShell>
  );
}
