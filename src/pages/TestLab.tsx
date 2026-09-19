import { useState } from "react";
import { AppShell } from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { FlushPanel, Panel, StatStrip, StatusDot } from "@/components/sms-ui";
import { aggregateTestLab, runScenario, SCENARIOS } from "@/sms/scenarios";
import type { TestLabReport } from "@/sms/scenarios";
import { cn } from "@/lib/utils";
import { Loader2, Play } from "lucide-react";

const RISK_TEXT = {
  healthy: "text-(--sms-healthy)",
  low: "text-(--sms-low)",
  medium: "text-(--sms-medium)",
  high: "text-(--sms-high)",
  critical: "text-(--sms-critical)",
} as const;

/**
 * Test Lab: generates real PCAP bytes for each labeled scenario and runs the
 * production pipeline over them. Detection numbers are measured from pipeline
 * output (expected vs detected rule IDs), never asserted.
 */
export default function TestLab() {
  const [running, setRunning] = useState(false);
  const [current, setCurrent] = useState<string | null>(null);
  const [report, setReport] = useState<TestLabReport | null>(null);

  const runAll = async () => {
    setRunning(true);
    setReport(null);
    setCurrent(null);
    const results = [];
    for (let i = 0; i < SCENARIOS.length; i++) {
      setCurrent(SCENARIOS[i].id);
      const r = await runScenario(SCENARIOS[i]);
      results.push(r);
    }
    setReport(aggregateTestLab(results));
    setCurrent(null);
    setRunning(false);
  };

  return (
    <AppShell
      title="Test Lab"
      subtitle="Self-evaluation: labeled scenarios through the production pipeline, results measured — not asserted"
      actions={
        <Button size="sm" className="gap-2" disabled={running} onClick={runAll}>
          {running ? <Loader2 className="size-3.5 animate-spin" /> : <Play className="size-3.5" />}
          Run all scenarios
        </Button>
      }
    >
      <Panel
        label="Scenario suite"
        meta={SCENARIOS.length + " labeled captures"}
        actions={
          running && current ? (
            <span className="sms-mono text-primary flex items-center gap-1.5 text-[10px]">
              <StatusDot active tone="info" />
              {current}
            </span>
          ) : undefined
        }
      >
        <p className="text-muted-foreground mb-4 text-xs leading-relaxed">
          Each scenario builds a real PCAP with known cryptographic properties — expired
          certificates, deprecated TLS versions, weak ciphers, failed STARTTLS upgrades, plaintext
          sessions — then runs the identical pipeline used for uploaded captures. The table reports
          which rule IDs fired compared with the declared expectation for each capture.
        </p>

        {report && (
          <>
            <StatStrip
              className="mb-4"
              items={[
                {
                  label: "Completed",
                  value: report.completed + "/" + report.scenarios,
                  tone: report.completed === report.scenarios ? "good" : "warning",
                },
                {
                  label: "Expected detected",
                  value:
                    report.expectedFindings === 0
                      ? "—"
                      : report.detectedFindings + "/" + report.expectedFindings,
                  tone: report.missed === 0 ? "good" : "warning",
                },
                { label: "Missed", value: String(report.missed), tone: report.missed === 0 ? "good" : "danger" },
                {
                  label: "Extra fires",
                  value: String(report.falsePositives),
                  tone: report.falsePositives === 0 ? "good" : "warning",
                  hint: "Reviewed; mixed scenarios legitimately trigger one rule per weakness",
                },
              ]}
            />

            <FlushPanel label="Measured results" bodyClassName="overflow-x-auto">
              <table className="w-full min-w-[760px] text-sm">
                <thead>
                  <tr className="border-border/80 bg-muted/30 border-b">
                    <th className="sms-label text-muted-foreground px-3 py-2 text-left">Scenario</th>
                    <th className="sms-label text-muted-foreground px-3 py-2 text-left">Expected</th>
                    <th className="sms-label text-muted-foreground px-3 py-2 text-left">Detected</th>
                    <th className="sms-label text-muted-foreground px-3 py-2 text-left">Risk</th>
                    <th className="sms-label text-muted-foreground px-3 py-2 text-left">Result</th>
                  </tr>
                </thead>
                <tbody className="divide-border/70 divide-y">
                  {report.rows.map((row) => {
                    const clean =
                      row.error === null &&
                      row.missed.length === 0 &&
                      (row.riskMatches === null || row.riskMatches);
                    return (
                      <tr key={row.id} className="align-top">
                        <td className="px-3 py-2.5">
                          <div className="text-xs font-medium">{row.label}</div>
                          <div className="sms-mono text-muted-foreground text-[10px]">{row.id}</div>
                        </td>
                        <td className="sms-mono text-muted-foreground px-3 py-2.5 text-[11px]">
                          {SCENARIOS.find((s) => s.id === row.id)?.expectedFindings.join(", ") ||
                            "none"}
                        </td>
                        <td className="sms-mono px-3 py-2.5 text-[11px]">
                          {row.detected.length > 0 ? (
                            <span className="text-(--sms-healthy)">{row.detected.join(", ")}</span>
                          ) : (
                            <span className="text-muted-foreground">none</span>
                          )}
                          {row.extra.length > 0 && (
                            <div className="text-(--sms-low) mt-0.5">+{row.extra.join(", ")}</div>
                          )}
                        </td>
                        <td className="sms-mono px-3 py-2.5 text-[11px]">
                          <span className={RISK_TEXT[row.riskLevel as keyof typeof RISK_TEXT] ?? ""}>
                            {row.riskLevel ?? "—"}
                          </span>
                          {row.riskMatches === false && (
                            <span className="text-(--sms-medium)"> ≠ expected</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5">
                          {row.error ? (
                            <span className="sms-mono text-(--sms-critical) text-[10px]">
                              error
                            </span>
                          ) : clean ? (
                            <span className="sms-mono text-(--sms-healthy) text-[10px] tracking-[0.08em] uppercase">
                              pass
                            </span>
                          ) : (
                            <span className="sms-mono text-(--sms-medium) text-[10px] tracking-[0.08em] uppercase">
                              review
                            </span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </FlushPanel>

            <p className="text-muted-foreground mt-3 text-[11px] leading-relaxed">
              "Extra fires" are expected in mixed scenarios: a capture combining several
              misconfigurations legitimately triggers one rule per weakness. The measurement
              distinguishes missed detections (a real gap) from extras (a superset of expected
              evidence).
            </p>
          </>
        )}

        {!report && !running && (
          <div className="border-border/70 text-muted-foreground rounded-sm border border-dashed px-6 py-10 text-center text-xs">
            Run the suite to generate scenario captures and measure detection coverage against
            declared expectations.
          </div>
        )}
      </Panel>

      <div className="mt-4 grid gap-2 md:grid-cols-2 xl:grid-cols-3">
        {SCENARIOS.map((s, i) => (
          <div
            key={s.id}
            className={cn(
              "border-border/70 bg-card/40 rounded-sm border px-3.5 py-2.5 transition-colors",
              running && current === s.id && "border-primary/50",
            )}
          >
            <div className="flex items-center gap-2">
              <span className="sms-mono text-muted-foreground/70 text-[10px]">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className="text-xs font-semibold">{s.label}</span>
              {running && current === s.id && <StatusDot active tone="info" className="ml-auto" />}
            </div>
            <p className="text-muted-foreground mt-1 text-[11px] leading-snug">{s.description}</p>
            <div className="sms-mono text-muted-foreground mt-1.5 text-[10px]">
              expected:{" "}
              <span className="text-foreground/80">
                {s.expectedFindings.length > 0 ? s.expectedFindings.join(", ") : "no findings"}
              </span>{" "}
              · risk:{" "}
              <span className={RISK_TEXT[s.expectedRisk as keyof typeof RISK_TEXT]}>
                {s.expectedRisk}
              </span>
            </div>
          </div>
        ))}
      </div>
    </AppShell>
  );
}
