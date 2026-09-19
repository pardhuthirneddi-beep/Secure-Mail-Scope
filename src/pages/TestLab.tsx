import { useState } from "react";
import { AppShell } from "@/components/AppShell";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { StatTile } from "@/components/sms-ui";
import { aggregateTestLab, runScenario, SCENARIOS } from "@/sms/scenarios";
import type { TestLabReport } from "@/sms/scenarios";
import { cn } from "@/lib/utils";
import { CheckCircle2, FlaskConical, Loader2, Play, XCircle } from "lucide-react";

/**
 * Test Lab: generates real PCAP bytes for each labeled scenario and runs the
 * production pipeline over them. Detection numbers are measured from pipeline
 * output (expected vs detected rule IDs), never asserted.
 */
export default function TestLab() {
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [report, setReport] = useState<TestLabReport | null>(null);

  const runAll = async () => {
    setRunning(true);
    setReport(null);
    setProgress(0);
    const results = [];
    for (let i = 0; i < SCENARIOS.length; i++) {
      const r = await runScenario(SCENARIOS[i]);
      results.push(r);
      setProgress(Math.round(((i + 1) / SCENARIOS.length) * 100));
    }
    setReport(aggregateTestLab(results));
    setRunning(false);
  };

  return (
    <AppShell
      title="Test Lab"
      subtitle="Self-evaluation: labeled scenarios run through the production pipeline, results measured — not asserted"
      actions={
        <Button size="sm" className="gap-2" disabled={running} onClick={runAll}>
          {running ? <Loader2 className="size-4 animate-spin" /> : <Play className="size-4" />}
          Run all scenarios
        </Button>
      }
    >
      <Card className="border-border/70 shadow-none">
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-sm">
            <FlaskConical className="text-primary size-4" />
            Scenario suite ({SCENARIOS.length} labeled captures)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground mb-4 text-xs leading-relaxed">
            Each scenario builds a real PCAP with known cryptographic properties — expired
            certificates, deprecated TLS versions, weak ciphers, failed STARTTLS upgrades, plaintext
            sessions — then runs the identical pipeline used for uploaded captures. The table below
            reports which rule IDs fired compared with the declared expectation for each capture.
          </p>

          {running && <Progress value={progress} className="mb-4 h-1.5" />}

          {report && (
            <>
              <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                <StatTile
                  label="Scenarios completed"
                  value={report.completed + "/" + report.scenarios}
                  tone={report.completed === report.scenarios ? "good" : "warning"}
                />
                <StatTile
                  label="Expected findings detected"
                  value={
                    report.expectedFindings === 0
                      ? "—"
                      : report.detectedFindings + "/" + report.expectedFindings
                  }
                  tone={report.missed === 0 ? "good" : "warning"}
                />
                <StatTile
                  label="Missed"
                  value={String(report.missed)}
                  tone={report.missed === 0 ? "good" : "danger"}
                />
                <StatTile
                  label="Unexpected rule fires"
                  value={String(report.falsePositives)}
                  tone={report.falsePositives === 0 ? "good" : "warning"}
                  hint="Extras are reviewed; some scenarios legitimately trigger additional rules"
                />
              </div>

              <div className="border-border/70 overflow-x-auto rounded-md border">
                <table className="w-full min-w-[720px] text-sm">
                  <thead>
                    <tr className="bg-card/60 border-border/70 border-b text-left">
                      <th className="text-muted-foreground px-3 py-2 text-[11px] font-medium uppercase tracking-wider">
                        Scenario
                      </th>
                      <th className="text-muted-foreground px-3 py-2 text-[11px] font-medium uppercase tracking-wider">
                        Expected
                      </th>
                      <th className="text-muted-foreground px-3 py-2 text-[11px] font-medium uppercase tracking-wider">
                        Detected
                      </th>
                      <th className="text-muted-foreground px-3 py-2 text-[11px] font-medium uppercase tracking-wider">
                        Risk
                      </th>
                      <th className="text-muted-foreground px-3 py-2 text-[11px] font-medium uppercase tracking-wider">
                        Result
                      </th>
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
                            <div className="sms-mono text-muted-foreground text-[11px]">
                              {row.id}
                            </div>
                          </td>
                          <td className="sms-mono text-muted-foreground px-3 py-2.5 text-[11px]">
                            {SCENARIOS.find((s) => s.id === row.id)?.expectedFindings.join(", ") ||
                              "none"}
                          </td>
                          <td className="sms-mono px-3 py-2.5 text-[11px]">
                            {row.detected.length > 0 ? (
                              <span className="text-[--sms-healthy]">{row.detected.join(", ")}</span>
                            ) : (
                              <span className="text-muted-foreground">none</span>
                            )}
                            {row.extra.length > 0 && (
                              <div className="text-[--sms-low] mt-0.5">
                                +{row.extra.join(", ")}
                              </div>
                            )}
                          </td>
                          <td className="sms-mono px-3 py-2.5 text-[11px]">
                            {row.riskLevel ?? "—"}
                            {row.riskMatches === false && (
                              <span className="text-[--sms-medium]"> (mismatch)</span>
                            )}
                          </td>
                          <td className="px-3 py-2.5">
                            {row.error ? (
                              <span className="text-[--sms-critical] flex items-center gap-1 text-xs">
                                <XCircle className="size-3.5" />
                                {row.error.slice(0, 60)}
                              </span>
                            ) : clean ? (
                              <span className="text-[--sms-healthy] flex items-center gap-1 text-xs">
                                <CheckCircle2 className="size-3.5" />
                                Pass
                              </span>
                            ) : (
                              <span className="text-[--sms-medium] flex items-center gap-1 text-xs">
                                <XCircle className="size-3.5" />
                                Review
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <p className="text-muted-foreground mt-3 text-[11px] leading-relaxed">
                "Unexpected rule fires" are expected in mixed scenarios: a capture combining several
                misconfigurations legitimately triggers one rule per weakness. The measurement
                distinguishes missed detections (a real gap) from extras (a superset of expected
                evidence).
              </p>
            </>
          )}

          {!report && !running && (
            <div className="border-border/70 text-muted-foreground rounded-sm border border-dashed px-6 py-10 text-center text-sm">
              Run the suite to generate scenario captures and measure detection coverage against
              declared expectations.
            </div>
          )}
        </CardContent>
      </Card>

      <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {SCENARIOS.map((s) => (
          <div key={s.id} className="border-border/70 bg-card/40 rounded-md border px-4 py-3">
            <div className="text-xs font-semibold">{s.label}</div>
            <p className="text-muted-foreground mt-1 text-[11px] leading-snug">{s.description}</p>
            <div className="sms-mono text-muted-foreground mt-2 text-[10px]">
              expected: {s.expectedFindings.length > 0 ? s.expectedFindings.join(", ") : "no findings"} · risk:{" "}
              <span
                className={cn(
                  s.expectedRisk === "critical" || s.expectedRisk === "high"
                    ? "text-[--sms-critical]"
                    : s.expectedRisk === "medium"
                      ? "text-[--sms-medium]"
                      : "text-[--sms-healthy]",
                )}
              >
                {s.expectedRisk}
              </span>
            </div>
          </div>
        ))}
      </div>
    </AppShell>
  );
}
