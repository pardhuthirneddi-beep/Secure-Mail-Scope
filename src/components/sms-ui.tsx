import { cn } from "@/lib/utils";
import {
  severityClass,
  riskClass,
  riskLabel,
  formatBytes,
  formatDuration,
} from "@/lib/sms-format";
import { EVIDENCE_STATE_LABEL } from "@/sms/theme";
import type { Severity, RiskLevel, EvidenceState } from "@/sms/theme";
import { Badge } from "@/components/ui/badge";

/**
 * Small shared presentation primitives for the workstation UI.
 * Severity colors are semantic: red = critical/high, amber = medium,
 * cyan = informational, green = verified healthy. Nothing decorative.
 */

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "sms-mono inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
        severityClass(severity),
        className,
      )}
    >
      {severity}
    </span>
  );
}

export function RiskBadge({
  level,
  className,
}: {
  level: RiskLevel;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "sms-mono inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider",
        riskClass(level),
        className,
      )}
    >
      {riskLabel(level)}
    </span>
  );
}

export function EvidenceStateChip({
  state,
  className,
}: {
  state: EvidenceState;
  className?: string;
}) {
  return (
    <Badge
      variant="outline"
      className={cn(
        "sms-mono h-5 rounded-sm px-1.5 text-[10px] uppercase tracking-wider",
        state === "verified" && "border-[--sms-healthy]/40 text-[--sms-healthy]",
        state === "requires-investigation" && "border-[--sms-medium]/40 text-[--sms-medium]",
        state === "ai-assessed" && "border-[--sms-low]/40 text-[--sms-low]",
        (state === "unavailable" || state === "derived") && "text-muted-foreground",
        className,
      )}
    >
      {EVIDENCE_STATE_LABEL[state]}
    </Badge>
  );
}

export function StatTile({
  label,
  value,
  hint,
  tone = "neutral",
  className,
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: "neutral" | "danger" | "warning" | "good" | "info";
  className?: string;
}) {
  const toneClass = {
    neutral: "text-foreground",
    danger: "text-[--sms-critical]",
    warning: "text-[--sms-medium]",
    good: "text-[--sms-healthy]",
    info: "text-[--sms-low]",
  }[tone];
  return (
    <div
      className={cn(
        "border-border/70 bg-card/60 rounded-md border px-4 py-3",
        className,
      )}
    >
      <div className="text-muted-foreground text-[11px] font-medium uppercase tracking-wider">
        {label}
      </div>
      <div className={cn("sms-mono mt-1 text-2xl font-semibold tabular-nums", toneClass)}>
        {value}
      </div>
      {hint && <div className="text-muted-foreground mt-0.5 text-xs">{hint}</div>}
    </div>
  );
}

export function CaptureMetaLine({
  sizeBytes,
  packetCount,
  durationSec,
  className,
}: {
  sizeBytes: number;
  packetCount: number;
  durationSec: number;
  className?: string;
}) {
  return (
    <span className={cn("sms-mono text-muted-foreground text-xs", className)}>
      {formatBytes(sizeBytes)} · {packetCount} packets · {formatDuration(durationSec)}
    </span>
  );
}
