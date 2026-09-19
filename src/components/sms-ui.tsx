import { cn } from "@/lib/utils";
import { severityClass, riskClass, riskLabel } from "@/lib/sms-format";
import { EVIDENCE_STATE_LABEL } from "@/sms/theme";
import type { Severity, RiskLevel, EvidenceState } from "@/sms/theme";
import { CountUp } from "@/components/reactbits/reactbits";

/**
 * Presentation primitives for the workstation.
 *
 * Design language:
 * - Squares and hairlines, not rounded cards and shadows.
 * - Severity encoded positionally (left tick + mono label), like log lines.
 * - Mono for data, Plex Sans for prose; annotation labels in uppercase mono.
 * - Motion limited to hover states, disclosure transitions and status pulses.
 */

/* ------------------------------------------------------------------ panels */

export function Panel({
  label,
  meta,
  actions,
  children,
  className,
  bodyClassName,
}: {
  label: string;
  meta?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("border-border/80 bg-card/40 rounded-sm border", className)}>
      <header className="border-border/80 flex min-h-10 items-center justify-between gap-3 border-b px-3.5 py-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="bg-primary/70 h-3 w-0.5 shrink-0 rounded-full" aria-hidden />
          <h2 className="sms-label text-foreground">{label}</h2>
          {meta && <span className="sms-mono text-muted-foreground truncate text-[11px]">{meta}</span>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
      </header>
      <div className={cn("p-3.5", bodyClassName)}>{children}</div>
    </section>
  );
}

/** Bare list panel: header + flush body, for tables and rows. */
export function FlushPanel({
  label,
  meta,
  actions,
  children,
  className,
  bodyClassName,
}: {
  label: string;
  meta?: string;
  actions?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  bodyClassName?: string;
}) {
  return (
    <section className={cn("border-border/80 bg-card/40 rounded-sm border", className)}>
      <header className="border-border/80 flex min-h-10 items-center justify-between gap-3 border-b px-3.5 py-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <span className="bg-primary/70 h-3 w-0.5 shrink-0 rounded-full" aria-hidden />
          <h2 className="sms-label text-foreground">{label}</h2>
          {meta && <span className="sms-mono text-muted-foreground truncate text-[11px]">{meta}</span>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-1.5">{actions}</div>}
      </header>
      <div className={cn(bodyClassName)}>{children}</div>
    </section>
  );
}

/* ------------------------------------------------------------- stat strip */

const STAT_TONE = {
  neutral: "text-foreground",
  danger: "text-(--sms-critical)",
  warning: "text-(--sms-medium)",
  good: "text-(--sms-healthy)",
  info: "text-(--sms-low)",
} as const;

export function StatStrip({
  items,
  className,
}: {
  items: Array<{
    label: string;
    value: string;
    hint?: string;
    tone?: keyof typeof STAT_TONE;
  }>;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "border-border/80 bg-card/40 grid grid-cols-2 divide-x divide-y rounded-sm border sm:grid-cols-0 sm:divide-y-0",
        className,
      )}
      style={{
        gridTemplateColumns: undefined,
      }}
    >
      {items.map((s, i) => (
        <div
          key={s.label}
          className={cn(
            "relative px-4 py-3",
            i > 0 && "sm:border-l sm:border-(--border)",
            i >= 2 && "border-t sm:border-t-0",
          )}
        >
          <div className="sms-label text-muted-foreground">{s.label}</div>
          <div
            className={cn(
              "sms-mono mt-1.5 text-xl leading-none font-semibold tabular-nums",
              STAT_TONE[s.tone ?? "neutral"],
            )}
          >
            {/^-?\d+$/.test(s.value) ? (
              <CountUp to={parseInt(s.value, 10)} duration={1.1} className="tabular-nums" />
            ) : (
              s.value
            )}
          </div>
          {s.hint && <div className="text-muted-foreground mt-1.5 text-[11px]">{s.hint}</div>}
        </div>
      ))}
    </div>
  );
}

/* ----------------------------------------------------------------- badges */

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
        "sms-mono inline-flex items-center gap-1.5 border-l-2 py-px pr-1.5 pl-1.5 text-[10px] font-semibold tracking-[0.08em] uppercase",
        severityClass(severity),
        className,
      )}
    >
      {severity}
    </span>
  );
}

/** 6px square status marker — instrumental, color-semantic. */
export function RiskDot({ level, className }: { level: RiskLevel; className?: string }) {
  const color = {
    healthy: "bg-(--sms-healthy)",
    low: "bg-(--sms-low)",
    medium: "bg-(--sms-medium)",
    high: "bg-(--sms-high)",
    critical: "bg-(--sms-critical)",
  }[level];
  return (
    <span
      title={riskLabel(level)}
      className={cn("inline-block size-1.5 shrink-0 rounded-[1px]", color, className)}
    />
  );
}

export function RiskBadge({ level, className }: { level: RiskLevel; className?: string }) {
  return (
    <span
      className={cn(
        "sms-mono inline-flex items-center gap-1.5 border-l-2 py-px pr-1.5 pl-1.5 text-[10px] font-semibold tracking-[0.08em] uppercase",
        riskClass(level),
        className,
      )}
    >
      <RiskDot level={level} className="size-1" />
      {riskLabel(level)}
    </span>
  );
}

export function EvidenceChip({
  state,
  className,
}: {
  state: EvidenceState;
  className?: string;
}) {
  return (
    <span
      title={
        state === "verified"
          ? "Read directly from the capture"
          : state === "derived"
            ? "Calculated from observed evidence"
            : state === "ai-assessed"
              ? "Produced by the ML layer"
              : state === "requires-investigation"
                ? "Suggestive, not conclusive"
                : "Not present in the capture"
      }
      className={cn(
        "sms-mono inline-flex items-center gap-1 rounded-sm border px-1.5 py-px text-[10px] tracking-[0.06em] uppercase",
        state === "verified" && "border-(--sms-healthy)/40 text-(--sms-healthy)",
        state === "requires-investigation" && "border-(--sms-medium)/40 text-(--sms-medium)",
        state === "ai-assessed" && "border-(--sms-low)/40 text-(--sms-low)",
        (state === "unavailable" || state === "derived") && "border-border text-muted-foreground",
        className,
      )}
    >
      {state === "verified" && "✓"}
      {state === "requires-investigation" && "?"}
      {state === "ai-assessed" && "◆"}
      {EVIDENCE_STATE_LABEL[state]}
    </span>
  );
}

export function CodeChip({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "sms-mono border-border/80 bg-muted/60 inline-flex items-center rounded-sm border px-1.5 py-px text-[11px]",
        className,
      )}
    >
      {children}
    </span>
  );
}

/* ------------------------------------------------------------ status dots */

/** Live status indicator; pulses while `active`. */
export function StatusDot({
  active,
  tone = "info",
  className,
}: {
  active?: boolean;
  tone?: "info" | "good" | "warning" | "danger";
  className?: string;
}) {
  const color = {
    info: "bg-(--sms-low)",
    good: "bg-(--sms-healthy)",
    warning: "bg-(--sms-medium)",
    danger: "bg-(--sms-critical)",
  }[tone];
  return (
    <span className={cn("relative inline-flex size-2", className)}>
      <span className={cn("absolute inset-0 rounded-full", color)} />
      {active && (
        <span className={cn("absolute inset-0 animate-ping rounded-full opacity-40", color)} />
      )}
    </span>
  );
}

/* ------------------------------------------------------------------ meter */

export function Meter({
  value,
  tone = "info",
  className,
}: {
  value: number;
  tone?: "info" | "good" | "warning" | "danger";
  className?: string;
}) {
  const color = {
    info: "bg-(--sms-low)",
    good: "bg-(--sms-healthy)",
    warning: "bg-(--sms-medium)",
    danger: "bg-(--sms-critical)",
  }[tone];
  return (
    <div className={cn("bg-muted h-1 w-full overflow-hidden rounded-[1px]", className)}>
      <div
        className={cn("h-full transition-[width] duration-500 ease-out", color)}
        style={{ width: Math.max(0, Math.min(100, value)) + "%" }}
      />
    </div>
  );
}

/* -------------------------------------------------------------- key-value */

export function KeyValue({
  rows,
  className,
}: {
  rows: Array<{ k: string; v: React.ReactNode; state?: EvidenceState }>;
  className?: string;
}) {
  return (
    <dl className={cn("divide-border/60 divide-y", className)}>
      {rows.map((r) => (
        <div key={r.k} className="flex items-baseline justify-between gap-4 py-1.5">
          <dt className="sms-label text-muted-foreground shrink-0">{r.k}</dt>
          <dd className="sms-mono min-w-0 truncate text-right text-xs" title={typeof r.v === "string" ? r.v : undefined}>
            {r.v}
            {r.state && (
              <span className="ml-2 inline-block align-middle">
                <EvidenceChip state={r.state} />
              </span>
            )}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/* ------------------------------------------------------------- disclosure */

export function Disclosure({
  id,
  title,
  meta,
  chip,
  children,
  defaultOpen = false,
}: {
  id: string;
  title: React.ReactNode;
  meta?: React.ReactNode;
  chip?: React.ReactNode;
  children: React.ReactNode;
  defaultOpen?: boolean;
}) {
  return (
    <details
      open={defaultOpen}
      className={cn(
        "group border-border/70 hover:border-border rounded-sm border transition-colors",
        "open:bg-muted/20",
      )}
    >
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2.5">
        <span className="flex min-w-0 items-center gap-2">
          <svg
            viewBox="0 0 8 8"
            className="text-muted-foreground size-2 shrink-0 transition-transform duration-200 group-open:rotate-90"
            aria-hidden
          >
            <path d="M2 1l4 3-4 3z" fill="currentColor" />
          </svg>
          <span className="sms-mono text-muted-foreground shrink-0 text-[11px]">{id}</span>
          <span className="truncate text-xs font-medium">{title}</span>
        </span>
        <span className="flex shrink-0 items-center gap-2">
          {meta && <span className="text-muted-foreground hidden truncate text-[11px] sm:block">{meta}</span>}
          {chip}
        </span>
      </summary>
      <div className="border-border/50 border-t px-3 py-2.5">{children}</div>
    </details>
  );
}

/* ------------------------------------------------------------ pipeline flow */

/** State of one analysis stage in the connected flow. */
export type FlowState = "done" | "active" | "pending" | "warning";

/**
 * Horizontal connected pipeline: small technical icon boxes joined by thin
 * amber connectors — the workstation's visual summary of the analysis chain.
 * Icons come from the caller; state styling is deterministic.
 */
export function PipelineFlow({
  stages,
  className,
}: {
  stages: Array<{ id: string; label: string; icon?: React.ReactNode; state?: FlowState }>;
  className?: string;
}) {
  const nodes: React.ReactNode[] = [];
  stages.forEach((s, i) => {
    if (i > 0) {
      nodes.push(
        <svg
          key={"c-" + s.id}
          viewBox="0 0 10 10"
          className="text-(--sms-wave)/50 mx-0.5 size-2 shrink-0 self-center"
          aria-hidden
        >
          <path d="M2 1.5 6.5 5 2 8.5" stroke="currentColor" strokeWidth="1.4" fill="none" strokeLinecap="round" strokeLinejoin="round" />
        </svg>,
      );
    }
    const state = s.state ?? "pending";
    nodes.push(
      <div key={s.id} className="flex min-w-[72px] flex-1 flex-col items-center gap-1.5">
        <span
          className={cn(
            "flex size-8 items-center justify-center rounded-[3px] border transition-colors duration-300",
            state === "done" &&
              "border-(--sms-healthy)/35 bg-(--sms-healthy)/8 text-(--sms-healthy)",
            state === "active" &&
              "border-(--sms-wave)/55 bg-(--sms-wave)/10 text-primary",
            state === "warning" &&
              "border-(--sms-medium)/50 bg-(--sms-medium)/10 text-(--sms-medium)",
            state === "pending" && "border-border text-muted-foreground/50",
          )}
        >
          {s.icon}
        </span>
        <span
          className={cn(
            "sms-mono max-w-[92px] text-center text-[9px] leading-tight",
            state === "pending" ? "text-muted-foreground/50" : "text-muted-foreground",
          )}
        >
          {s.label}
        </span>
      </div>,
    );
  });
  return <div className={cn("flex items-start", className)}>{nodes}</div>;
}

/* --------------------------------------------------------- pipeline stage */

/** Vertical stage list used while a capture is being analyzed. */
export function StageProgress({
  stages,
  activeIndex,
  className,
}: {
  stages: Array<{ id: string; label: string }>;
  activeIndex: number;
  className?: string;
}) {
  return (
    <ol className={cn("space-y-0", className)}>
      {stages.map((s, i) => {
        const done = i < activeIndex;
        const active = i === activeIndex;
        return (
          <li key={s.id} className="flex items-center gap-2.5 py-1">
            <span
              className={cn(
                "flex size-3.5 shrink-0 items-center justify-center rounded-[2px] border text-[8px] leading-none",
                done && "border-(--sms-healthy)/50 bg-(--sms-healthy)/15 text-(--sms-healthy)",
                active && "border-primary/60 bg-primary/10",
                !done && !active && "border-border text-transparent",
              )}
            >
              {done && "✓"}
            </span>
            <span
              className={cn(
                "text-xs transition-colors",
                done && "text-muted-foreground",
                active && "text-foreground font-medium",
                !done && !active && "text-muted-foreground/60",
              )}
            >
              {s.label}
            </span>
            {active && (
              <span className="sms-mono text-muted-foreground ml-auto text-[10px]">running</span>
            )}
          </li>
        );
      })}
    </ol>
  );
}
