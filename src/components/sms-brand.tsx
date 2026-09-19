import { cn } from "@/lib/utils";

/**
 * SecureMailScope identity elements.
 *
 * The brand mark is a drawn mail envelope whose flap reads as a magnifier
 * handle — mail plus evidence inspection in one line icon. Warm white with a
 * single amber accent. The wave motif renders thin amber signal traces that
 * drift almost imperceptibly, suggesting traffic flowing through the pipeline;
 * it is always decorative-but-thematic, never the focus, and disabled under
 * prefers-reduced-motion via the CSS animation gate.
 */

export function BrandMark({
  size = 28,
  className,
}: {
  size?: number;
  className?: string;
}) {
  return (
    <span
      aria-hidden
      style={{ width: size, height: size }}
      className={cn(
        "border-(--sms-wave)/45 bg-(--sms-wave)/8 text-foreground/90 relative inline-flex shrink-0 items-center justify-center rounded-[3px] border",
        className,
      )}
    >
      <svg viewBox="0 0 24 24" width={size * 0.62} height={size * 0.62} fill="none">
        {/* envelope body */}
        <rect x="3" y="5.5" width="18" height="13" rx="1.2" stroke="currentColor" strokeWidth="1.5" />
        {/* envelope flap, extended into a scope handle */}
        <path
          d="M3.5 6.5 12 13l8.5-6.5"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
        {/* scope lens on the flap fold — the amber accent */}
        <circle cx="12" cy="12.6" r="2.1" stroke="var(--sms-wave)" strokeWidth="1.5" />
        <path
          d="M13.6 14.2 15.6 16.2"
          stroke="var(--sms-wave)"
          strokeWidth="1.5"
          strokeLinecap="round"
        />
      </svg>
    </span>
  );
}

/** Wordmark: warm white "SecureMail", amber "Scope". */
export function BrandWordmark({
  compact = false,
  className,
}: {
  compact?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("leading-tight select-none", className)}>
      <div
        className={cn(
          "font-semibold tracking-tight text-foreground",
          compact ? "text-[13px]" : "text-base",
        )}
      >
        SecureMail<span className="text-primary">Scope</span>
      </div>
      {!compact && (
        <div className="sms-mono text-muted-foreground mt-0.5 text-[9px] tracking-[0.14em] uppercase">
          Cryptographic Security Posture Assessment
        </div>
      )}
    </div>
  );
}

/**
 * Forensic wave lines — the product's visual signature. Several thin amber
 * curves at very low opacity, drawn as a repeating SVG strip so the CSS drift
 * animation can loop it seamlessly. `tone` picks the opacity band; `height`
 * the strip height. Purely ambient: no pointer events, aria-hidden.
 */
export function ForensicWaves({
  className,
  height = 96,
  tone = "mid",
  drift = true,
}: {
  className?: string;
  height?: number;
  tone?: "strong" | "mid" | "soft";
  drift?: boolean;
}) {
  const stroke = {
    strong: "var(--sms-wave-strong)",
    mid: "var(--sms-wave-mid)",
    soft: "var(--sms-wave-soft)",
  }[tone];

  // One tile of the repeating pattern; two copies render back to back so the
  // -50% drift loops without a visible seam. Shapes suggest packet signal
  // traces: mostly flat runs interrupted by protocol-burst spikes and decaying
  // handshakes — not ocean waves.
  const tile = (
    <svg
      viewBox="0 0 1200 96"
      preserveAspectRatio="none"
      className="h-full w-1/2 shrink-0"
      fill="none"
    >
      <path
        d="M0 64 H60 L70 40 L80 64 H180 L190 52 L200 64 H320 C360 64 380 30 420 30 S480 64 520 64 H700 L710 44 L720 64 H860 L870 56 L880 64 H1020 C1060 64 1080 24 1120 24 S1180 64 1200 64"
        stroke={stroke}
        strokeWidth="1.2"
      />
      <path
        d="M0 78 H140 L150 66 L160 78 H420 C470 78 500 52 550 52 S620 78 680 78 H980 L990 70 L1000 78 H1200"
        stroke={stroke}
        strokeWidth="1"
      />
      <path
        d="M0 50 H90 L100 22 L110 50 H260 L270 42 L280 50 H540 C590 50 620 14 670 14 S740 50 800 50 H1060 L1070 38 L1080 50 H1200"
        stroke={stroke}
        strokeWidth="0.8"
      />
    </svg>
  );

  return (
    <div
      aria-hidden
      className={cn("pointer-events-none relative flex overflow-hidden", className)}
      style={{ height }}
    >
      <div className={cn("flex h-full w-[200%]", drift && "sms-wave-drift")}>
        {tile}
        {tile}
      </div>
    </div>
  );
}

/**
 * Restrained technical geometry for section corners: a faint right-angle rule
 * with tick marks. Used sparingly around hero / pipeline areas.
 */
export function TechCorner({ className }: { className?: string }) {
  return (
    <svg
      aria-hidden
      viewBox="0 0 40 40"
      className={cn("pointer-events-none absolute size-10", className)}
      fill="none"
    >
      <path d="M0 8 H8 V0" stroke="var(--sms-wave-mid)" strokeWidth="1" />
      <path d="M2 14 H4 M2 20 H6 M2 26 H4" stroke="var(--sms-wave-soft)" strokeWidth="1" />
    </svg>
  );
}
