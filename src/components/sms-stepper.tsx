import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { Check } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * StepperFlow — sequential forensic-analysis stepper.
 *
 * Inspired by the React Bits Stepper pattern (one-step-at-a-time progression
 * with animated connectors), adapted to the Graphite Forensic identity:
 * graphite pending nodes, amber processing node with a slow icon pulse, an
 * amber evidence packet that physically travels the connector between nodes,
 * and muted-green settle on completion. No neon, no glow, no looping after
 * completion.
 *
 * Honesty contract: the visual sequencer is presentation-only. It can never
 * advance past `realDoneCount` — the number of stages the real pipeline has
 * reported complete. When measured progress is ahead of the animation, the
 * sequence catches up at its own deliberate pace; when measured progress is
 * behind, the active node simply keeps pulsing until the pipeline catches up.
 * No stage is ever shown completed before the pipeline completes it.
 */

export interface StepperStage {
  id: string;
  label: string;
  icon: React.ReactNode;
}

/* Cinematic pacing (ms). Deliberate, not a spinner. */
const STAGE_DWELL_MS = 850; // node activation before its connector departs
const CONNECTOR_TRAVEL_MS = 520; // packet travel between nodes
const INTER_STAGE_PAUSE_MS = 200; // breath between stages
const FINISH_FLASH_MS = 950; // one-time completion flourish

type Phase =
  | { kind: "idle" }
  | { kind: "dwell"; index: number }
  | { kind: "travel"; index: number };

type NodeState = "done" | "active" | "incoming" | "pending";

const NODE_CLASS: Record<NodeState, string> = {
  done: "border-(--sms-healthy)/35 bg-(--sms-healthy)/8 text-(--sms-healthy)",
  active: "border-(--sms-wave)/60 bg-(--sms-wave)/10 text-primary",
  incoming: "border-(--sms-wave)/30 text-muted-foreground/70",
  pending: "border-border text-muted-foreground/50",
};

const LABEL_CLASS: Record<NodeState, string> = {
  done: "text-muted-foreground",
  active: "text-foreground",
  incoming: "text-muted-foreground/70",
  pending: "text-muted-foreground/50",
};

export function StepperFlow({
  stages,
  realDoneCount,
  running,
  error = false,
  runId,
  className,
}: {
  stages: StepperStage[];
  /** Stages the real pipeline has actually completed (measured, never faked). */
  realDoneCount: number;
  /** True while a real analysis is in progress. */
  running: boolean;
  /** A real error stopped the run: freeze motion, reflect measured reality. */
  error?: boolean;
  /** Change to reset the sequence cleanly for a fresh analysis. */
  runId: number;
  className?: string;
}) {
  const reduced = useReducedMotion();
  const [settled, setSettled] = useState(0); // nodes visually completed
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [finishFlash, setFinishFlash] = useState(false);
  const timers = useRef<number[]>([]);

  const clearTimers = () => {
    timers.current.forEach((t) => clearTimeout(t));
    timers.current = [];
  };
  const schedule = (fn: () => void, ms: number) => {
    timers.current.push(window.setTimeout(fn, ms));
  };

  // Fresh analysis → clean reset and replay from stage 1.
  useEffect(() => {
    clearTimers();
    setSettled(0);
    setPhase({ kind: "idle" });
    setFinishFlash(false);
    return clearTimers;
  }, [runId]);

  // The sequencer. Each run owns its timers exclusively (cleared up front), so
  // dependency changes cannot double-fire transitions.
  useEffect(() => {
    clearTimers();

    // Stop conditions: real error, or run over and animation caught up.
    if (error || !running) {
      setPhase({ kind: "idle" });
      return;
    }
    if (finishFlash) return;
    if (settled >= stages.length) return; // fully caught up; hold green, no loop
    if (settled >= realDoneCount) return; // waiting on measured progress; hold pulse

    if (phase.kind === "idle") {
      schedule(
        () => setPhase({ kind: "dwell", index: settled }),
        settled === 0 ? 0 : INTER_STAGE_PAUSE_MS,
      );
      return;
    }
    if (phase.kind === "dwell") {
      const i = phase.index;
      schedule(() => {
        setSettled(i + 1); // node settles green as its connector departs
        if (i + 1 >= stages.length) {
          setPhase({ kind: "idle" });
          setFinishFlash(true);
          schedule(() => setFinishFlash(false), FINISH_FLASH_MS);
        } else {
          setPhase({ kind: "travel", index: i });
        }
      }, STAGE_DWELL_MS);
      return;
    }
    if (phase.kind === "travel") {
      schedule(() => setPhase({ kind: "idle" }), CONNECTOR_TRAVEL_MS);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, running, error, realDoneCount, settled, stages.length, runId]);

  const nodeState = (i: number): NodeState => {
    if (i < settled) return "done";
    if (error || !running) return "pending";
    if (phase.kind === "dwell" && phase.index === i) return "active";
    if (phase.kind === "travel" && phase.index === i - 1) return "incoming";
    // Waiting on measured progress: the next group is genuinely in flight, so
    // it holds the amber processing pulse until the pipeline reports it done.
    if (phase.kind === "idle" && i === settled && settled < stages.length)
      return "active";
    return "pending";
  };

  // Completion settle: when the measured pipeline finishes ahead of the paced
  // visuals, settle the remaining genuinely-completed stages after a short
  // grace period. The end state always reflects measured reality — never less,
  // never more.
  useEffect(() => {
    if (running || error) return;
    if (settled >= Math.min(realDoneCount, stages.length)) return;
    const t = window.setTimeout(() => {
      const next = Math.min(realDoneCount, stages.length);
      if (next > settled) {
        setSettled(next);
        if (next >= stages.length) {
          setFinishFlash(true);
          window.setTimeout(() => setFinishFlash(false), FINISH_FLASH_MS);
        }
      }
    }, 600);
    return () => clearTimeout(t);
  }, [running, error, realDoneCount, settled, stages.length]);

  return (
    <div className={cn("flex items-start", className)} role="list">
      {stages.map((s, i) => {
        const state = nodeState(i);
        return (
          <div key={s.id} role="listitem" className="flex min-w-0 flex-1 items-start">
            {/* Connector carrying the evidence signal into this node */}
            {i > 0 && (
              <Connector
                traveled={settled >= i}
                traveling={phase.kind === "travel" && phase.index === i - 1 && !reduced}
                reduced={!!reduced}
              />
            )}
            <div className="flex min-w-[76px] flex-1 flex-col items-center gap-1.5">
              <div className="relative">
                <div
                  className={cn(
                    "flex size-8 items-center justify-center rounded-[3px] border transition-colors duration-300",
                    NODE_CLASS[state],
                  )}
                >
                  <AnimatePresence mode="wait" initial={false}>
                    {state === "done" ? (
                      <motion.span
                        key="done"
                        initial={{ opacity: 0, scale: 0.5 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.5 }}
                        transition={{ duration: 0.22, ease: "easeOut" }}
                      >
                        <Check className="size-3.5" strokeWidth={2.5} />
                      </motion.span>
                    ) : (
                      <motion.span
                        key="icon"
                        initial={{ opacity: 0 }}
                        animate={
                          state === "active" && !reduced
                            ? { opacity: 1, scale: [1, 1.12, 1] }
                            : { opacity: 1, scale: 1 }
                        }
                        exit={{ opacity: 0 }}
                        transition={
                          state === "active"
                            ? { duration: 1.3, repeat: Infinity, ease: "easeInOut" }
                            : { duration: 0.2 }
                        }
                      >
                        {s.icon}
                      </motion.span>
                    )}
                  </AnimatePresence>
                </div>
                {/* Processing halo — slow, single ring, never neon */}
                {state === "active" && !reduced && (
                  <motion.span
                    aria-hidden
                    className="border-(--sms-wave)/50 pointer-events-none absolute inset-0 rounded-[3px] border"
                    animate={{ scale: [1, 1.35], opacity: [0.6, 0] }}
                    transition={{ duration: 1.5, repeat: Infinity, ease: "easeOut" }}
                  />
                )}
                {/* One-time completion flourish on the final stage */}
                {finishFlash && i === stages.length - 1 && (
                  <motion.span
                    aria-hidden
                    className="border-(--sms-healthy) pointer-events-none absolute inset-0 rounded-[3px] border"
                    initial={{ scale: 1, opacity: 0.7 }}
                    animate={{ scale: 1.9, opacity: 0 }}
                    transition={{ duration: 0.9, ease: "easeOut" }}
                  />
                )}
              </div>
              <span
                className={cn(
                  "sms-mono max-w-[92px] text-center text-[9px] leading-tight transition-colors duration-300",
                  LABEL_CLASS[state],
                )}
              >
                {s.label}
              </span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/** Thin connector between two nodes: neutral track, amber fill + packet while traveling. */
function Connector({
  traveled,
  traveling,
  reduced,
}: {
  traveled: boolean;
  traveling: boolean;
  reduced: boolean;
}) {
  return (
    <div
      aria-hidden
      className="border-border relative mx-0.5 mt-4 h-px w-5 shrink-0 overflow-hidden rounded-full border-t bg-border/60 sm:w-7"
    >
      {/* Resting fill once traveled — solid hairline like the ✓━━ example */}
      <span
        className={cn(
          "absolute inset-0 origin-left transition-colors duration-300",
          traveled ? "bg-foreground/25" : "bg-transparent",
        )}
      />
      {/* Amber fill sweeping left→right during travel */}
      <AnimatePresence>
        {traveling && (
          <motion.span
            key="fill"
            className="bg-(--sms-wave) absolute inset-y-0 left-0 w-full origin-left"
            initial={{ scaleX: 0 }}
            animate={{ scaleX: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: reduced ? 0.1 : CONNECTOR_TRAVEL_MS / 1000, ease: "easeInOut" }}
          />
        )}
      </AnimatePresence>
      {/* The evidence packet itself */}
      {traveling && !reduced && (
        <motion.span
          key="packet"
          className="bg-primary absolute top-1/2 size-1 -translate-y-1/2 rounded-full"
          initial={{ left: "0%", opacity: 0 }}
          animate={{ left: "100%", opacity: [0, 1, 1, 0] }}
          transition={{ duration: CONNECTOR_TRAVEL_MS / 1000, ease: "easeInOut" }}
        />
      )}
    </div>
  );
}
