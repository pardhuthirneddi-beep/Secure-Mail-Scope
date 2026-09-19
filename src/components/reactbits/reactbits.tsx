/**
 * React Bits components — ported from reactbits.dev (MIT License).
 * Source: github.com/DavidHDev/react-bits
 *
 * Adaptations for this project:
 * - `motion/react` imports map to the installed `framer-motion` (same API).
 * - All ambient effects respect `prefers-reduced-motion`.
 * - Colors default to the Graphite Forensic token system instead of demo colors.
 * - SpotlightCard CSS from React Bits is inlined here; no separate .css files.
 */

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
  type ReactNode,
} from "react";
import { motion, useInView, useMotionValue, useSpring, useReducedMotion } from "framer-motion";
import { cn } from "@/lib/utils";

/* ============================================================ CountUp ====== */

interface CountUpProps {
  to: number;
  from?: number;
  direction?: "up" | "down";
  delay?: number;
  duration?: number;
  className?: string;
  startWhen?: boolean;
  separator?: string;
}

/** Spring-animated number count-up on scroll into view. */
export function CountUp({
  to,
  from = 0,
  direction = "up",
  delay = 0,
  duration = 2,
  className = "",
  startWhen = true,
  separator = "",
}: CountUpProps) {
  const ref = useRef<HTMLSpanElement>(null);
  const motionValue = useMotionValue(direction === "down" ? to : from);
  const damping = 20 + 40 * (1 / duration);
  const stiffness = 100 * (1 / duration);
  const springValue = useSpring(motionValue, { damping, stiffness });
  const isInView = useInView(ref, { once: true, margin: "0px" });
  const reduced = useReducedMotion();

  const maxDecimals = Math.max(
    getDecimalPlaces(from),
    getDecimalPlaces(to),
  );

  const formatValue = useCallback(
    (latest: number) => {
      const hasDecimals = maxDecimals > 0;
      const options: Intl.NumberFormatOptions = {
        useGrouping: !!separator,
        minimumFractionDigits: hasDecimals ? maxDecimals : 0,
        maximumFractionDigits: hasDecimals ? maxDecimals : 0,
      };
      const formattedNumber = Intl.NumberFormat("en-US", options).format(latest);
      return separator ? formattedNumber.replace(/,/g, separator) : formattedNumber;
    },
    [maxDecimals, separator],
  );

  useEffect(() => {
    if (ref.current) {
      ref.current.textContent = formatValue(reduced ? to : direction === "down" ? to : from);
    }
  }, [from, to, direction, formatValue, reduced]);

  useEffect(() => {
    if (!isInView || !startWhen || reduced) return;
    const timeoutId = setTimeout(() => {
      motionValue.set(direction === "down" ? from : to);
    }, delay * 1000);
    return () => clearTimeout(timeoutId);
  }, [isInView, startWhen, motionValue, direction, from, to, delay, reduced]);

  useEffect(() => {
    const unsubscribe = springValue.on("change", (latest: number) => {
      if (ref.current) {
        ref.current.textContent = formatValue(latest);
      }
    });
    return () => unsubscribe();
  }, [springValue, formatValue]);

  return <span className={className} ref={ref} />;
}

function getDecimalPlaces(num: number): number {
  const str = num.toString();
  if (str.includes(".")) {
    const decimals = str.split(".")[1];
    if (parseInt(decimals) !== 0) return decimals.length;
  }
  return 0;
}

/* ====================================================== SpotlightCard ====== */

interface SpotlightCardProps {
  children: ReactNode;
  className?: string;
  spotlightColor?: string;
  as?: "div" | "section";
}

/**
 * Card with a mouse-following radial spotlight (React Bits SpotlightCard).
 * The spotlight is a restrained warm wash; it only appears on hover.
 */
export function SpotlightCard({
  children,
  className,
  spotlightColor = "color-mix(in oklab, var(--primary) 9%, transparent)",
  as = "div",
}: SpotlightCardProps) {
  const divRef = useRef<HTMLDivElement>(null);
  const reduced = useReducedMotion();

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!divRef.current || reduced) return;
    const rect = divRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    divRef.current.style.setProperty("--mouse-x", `${x}px`);
    divRef.current.style.setProperty("--mouse-y", `${y}px`);
    divRef.current.style.setProperty("--spotlight-color", spotlightColor);
  };

  const Tag = as;
  return (
    <Tag
      ref={divRef as never}
      onMouseMove={handleMouseMove}
      className={cn("sms-spotlight", className)}
    >
      {children}
    </Tag>
  );
}

/* ========================================================== ShinyText ====== */

interface ShinyTextProps {
  text: string;
  disabled?: boolean;
  speed?: number;
  className?: string;
  color?: string;
  shineColor?: string;
  spread?: number;
}

/**
 * Shimmer sweep across text (React Bits ShinyText), reimplemented with a CSS
 * keyframe instead of the motion loop. Used for the primary CTA label.
 */
export function ShinyText({
  text,
  disabled = false,
  speed = 4,
  className = "",
  color = "var(--primary-foreground)",
  shineColor = "rgb(255 255 255 / 0.85)",
  spread = 120,
}: ShinyTextProps) {
  const reduced = useReducedMotion();
  const gradientStyle: CSSProperties = useMemo(
    () => ({
      backgroundImage: `linear-gradient(${spread}deg, ${color} 0%, ${color} 40%, ${shineColor} 50%, ${color} 60%, ${color} 100%)`,
      backgroundSize: "200% auto",
      WebkitBackgroundClip: "text",
      backgroundClip: "text",
      WebkitTextFillColor: "transparent",
    }),
    [color, shineColor, spread],
  );

  return (
    <span
      className={cn(!disabled && !reduced && "sms-shiny", className)}
      style={gradientStyle}
    >
      {text}
    </span>
  );
}

/* ====================================================== AnimatedList ======= */

interface AnimatedListItem {
  key: string;
  node: ReactNode;
}

/**
 * Staggered entrance for list rows (React Bits AnimatedList pattern): rows
 * scale/fade in one after another as they enter the viewport. Content-agnostic
 * — callers pass fully rendered row nodes.
 */
export function AnimatedList({
  items,
  className,
  stagger = 0.05,
  disabled = false,
}: {
  items: AnimatedListItem[];
  className?: string;
  stagger?: number;
  disabled?: boolean;
}) {
  const reduced = useReducedMotion();
  if (reduced || disabled) {
    return (
      <div className={className}>
        {items.map((it) => (
          <div key={it.key}>{it.node}</div>
        ))}
      </div>
    );
  }
  return (
    <div className={className}>
      {items.map((it, i) => (
        <motion.div
          key={it.key}
          initial={{ scale: 0.97, opacity: 0 }}
          whileInView={{ scale: 1, opacity: 1 }}
          viewport={{ once: true, margin: "-40px" }}
          transition={{ duration: 0.28, delay: Math.min(i * stagger, 0.5), ease: "easeOut" }}
        >
          {it.node}
        </motion.div>
      ))}
    </div>
  );
}

/* ======================================================== FadeContent ====== */

/**
 * Fade/rise entrance on scroll into view (React Bits FadeContent), built with
 * framer-motion instead of GSAP to avoid a new dependency.
 */
export function FadeContent({
  children,
  className,
  duration = 0.5,
  delay = 0,
  blur = false,
}: {
  children: ReactNode;
  className?: string;
  duration?: number;
  delay?: number;
  blur?: boolean;
}) {
  const reduced = useReducedMotion();
  if (reduced) return <div className={className}>{children}</div>;
  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: 8, filter: blur ? "blur(6px)" : "blur(0px)" }}
      whileInView={{ opacity: 1, y: 0, filter: "blur(0px)" }}
      viewport={{ once: true, margin: "-40px" }}
      transition={{ duration, delay, ease: "easeOut" }}
    >
      {children}
    </motion.div>
  );
}
