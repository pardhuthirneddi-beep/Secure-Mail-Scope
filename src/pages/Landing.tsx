import { motion } from "framer-motion";
import {
  ArrowRight,
  Lock,
  ShieldCheck,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { useAuth } from "@/hooks/use-auth";
import { Link } from "react-router";

const fadeUp = {
  initial: { opacity: 0, y: 12 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-60px" },
  transition: { duration: 0.45, ease: "easeOut" as const },
};

const PIPELINE = [
  {
    n: "01",
    title: "Ingest",
    body: "PCAP or PCAPNG, parsed in the browser. Link layers, VLANs, IPv4/IPv6 and TCP reassembly handled without uploading a byte.",
  },
  {
    n: "02",
    title: "Reconstruct",
    body: "Flows are reassembled into sessions and classified as SMTP, IMAP or POP3 from observed banners and command grammar.",
  },
  {
    n: "03",
    title: "Trace upgrades",
    body: "Every STARTTLS/STLS exchange is tracked: advertised, requested, accepted, or silently absent.",
  },
  {
    n: "04",
    title: "Extract",
    body: "TLS versions, cipher suites, key exchange, forward secrecy and full X.509 certificate fields are read from handshake bytes.",
  },
  {
    n: "05",
    title: "Assess",
    body: "A published rule set proves weaknesses deterministically; an isolation-forest model and logistic classifier prioritize them.",
  },
  {
    n: "06",
    title: "Report",
    body: "Session risk rationale, prioritized remediation, and a JSON evidence bundle — every claim traceable to the capture.",
  },
];

const CAPABILITIES = [
  {
    k: "TLS",
    title: "Handshake-level TLS analysis",
    body: "Negotiated version, suite, key exchange and forward secrecy are read from the handshake itself — including ClientHello offers versus ServerHello reality, which exposes downgrade behavior no configuration scan can see.",
  },
  {
    k: "CERT",
    title: "Certificate evidence, parsed",
    body: "Subject, issuer, SAN entries, validity window, signature algorithm and key size extracted from presented X.509 bytes. Expired, self-signed and weak-key certificates are flagged with the proof attached.",
  },
  {
    k: "STARTTLS",
    title: "Upgrade-path integrity",
    body: "Advertised capability, client requests and TLS establishment are correlated per session. Failed upgrades and plaintext fallback are proven from the command stream, not inferred from ports.",
  },
  {
    k: "RULES",
    title: "Deterministic, published rules",
    body: "Nine rule IDs with declared evidence requirements, severities and limitations. A finding is a proof with a citation — never a statistical guess dressed as certainty.",
  },
  {
    k: "ML",
    title: "Machine learning, bounded",
    body: "Risk classification and anomaly detection prioritize what matters across the capture population. Output is always labeled AI-assessed and can never overrule deterministic evidence.",
  },
  {
    k: "PASSIVE",
    title: "Passive by construction",
    body: "Nothing is intercepted, decrypted or exfiltrated. Analysis runs on your machine against the capture you supply, and every limitation of passive evidence is stated where it applies.",
  },
];

export default function Landing() {
  const { isAuthenticated } = useAuth();

  return (
    <div className="bg-background text-foreground flex min-h-screen flex-col">
      <header className="border-border/70 bg-background/95 sticky top-0 z-20 border-b">
        <div className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between px-4">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="border-primary/40 bg-primary/10 text-primary flex size-7 items-center justify-center rounded-sm border">
              <ShieldCheck className="size-4" />
            </div>
            <div className="leading-tight">
              <div className="text-[13px] font-semibold tracking-tight">Secure Mail Analysis</div>
              <div className="sms-mono text-muted-foreground text-[10px]">
                cryptographic posture assessment
              </div>
            </div>
          </Link>
          <nav className="flex items-center gap-1">
            <Button asChild variant="ghost" size="sm" className="text-xs">
              <a href="#method">Method</a>
            </Button>
            <Button asChild variant="ghost" size="sm" className="text-xs">
              <a href="#capabilities">Capabilities</a>
            </Button>
            <Button asChild size="sm" className="ml-1 gap-1.5 text-xs">
              <Link to={isAuthenticated ? "/dashboard" : "/auth"}>
                {isAuthenticated ? "Open workstation" : "Launch workstation"}
                <ArrowRight className="size-3.5" />
              </Link>
            </Button>
          </nav>
        </div>
      </header>

      <main className="flex-1">
        {/* Hero */}
        <section className="sms-grid-bg border-border/70 border-b">
          <div className="mx-auto w-full max-w-6xl px-4 py-20 sm:py-28">
            <motion.p {...fadeUp} className="sms-label text-primary">
              Passive capture analysis · evidence-driven
            </motion.p>
            <motion.h1
              {...fadeUp}
              transition={{ ...fadeUp.transition, delay: 0.05 }}
              className="mt-4 max-w-2xl text-3xl leading-[1.15] font-bold tracking-tight sm:text-[2.6rem]"
            >
              Know exactly how your email was protected.
              <span className="text-primary block">Prove it from the packets.</span>
            </motion.h1>
            <motion.p
              {...fadeUp}
              transition={{ ...fadeUp.transition, delay: 0.1 }}
              className="text-muted-foreground mt-5 max-w-2xl text-[15px] leading-relaxed"
            >
              Secure Mail Analysis reconstructs email sessions from a captured PCAP, traces every
              STARTTLS transition, extracts TLS versions, cipher suites and certificates, and
              reports what was protected, what was exposed, and what to fix first. Every finding
              cites the packet evidence that proves it — nothing is inferred beyond the capture.
            </motion.p>
            <motion.div
              {...fadeUp}
              transition={{ ...fadeUp.transition, delay: 0.15 }}
              className="mt-8 flex flex-col gap-3 sm:flex-row"
            >
              <Button asChild size="lg" className="gap-2">
                <Link to={isAuthenticated ? "/dashboard" : "/auth"}>
                  Analyze your first capture
                  <ArrowRight className="size-4" />
                </Link>
              </Button>
              <Button asChild size="lg" variant="outline">
                <a href="#method">How the analysis works</a>
              </Button>
            </motion.div>

            {/* Terminal-style sample of real output */}
            <motion.div
              {...fadeUp}
              transition={{ ...fadeUp.transition, delay: 0.2 }}
              className="border-border/80 bg-card/50 mt-14 rounded-sm border"
            >
              <div className="border-border/80 bg-muted/30 flex items-center justify-between border-b px-3.5 py-2">
                <span className="sms-mono text-muted-foreground text-[11px]">
                  mixed-enterprise.pcap
                </span>
                <span className="sms-mono text-muted-foreground/70 text-[10px]">
                  4 sessions · 9 evidence items · 3 findings
                </span>
              </div>
              <div className="sms-mono divide-border/50 divide-y text-[11px] leading-relaxed">
                <div className="flex items-center gap-3 px-3.5 py-2.5">
                  <span className="bg-(--sms-healthy) size-1.5 shrink-0 rounded-[1px]" />
                  <span className="w-12 shrink-0 font-semibold">S-001</span>
                  <span className="text-muted-foreground min-w-0 truncate">
                    SMTP 587 · STARTTLS → TLS 1.3 · TLS_AES_256_GCM_SHA384 · valid certificate
                  </span>
                  <span className="text-(--sms-healthy) ml-auto shrink-0 text-[10px] tracking-[0.08em]">
                    HEALTHY
                  </span>
                </div>
                <div className="flex items-center gap-3 px-3.5 py-2.5">
                  <span className="bg-(--sms-high) size-1.5 shrink-0 rounded-[1px]" />
                  <span className="w-12 shrink-0 font-semibold">S-002</span>
                  <span className="text-muted-foreground min-w-0 truncate">
                    SMTP 465 · implicit TLS 1.2 · certificate expired 2026-08-12
                  </span>
                  <span className="text-(--sms-high) ml-auto shrink-0 text-[10px] tracking-[0.08em]">
                    HIGH
                  </span>
                </div>
                <div className="flex items-center gap-3 px-3.5 py-2.5">
                  <span className="bg-(--sms-critical) size-1.5 shrink-0 rounded-[1px]" />
                  <span className="w-12 shrink-0 font-semibold">S-004</span>
                  <span className="text-muted-foreground min-w-0 truncate">
                    POP3 110 · no TLS record layer · credentials observed in cleartext
                  </span>
                  <span className="text-(--sms-critical) ml-auto shrink-0 text-[10px] tracking-[0.08em]">
                    CRITICAL
                  </span>
                </div>
              </div>
              <div className="border-border/80 text-muted-foreground border-t px-3.5 py-2">
                <span className="sms-label">Output</span>{" "}
                <span className="sms-mono ml-2 text-[11px]">
                  posture report · prioritized remediation · JSON evidence bundle
                </span>
              </div>
              {/* footer strip intentionally plain — output example, not decoration */}
              <div className="sms-mono text-muted-foreground/50 border-t border-border/60 px-3.5 py-1.5 text-[9px] uppercase tracking-[0.14em]">
                illustrative output — generated by the production pipeline from demo captures
              </div>
            </motion.div>
          </div>
        </section>

        {/* Method */}
        <section id="method" className="border-border/70 border-b">
          <div className="mx-auto w-full max-w-6xl px-4 py-16 sm:py-20">
            <div className="grid gap-10 lg:grid-cols-[1fr_2fr]">
              <div>
                <motion.p {...fadeUp} className="sms-label text-primary">
                  Method
                </motion.p>
                <motion.h2
                  {...fadeUp}
                  className="mt-3 text-2xl font-bold tracking-tight sm:text-3xl"
                >
                  From capture to conclusion, without invention
                </motion.h2>
                <motion.p {...fadeUp} className="text-muted-foreground mt-4 text-sm leading-relaxed">
                  Four layers keep the analysis honest. Facts come from observed evidence.
                  Weaknesses are proven deterministically. Machine learning only prioritizes. And
                  every conclusion is written so an analyst can trace it back to the packets.
                </motion.p>
              </div>
              <div className="grid gap-x-8 sm:grid-cols-2">
                {PIPELINE.map((step, i) => (
                  <motion.div
                    key={step.n}
                    {...fadeUp}
                    transition={{ ...fadeUp.transition, delay: 0.04 * i }}
                    className="border-border/70 border-b py-4"
                  >
                    <div className="flex items-baseline gap-2.5">
                      <span className="sms-mono text-primary/80 text-[11px]">{step.n}</span>
                      <h3 className="text-sm font-semibold">{step.title}</h3>
                    </div>
                    <p className="text-muted-foreground mt-1.5 pl-6 text-xs leading-relaxed">
                      {step.body}
                    </p>
                  </motion.div>
                ))}
              </div>
            </div>

            {/* Four layers */}
            <motion.div
              {...fadeUp}
              className="border-border/80 bg-card/40 mt-10 grid gap-6 rounded-sm border p-5 sm:grid-cols-3"
            >
              {[
                {
                  t: "Layer A — Evidence",
                  d: "What was actually observed: endpoints, ports, commands, handshake fields, certificate bytes. Labeled verified when read directly from the capture.",
                },
                {
                  t: "Layer B — Deterministic",
                  d: "What can be proven: obsolete TLS, weak ciphers, expired certificates, failed upgrades. Published rules; no statistical guesswork.",
                },
                {
                  t: "Layer C — AI, bounded",
                  d: "Risk classification and anomaly detection over the evidence. Always labeled AI-assessed; never allowed to invent facts or overrule the packets.",
                },
              ].map((l) => (
                <div key={l.t}>
                  <div className="sms-label text-primary/80">{l.t}</div>
                  <p className="text-muted-foreground mt-2 text-xs leading-relaxed">{l.d}</p>
                </div>
              ))}
            </motion.div>
          </div>
        </section>

        {/* Capabilities */}
        <section id="capabilities" className="border-border/70 border-b">
          <div className="mx-auto w-full max-w-6xl px-4 py-16 sm:py-20">
            <motion.p {...fadeUp} className="sms-label text-primary">
              Capabilities
            </motion.p>
            <motion.h2 {...fadeUp} className="mt-3 max-w-xl text-2xl font-bold tracking-tight sm:text-3xl">
              Built for teams that must show their work
            </motion.h2>
            <div className="mt-10 grid gap-px overflow-hidden rounded-sm border border-border/70 bg-border/60 md:grid-cols-2 lg:grid-cols-3">
              {CAPABILITIES.map((cap, i) => (
                <motion.div
                  key={cap.k}
                  {...fadeUp}
                  transition={{ ...fadeUp.transition, delay: 0.04 * i }}
                  className="bg-background hover:bg-accent/30 group p-5 transition-colors"
                >
                  <div className="flex items-center justify-between">
                    <span className="sms-mono text-muted-foreground/70 text-[10px] tracking-[0.14em]">
                      {cap.k}
                    </span>
                    <Lock className="text-muted-foreground/30 group-hover:text-primary size-3.5 transition-colors" />
                  </div>
                  <h3 className="mt-3 text-sm leading-snug font-semibold">{cap.title}</h3>
                  <p className="text-muted-foreground mt-2 text-xs leading-relaxed">{cap.body}</p>
                </motion.div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section className="sms-grid-bg">
          <div className="mx-auto w-full max-w-6xl px-4 py-16 text-center sm:py-20">
            <motion.p {...fadeUp} className="sms-label text-primary">
              Get started
            </motion.p>
            <motion.h2 {...fadeUp} className="mx-auto mt-3 max-w-xl text-2xl font-bold tracking-tight sm:text-3xl">
              Bring a capture. Leave with a posture report.
            </motion.h2>
            <motion.p {...fadeUp} className="text-muted-foreground mx-auto mt-3 max-w-lg text-sm">
              The workstation runs the full pipeline in your browser — upload a PCAP, investigate
              every session, and export a remediation report with evidence attached.
            </motion.p>
            <motion.div {...fadeUp} className="mt-7 flex justify-center">
              <Button asChild size="lg" className="gap-2">
                <Link to={isAuthenticated ? "/dashboard" : "/auth"}>
                  Open the workstation
                  <ArrowRight className="size-4" />
                </Link>
              </Button>
            </motion.div>
          </div>
        </section>
      </main>

      <footer className="border-border/70 border-t">
        <div className="mx-auto flex w-full max-w-6xl flex-col items-center justify-between gap-2 px-4 py-6 text-xs sm:flex-row">
          <span className="text-muted-foreground">
            Secure Mail Analysis — passive cryptographic posture assessment for email
            communications.
          </span>
          <span className="sms-mono text-muted-foreground/70 text-[10px] tracking-[0.1em] uppercase">
            pcap in · evidence out
          </span>
        </div>
      </footer>
    </div>
  );
}
