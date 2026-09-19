import { motion } from "framer-motion";
import {
  ArrowRight,
  FileSearch,
  FlaskConical,
  GitBranch,
  Layers,
  Lock,
  ShieldCheck,
  ScanSearch,
  FileText,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useAuth } from "@/hooks/use-auth";
import { Link } from "react-router";

const fadeUp = {
  initial: { opacity: 0, y: 16 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: "-80px" },
  transition: { duration: 0.5, ease: "easeOut" as const },
};

const PIPELINE = [
  { icon: FileSearch, label: "PCAP ingested" },
  { icon: ScanSearch, label: "Sessions reconstructed" },
  { icon: GitBranch, label: "STARTTLS traced" },
  { icon: Lock, label: "TLS + certificates extracted" },
  { icon: Layers, label: "Deterministic rules" },
  { icon: ShieldCheck, label: "Evidence-linked report" },
];

const CAPABILITIES = [
  {
    icon: Lock,
    title: "TLS and cipher analysis from observed handshakes",
    body: "Reconstructs SMTP, IMAP and POP3 sessions, tracks every STARTTLS transition, and extracts negotiated TLS versions, cipher suites, key exchange and forward-secrecy properties directly from handshake bytes.",
  },
  {
    icon: ShieldCheck,
    title: "Certificate evidence, not assumptions",
    body: "Parses presented X.509 certificates for subject, issuer, validity window, signature algorithm and key size, and flags expired, self-signed or weak-key certificates with the exact evidence that proves each finding.",
  },
  {
    icon: Layers,
    title: "Deterministic rules where facts are provable",
    body: "Deprecated protocol versions, broken ciphers and failed TLS upgrades are proven by packet evidence, not inferred. The rule set is published: every finding cites the rule ID and the observed bytes behind it.",
  },
  {
    icon: FlaskConical,
    title: "Machine learning only where it adds value",
    body: "A logistic risk classifier and an isolation-forest anomaly model prioritize findings and surface unusual handshake shapes. Their output is always labeled AI-assessed and never overrules deterministic evidence.",
  },
  {
    icon: FileText,
    title: "Reports your team can act on",
    body: "Every capture produces a posture report with prioritized remediation, session risk rationale, and a JSON evidence bundle — each claim traceable back to the capture it came from.",
  },
  {
    icon: ScanSearch,
    title: "Passive by design",
    body: "Nothing is intercepted, decrypted or sent to a third party. Analysis runs in your browser on the capture you supply, encrypted content stays encrypted, and every limitation is stated in the report.",
  },
];

export default function Landing() {
  const { isAuthenticated } = useAuth();

  return (
    <div className="bg-background text-foreground flex min-h-screen flex-col">
      <header className="border-border/70 sticky top-0 z-20 border-b backdrop-blur">
        <div className="mx-auto flex h-14 w-full max-w-6xl items-center justify-between px-4">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="bg-primary/15 flex size-7 items-center justify-center rounded-sm">
              <ShieldCheck className="text-primary size-4" />
            </div>
            <div className="leading-tight">
              <div className="text-[13px] font-semibold tracking-tight">Secure Mail Analysis</div>
              <div className="text-muted-foreground hidden text-[10px] sm:block">
                Cryptographic security posture assessment
              </div>
            </div>
          </Link>
          <nav className="flex items-center gap-1.5">
            <Button asChild variant="ghost" size="sm" className="text-xs">
              <a href="#capabilities">Capabilities</a>
            </Button>
            <Button asChild variant="ghost" size="sm" className="text-xs">
              <a href="#method">Method</a>
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
            <motion.div {...fadeUp}>
              <Badge variant="outline" className="sms-mono gap-1.5 rounded-sm px-2 py-1 text-[10px] uppercase tracking-wider">
                <span className="bg-[--sms-healthy] size-1.5 rounded-full" />
                Passive capture analysis · Evidence-driven
              </Badge>
            </motion.div>
            <motion.h1
              {...fadeUp}
              transition={{ ...fadeUp.transition, delay: 0.05 }}
              className="mt-5 max-w-3xl text-4xl leading-[1.1] font-bold tracking-tight sm:text-5xl"
            >
              Know exactly how your email was protected.
              <span className="text-primary block">Prove it from the packets.</span>
            </motion.h1>
            <motion.p
              {...fadeUp}
              transition={{ ...fadeUp.transition, delay: 0.1 }}
              className="text-muted-foreground mt-5 max-w-2xl text-base leading-relaxed sm:text-lg"
            >
              Secure Mail Analysis turns captured email traffic into an evidence-linked
              cryptographic posture assessment. Upload a PCAP and the workstation reconstructs every
              mail session, traces each STARTTLS transition, extracts TLS versions, cipher suites
              and certificates, and reports what was protected, what was exposed, and what to fix
              first — with every finding traceable to packet evidence.
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
              <Button asChild size="lg" variant="outline" className="gap-2">
                <a href="#method">
                  How the analysis works
                </a>
              </Button>
            </motion.div>

            <motion.div
              {...fadeUp}
              transition={{ ...fadeUp.transition, delay: 0.2 }}
              className="border-border/70 bg-card/50 mt-12 overflow-hidden rounded-md border"
            >
              <div className="border-border/70 bg-card/70 flex items-center gap-1.5 border-b px-3 py-2">
                <span className="size-2 rounded-full bg-[--sms-critical]/60" />
                <span className="size-2 rounded-full bg-[--sms-medium]/60" />
                <span className="size-2 rounded-full bg-[--sms-healthy]/60" />
                <span className="sms-mono text-muted-foreground ml-2 text-[10px]">
                  mixed-enterprise.pcap — 4 sessions
                </span>
              </div>
              <div className="sms-mono space-y-1.5 p-4 text-[11px] leading-relaxed">
                <div>
                  <span className="text-[--sms-healthy]">S-001</span>
                  <span className="text-muted-foreground"> SMTP 587 · STARTTLS → TLS 1.3</span>
                  <span className="text-muted-foreground"> · TLS_AES_256_GCM_SHA384 · risk </span>
                  <span className="text-[--sms-healthy]">HEALTHY</span>
                </div>
                <div>
                  <span className="text-[--sms-medium]">S-002</span>
                  <span className="text-muted-foreground"> SMTP 465 · implicit TLS 1.2</span>
                  <span className="text-muted-foreground"> · certificate expired 2026-08-12 · risk </span>
                  <span className="text-[--sms-medium]">HIGH</span>
                </div>
                <div>
                  <span className="text-[--sms-critical]">S-004</span>
                  <span className="text-muted-foreground"> POP3 110 · no TLS record layer</span>
                  <span className="text-muted-foreground"> · credentials observed in cleartext · risk </span>
                  <span className="text-[--sms-critical]">CRITICAL</span>
                </div>
                <div className="text-muted-foreground pt-1">
                  9 evidence items · 3 deterministic findings · 1 prioritized remediation
                </div>
              </div>
            </motion.div>
          </div>
        </section>

        {/* Pipeline */}
        <section id="method" className="border-border/70 border-b">
          <div className="mx-auto w-full max-w-6xl px-4 py-16 sm:py-20">
            <motion.h2 {...fadeUp} className="text-2xl font-bold tracking-tight sm:text-3xl">
              From capture to conclusion, without invention
            </motion.h2>
            <motion.p {...fadeUp} className="text-muted-foreground mt-3 max-w-2xl">
              Four layers keep the analysis honest: observed evidence, deterministic analysis,
              machine learning for prioritization only, and plain-language explanation. Conclusions
              never outrun their evidence.
            </motion.p>
            <div className="mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {PIPELINE.map((step, i) => (
                <motion.div
                  key={step.label}
                  {...fadeUp}
                  transition={{ ...fadeUp.transition, delay: 0.05 * i }}
                  className="border-border/70 bg-card/40 flex items-start gap-3 rounded-md border px-4 py-3.5"
                >
                  <span className="sms-mono text-muted-foreground mt-0.5 text-xs">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <div>
                    <step.icon className="text-primary mb-1.5 size-4" />
                    <div className="text-sm font-medium">{step.label}</div>
                  </div>
                </motion.div>
              ))}
            </div>
            <motion.div
              {...fadeUp}
              className="border-border/70 bg-card/40 mt-6 rounded-md border p-5"
            >
              <div className="grid gap-4 text-sm sm:grid-cols-3">
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-[--sms-healthy]">
                    Layer A — Evidence
                  </div>
                  <p className="text-muted-foreground mt-1.5 text-xs leading-relaxed">
                    What was actually observed: endpoints, ports, commands, handshake fields,
                    certificate bytes. Labeled verified when read directly from the capture.
                  </p>
                </div>
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-[--sms-medium]">
                    Layer B — Deterministic analysis
                  </div>
                  <p className="text-muted-foreground mt-1.5 text-xs leading-relaxed">
                    What can be proven: obsolete TLS, weak ciphers, expired certificates, failed
                    upgrades. Published rule set, no statistical guesswork.
                  </p>
                </div>
                <div>
                  <div className="text-[10px] font-semibold uppercase tracking-wider text-[--sms-low]">
                    Layer C — AI/ML, bounded
                  </div>
                  <p className="text-muted-foreground mt-1.5 text-xs leading-relaxed">
                    Risk classification and anomaly detection over the evidence. Always labeled
                    AI-assessed, never allowed to invent facts or overrule what the packets show.
                  </p>
                </div>
              </div>
            </motion.div>
          </div>
        </section>

        {/* Capabilities */}
        <section id="capabilities" className="border-border/70 border-b">
          <div className="mx-auto w-full max-w-6xl px-4 py-16 sm:py-20">
            <motion.h2 {...fadeUp} className="text-2xl font-bold tracking-tight sm:text-3xl">
              Built for evidence-driven security teams
            </motion.h2>
            <div className="mt-10 grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              {CAPABILITIES.map((cap, i) => (
                <motion.div
                  key={cap.title}
                  {...fadeUp}
                  transition={{ ...fadeUp.transition, delay: 0.04 * i }}
                  className="border-border/70 bg-card/40 hover:border-primary/40 group rounded-md border px-5 py-5 transition-colors"
                >
                  <div className="bg-primary/10 text-primary mb-4 inline-flex size-9 items-center justify-center rounded-sm">
                    <cap.icon className="size-4.5" />
                  </div>
                  <h3 className="text-sm leading-snug font-semibold">{cap.title}</h3>
                  <p className="text-muted-foreground mt-2 text-xs leading-relaxed">{cap.body}</p>
                </motion.div>
              ))}
            </div>
          </div>
        </section>

        {/* CTA */}
        <section>
          <div className="sms-grid-bg">
            <div className="mx-auto w-full max-w-6xl px-4 py-16 text-center sm:py-20">
              <motion.h2 {...fadeUp} className="text-2xl font-bold tracking-tight sm:text-3xl">
                Bring a capture. Leave with a posture report.
              </motion.h2>
              <motion.p {...fadeUp} className="text-muted-foreground mx-auto mt-3 max-w-xl">
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
          </div>
        </section>
      </main>

      <footer className="border-border/70 border-t">
        <div className="text-muted-foreground mx-auto flex w-full max-w-6xl flex-col items-center justify-between gap-2 px-4 py-6 text-xs sm:flex-row">
          <span>
            Secure Mail Analysis — passive cryptographic posture assessment for email
            communications.
          </span>
          <span className="sms-mono">PCAP in · evidence out. No decryption, no data exfiltration.</span>
        </div>
      </footer>
    </div>
  );
}
