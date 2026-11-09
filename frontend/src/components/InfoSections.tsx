"use client";
import { Shield, Layers, Database, Eye, Lock, Fingerprint, FileWarning, Cpu } from "lucide-react";

const steps = [
  { icon: Shield, title: "Input & Validation", desc: "Submit any URL or suspicious message. Our multi-layer SSRF guard validates every request, blocking private addresses, numeric disguises, and DNS rebinding attacks." },
  { icon: Layers, title: "7-Layer Analysis", desc: "Lexical patterns, DNS/RDAP age, TLS certificates, security headers, threat intelligence feeds, social engineering heuristics, and campaign correlation." },
  { icon: Database, title: "Blockchain Proof", desc: "Reports are canonically serialized to UTF-8 JSON, SHA-256 hashed, and committed to an EVM smart contract for tamper-evident verification." },
];

const features = [
  { icon: Shield, title: "SSRF Guard & Anti-Rebinding", desc: "Blocks loopback, private ranges, cloud metadata, CGNAT, numeric disguises, and DNS rebinding via IP-pinned sockets." },
  { icon: Eye, title: "Passive Inspection Only", desc: "No scripts executed, no files downloaded. Response bodies capped at 200KB with strict timeouts (4s/10s/25s)." },
  { icon: Cpu, title: "AI Safety & Prompt Defense", desc: "Untrusted input wrapped in random boundary markers. AI cannot alter risk labels — only explains technical findings." },
  { icon: Lock, title: "Off-Chain Privacy", desc: "Zero PII, passwords, or raw URLs stored on blockchain. Only SHA-256 hash, timestamp, and reporter address go on-chain." },
  { icon: FileWarning, title: "Sensitive Token Redaction", desc: "Automatically detects and redacts credit card numbers, Aadhaar, OTPs, and private keys before storage or AI processing." },
  { icon: Fingerprint, title: "CA Distrust Verification", desc: "Matches certificate chains against published distrust lists by SHA-256 fingerprint. Includes eMudhra incident coverage." },
];

export function HowItWorks() {
  return (
    <section id="how-it-works" className="scroll-mt-20">
      <div className="text-center mb-12">
        <h2 className="text-3xl sm:text-4xl font-black tracking-tight text-zinc-900 dark:text-zinc-100">How It Works</h2>
        <p className="mt-3 text-zinc-500 dark:text-zinc-400 max-w-xl mx-auto">Three steps from suspicious link to cryptographically verified intelligence report.</p>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {steps.map((s, i) => (
          <div
            key={i}
            className="cyber-card relative bg-white dark:bg-[#121215] rounded-2xl border border-zinc-200 dark:border-zinc-800 p-6 shadow-sm group hover:-translate-y-1 transition-all duration-300"
          >
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2.5 bg-brand-50 dark:bg-brand-950/40 rounded-xl text-brand-600 dark:text-brand-400 group-hover:scale-110 group-hover:rotate-3 transition-transform duration-300 border border-brand-200/40 dark:border-brand-800/40">
                <s.icon className="w-6 h-6" />
              </div>
              <span className="text-xs font-bold text-brand-600 dark:text-brand-400 bg-brand-50 dark:bg-brand-950/40 px-2.5 py-0.5 rounded-full border border-brand-200/50 dark:border-brand-800/50">
                Step {i + 1}
              </span>
            </div>
            <h3 className="text-lg font-bold text-zinc-900 dark:text-zinc-100 mb-2 group-hover:text-brand-600 dark:group-hover:text-brand-400 transition-colors">
              {s.title}
            </h3>
            <p className="text-sm text-zinc-500 dark:text-zinc-400 leading-relaxed">{s.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}

export function SecurityFeatures() {
  return (
    <section id="security" className="scroll-mt-20">
      <div className="text-center mb-12">
        <h2 className="text-3xl sm:text-4xl font-black tracking-tight text-zinc-900 dark:text-zinc-100">Security Built In</h2>
        <p className="mt-3 text-zinc-500 dark:text-zinc-400 max-w-xl mx-auto">Every layer is designed with defense-in-depth principles. Here&apos;s what protects you and your data.</p>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
        {features.map((f, i) => (
          <div
            key={i}
            className="cyber-card bg-white dark:bg-[#121215] rounded-2xl border border-zinc-200 dark:border-zinc-800 p-5 group hover:-translate-y-1 transition-all duration-300"
          >
            <div className="p-2 bg-zinc-100 dark:bg-[#18181c] rounded-lg inline-block mb-3 group-hover:bg-brand-50 dark:group-hover:bg-brand-950/40 transition-colors group-hover:scale-110 transition-transform duration-300">
              <f.icon className="w-5 h-5 text-zinc-600 dark:text-zinc-400 group-hover:text-brand-600 dark:group-hover:text-brand-400 transition-colors" />
            </div>
            <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 mb-1.5 group-hover:text-brand-600 dark:group-hover:text-brand-400 transition-colors">
              {f.title}
            </h3>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 leading-relaxed">{f.desc}</p>
          </div>
        ))}
      </div>
    </section>
  );
}
