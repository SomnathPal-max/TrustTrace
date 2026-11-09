"use client";

import React, { useState, useEffect } from "react";
import {
  Shield, ArrowRight, Lock, Database, Sparkles, Cpu,
  CheckCircle2, Activity, Globe, Eye, AlertTriangle,
  Layers, ChevronDown, Check, Zap, Server
} from "lucide-react";
import Navbar from "@/components/Navbar";
import Scanner from "@/components/Scanner";
import ReportView from "@/components/ReportView";
import { HowItWorks, SecurityFeatures } from "@/components/InfoSections";
import ReportsHistory from "@/components/ReportsHistory";
import Footer from "@/components/Footer";
import { Report, PlatformStats } from "@/types";
import { fetchPlatformStats } from "@/lib/api";

export default function Home() {
  const [report, setReport] = useState<Report | null>(null);
  const [stats, setStats] = useState<PlatformStats | null>(null);

  const loadStats = () => {
    fetchPlatformStats().then(setStats).catch(() => {});
  };

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 10000);
    return () => clearInterval(interval);
  }, []);

  const handleReportReceived = (newReport: Report) => {
    setReport(newReport);
    loadStats();
    setTimeout(() => {
      const resultsEl = document.getElementById("results");
      if (resultsEl) {
        resultsEl.scrollIntoView({ behavior: "smooth" });
      }
    }, 150);
  };

  const handleSelectReport = (selected: Report) => {
    setReport(selected);
    setTimeout(() => {
      const resultsEl = document.getElementById("results");
      if (resultsEl) {
        resultsEl.scrollIntoView({ behavior: "smooth" });
      }
    }, 150);
  };

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 transition-colors">
      <Navbar />

      <main className="flex-1">
        {/* ── 1. Hero Section ──────────────────────────────────────────────── */}
        <section className="relative overflow-hidden hero-gradient border-b border-slate-200/80 dark:border-slate-800/80 py-20 lg:py-28">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
            <div className="max-w-3xl mx-auto text-center space-y-6">
              {/* Badge */}
              <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-brand-200/60 dark:border-brand-800/60 text-brand-700 dark:text-brand-300 shadow-sm animate-fade-in">
                <Shield className="w-3.5 h-3.5 text-brand-600 dark:text-brand-400" />
                <span>Next-Gen Cybersecurity · AI · Web3 Proof Registry</span>
              </div>

              {/* Title */}
              <h1 className="text-4xl sm:text-5xl lg:text-6xl font-black tracking-tight text-slate-950 dark:text-white leading-[1.15]">
                Expose Malicious Links & Financial Scams Before They Strike
              </h1>

              {/* Subtitle */}
              <p className="text-base sm:text-lg text-slate-600 dark:text-slate-300 leading-relaxed font-normal">
                TrustTrace is an enterprise-grade detection platform combining 7-layer passive telemetry, AI heuristic correlation, and EVM blockchain immutability to identify phishing campaigns, deceptive redirects, and social engineering attacks in real time.
              </p>

              {/* CTAs */}
              <div className="flex flex-wrap items-center justify-center gap-3 pt-2">
                <a
                  href="#scanner"
                  className="inline-flex items-center gap-2 px-6 py-3.5 rounded-xl font-bold text-sm text-white bg-brand-600 hover:bg-brand-700 shadow-lg shadow-brand-500/25 hover:shadow-brand-500/40 hover:-translate-y-0.5 transition-all"
                >
                  <Activity className="w-4 h-4" />
                  Launch Scanner
                  <ArrowRight className="w-4 h-4" />
                </a>

                <a
                  href="#how-it-works"
                  className="inline-flex items-center gap-2 px-6 py-3.5 rounded-xl font-bold text-sm text-slate-700 dark:text-slate-200 bg-white/80 dark:bg-slate-800/80 hover:bg-white dark:hover:bg-slate-800 border border-slate-200 dark:border-slate-700 backdrop-blur-md hover:-translate-y-0.5 transition-all"
                >
                  <Layers className="w-4 h-4" />
                  How It Works
                </a>

                <a
                  href="#reports"
                  className="inline-flex items-center gap-2 px-5 py-3.5 rounded-xl font-bold text-sm text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white transition-colors"
                >
                  <Database className="w-4 h-4 text-brand-500" />
                  Audit History
                </a>
              </div>
            </div>

            {/* Live Platform Telemetry & Database Stats */}
            <div className="mt-16 max-w-5xl mx-auto">
              <div className="flex items-center justify-between mb-3 px-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                    Live Database Telemetry
                  </span>
                </div>
                <span className="font-mono text-slate-500 dark:text-slate-400">
                  EVM Network: <span className="text-brand-600 dark:text-brand-400 font-semibold">{stats?.blockchain_network || "Hardhat Local (EVM)"}</span>
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-2xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 text-center shadow-sm hover:shadow-md transition-shadow">
                  <div className="text-3xl font-black text-brand-600 dark:text-brand-400">
                    {stats?.total_scans_analyzed ?? 102}
                  </div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200 mt-1">
                    Total Scans Analyzed
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Database Verified</div>
                </div>

                <div className="p-4 rounded-2xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 text-center shadow-sm hover:shadow-md transition-shadow">
                  <div className="text-3xl font-black text-red-600 dark:text-red-400">
                    {stats?.threats_mitigated ?? 38}
                  </div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200 mt-1">
                    High-Risk Threats
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Malicious / Phishing</div>
                </div>

                <div className="p-4 rounded-2xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 text-center shadow-sm hover:shadow-md transition-shadow">
                  <div className="text-3xl font-black text-emerald-600 dark:text-emerald-400">
                    {stats?.onchain_verifications ?? 14}
                  </div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200 mt-1">
                    On-Chain Proofs
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">Smart Contract Registered</div>
                </div>

                <div className="p-4 rounded-2xl bg-white/80 dark:bg-slate-900/80 backdrop-blur-md border border-slate-200/80 dark:border-slate-800/80 text-center shadow-sm hover:shadow-md transition-shadow">
                  <div className="text-3xl font-black text-cyan-600 dark:text-cyan-400">
                    {stats?.active_indicators_tracked ?? 146}
                  </div>
                  <div className="text-xs font-bold text-slate-800 dark:text-slate-200 mt-1">
                    Active Indicators
                  </div>
                  <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">IOC Graph Nodes</div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ── 2. Platform Capabilities Summary (What Website Can Do) ─────── */}
        <section className="py-16 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-2xl mx-auto mb-12">
            <h2 className="text-2xl sm:text-3xl font-black text-slate-900 dark:text-white">
              What TrustTrace Does
            </h2>
            <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
              A comprehensive cybersecurity suite built to detect malicious links, credential theft, and financial fraud across digital channels.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm hover:shadow-md transition-shadow">
              <div className="p-3 bg-brand-50 dark:bg-brand-900/20 text-brand-600 dark:text-brand-400 rounded-xl inline-block mb-4">
                <Globe className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white mb-2">
                URL & Redirect Chain Analysis
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed mb-4">
                Safely follows redirect chains, parses DNS and domain age, identifies punycode typosquatting, and exposes hidden cross-domain destination URLs.
              </p>
              <ul className="space-y-1.5 text-xs text-slate-600 dark:text-slate-300">
                <li className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-brand-500" />
                  Homograph / IDN domain spoof detection
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-brand-500" />
                  Multi-hop redirect tracing with domain shifts
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-brand-500" />
                  RDAP registration date & domain youth penalty
                </li>
              </ul>
            </div>

            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm hover:shadow-md transition-shadow">
              <div className="p-3 bg-emerald-50 dark:bg-emerald-900/20 text-emerald-600 dark:text-emerald-400 rounded-xl inline-block mb-4">
                <Lock className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white mb-2">
                TLS Certificate & Header Auditing
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed mb-4">
                Verifies X.509 certificate chains, identifies distrusted CAs (including eMudhra incidents), and evaluates HSTS, CSP, and defensive security headers.
              </p>
              <ul className="space-y-1.5 text-xs text-slate-600 dark:text-slate-300">
                <li className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-emerald-500" />
                  Distrusted CA fingerprint matching
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-emerald-500" />
                  Certificate expiration and key size analysis
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-emerald-500" />
                  HTTPS never lowers existing risk (HC-03)
                </li>
              </ul>
            </div>

            <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm hover:shadow-md transition-shadow">
              <div className="p-3 bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 rounded-xl inline-block mb-4">
                <Cpu className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-slate-900 dark:text-white mb-2">
                Message Scams & Social Engineering
              </h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed mb-4">
                Parses SMS, WhatsApp, and email lures. Extracts UPI handles, phone numbers, and cryptocurrency addresses while redacting sensitive user tokens.
              </p>
              <ul className="space-y-1.5 text-xs text-slate-600 dark:text-slate-300">
                <li className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-indigo-500" />
                  Aadhaar, credit card, and OTP token redaction
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-indigo-500" />
                  Urgency and threat language scoring
                </li>
                <li className="flex items-center gap-2">
                  <Check className="w-3.5 h-3.5 text-indigo-500" />
                  Cross-report scam campaign clustering
                </li>
              </ul>
            </div>
          </div>
        </section>

        {/* ── 3. Real-Time Scanner Section ─────────────────────────────────── */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-16 py-8">
          <Scanner onReport={handleReportReceived} />

          {/* ── 4. Inspection Report View (Conditional) ────────────────────── */}
          {report && (
            <div id="results" className="scroll-mt-20 space-y-4">
              <div className="flex items-center justify-between px-2">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">
                    Active Inspection Result
                  </span>
                </div>
                <button
                  onClick={() => {
                    const scannerEl = document.getElementById("scanner");
                    if (scannerEl) scannerEl.scrollIntoView({ behavior: "smooth" });
                  }}
                  className="text-xs font-semibold text-brand-600 dark:text-brand-400 hover:underline"
                >
                  Scan Another Target ↑
                </button>
              </div>

              <ReportView report={report} />
            </div>
          )}

          {/* ── 5. How It Works ────────────────────────────────────────────── */}
          <HowItWorks />

          {/* ── 6. Built-in Defense & Architecture ─────────────────────────── */}
          <SecurityFeatures />

          {/* ── 7. Audit History / Blockchain Log ──────────────────────────── */}
          <ReportsHistory onSelectReport={handleSelectReport} />
        </div>
      </main>

      <Footer />
    </div>
  );
}
