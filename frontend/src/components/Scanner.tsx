"use client";
import React, { useState } from "react";
import {
  Shield, Link2, MessageSquare, Search, RefreshCw,
  CheckCircle2, Circle, Loader2, Sparkles, Activity
} from "lucide-react";
import { startScan, pollScan } from "@/lib/api";
import { Report } from "@/types";

const SCAN_STEPS = [
  "Validating link safety (SSRF Guard)",
  "Analysing domain & DNS telemetry",
  "Tracing HTTP redirect hops",
  "Inspecting TLS certificate chain",
  "Querying threat intelligence feeds",
  "Correlating campaign indicators",
  "Synthesizing explainable AI report",
];

interface ScannerProps {
  onReport: (report: Report) => void;
}

export default function Scanner({ onReport }: ScannerProps) {
  const [tab, setTab] = useState<"url" | "message">("url");
  const [value, setValue] = useState("");
  const [scanning, setScanning] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);
  const [stepName, setStepName] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    const v = value.trim();
    if (!v) { setError("Please enter a URL or message to analyze."); return; }
    setScanning(true); setError(null); setStepIdx(0); setStepName(SCAN_STEPS[0]);

    try {
      const init = await startScan(tab, v, false);
      const rid = init.report_id;

      const poll = setInterval(async () => {
        try {
          const s = await pollScan(rid);
          if (s.status === "failed") {
            clearInterval(poll); setScanning(false);
            setError(s.error || "Analysis encountered an issue.");
          } else if (s.status === "complete") {
            clearInterval(poll); setScanning(false);
            onReport(s.report);
          } else {
            setStepName(s.progress_step || "Analyzing...");
            setStepIdx(s.step_index || 1);
          }
        } catch {
          clearInterval(poll); setScanning(false);
          setError("Lost connection to the analysis engine.");
        }
      }, 600);
    } catch (err: any) {
      setScanning(false);
      setError(err.message || "Failed to start analysis.");
    }
  };

  return (
    <section id="scanner" className="scroll-mt-20">
      <div className="max-w-3xl mx-auto">
        <div className="relative bg-white dark:bg-[#121215] rounded-3xl border border-zinc-200 dark:border-zinc-800/80 shadow-2xl shadow-zinc-200/50 dark:shadow-black/60 overflow-hidden transition-all duration-300">
          
          {/* Animated Scanning Radar Beam */}
          {scanning && <div className="scanner-radar-beam" />}

          {/* Real-Time Stepper Progress Bar */}
          {scanning && (
            <div className="w-full bg-zinc-100 dark:bg-zinc-800/60 h-1.5 overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-emerald-500 via-teal-400 to-emerald-400 transition-all duration-500 ease-out shadow-sm shadow-emerald-500/50"
                style={{ width: `${Math.min(100, Math.max(12, ((stepIdx + 1) / SCAN_STEPS.length) * 100))}%` }}
              />
            </div>
          )}

          {/* Tab Switcher */}
          <div className="flex border-b border-zinc-200 dark:border-zinc-800/80">
            {[
              { id: "url" as const, label: "Live Link Scanner", icon: Link2 },
              { id: "message" as const, label: "Scam Message Detective", icon: MessageSquare },
            ].map(t => (
              <button
                key={t.id}
                onClick={() => { setTab(t.id); setError(null); }}
                className={`flex-1 flex items-center justify-center gap-2.5 py-4 text-xs sm:text-sm font-bold transition-all relative ${
                  tab === t.id
                    ? "text-brand-600 dark:text-emerald-400 bg-brand-50/40 dark:bg-emerald-950/20"
                    : "text-zinc-500 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200 hover:bg-zinc-50 dark:hover:bg-zinc-800/30"
                }`}
              >
                <t.icon className="w-4 h-4" />
                {t.label}
                {tab === t.id && (
                  <span className="absolute bottom-0 inset-x-0 h-0.5 bg-brand-600 dark:bg-emerald-400 shadow-sm" />
                )}
              </button>
            ))}
          </div>

          {/* Input Form */}
          <div className="p-6 sm:p-8 space-y-5">
            {tab === "url" ? (
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                    Target URL or Hostname
                  </label>
                  <span className="text-[11px] font-medium text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                    <Activity className="w-3 h-3" />
                    Passive 7-Layer Telemetry
                  </span>
                </div>

                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1 relative group">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-zinc-400 group-focus-within:text-brand-500 transition-colors">
                      <Search className="w-4 h-4" />
                    </div>
                    <input
                      type="text"
                      value={value}
                      onChange={e => setValue(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && handleScan()}
                      placeholder="e.g. suspicious-site.com or https://example.com/login"
                      className="w-full pl-10 pr-4 py-3.5 bg-zinc-50 dark:bg-[#18181c] border border-zinc-200 dark:border-zinc-700/80 rounded-2xl text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:ring-2 focus:ring-brand-500 dark:focus:ring-emerald-500 focus:border-transparent focus:outline-none transition-all shadow-inner"
                    />
                  </div>
                  <button
                    onClick={handleScan}
                    disabled={scanning}
                    className="px-7 py-3.5 bg-gradient-to-r from-brand-600 to-emerald-600 hover:from-brand-500 hover:to-emerald-500 disabled:opacity-50 text-white font-bold text-sm rounded-2xl shadow-lg shadow-brand-500/25 hover:shadow-brand-500/40 hover:-translate-y-0.5 transition-all flex items-center justify-center gap-2 shrink-0"
                  >
                    {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                    {scanning ? "Scanning..." : "Inspect Target"}
                  </button>
                </div>
                <p className="text-xs text-zinc-400 dark:text-zinc-500">
                  Strictly passive — zero script execution, response capped at 200KB, multi-layer SSRF defense.
                </p>
              </div>
            ) : (
              <div className="space-y-2.5">
                <div className="flex justify-between items-center">
                  <label className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                    Suspicious Message Lure
                  </label>
                  <span className="text-[11px] font-medium text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 px-2 py-0.5 rounded-full border border-amber-200/50 dark:border-amber-800/50">
                    Sensitive Tokens Redacted Off-Chain
                  </span>
                </div>
                <textarea
                  rows={4}
                  maxLength={5000}
                  value={value}
                  onChange={e => setValue(e.target.value)}
                  placeholder="Paste suspicious SMS, WhatsApp, or phishing email text here..."
                  className="w-full px-4 py-3 bg-zinc-50 dark:bg-[#18181c] border border-zinc-200 dark:border-zinc-700/80 rounded-2xl text-sm text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:ring-2 focus:ring-brand-500 dark:focus:ring-emerald-500 focus:border-transparent focus:outline-none transition-all shadow-inner resize-none"
                />
                <div className="flex justify-between items-center pt-1">
                  <span className="text-xs text-zinc-400 dark:text-zinc-500">{value.length} / 5,000 characters</span>
                  <button
                    onClick={handleScan}
                    disabled={scanning}
                    className="px-7 py-3 bg-gradient-to-r from-brand-600 to-emerald-600 hover:from-brand-500 hover:to-emerald-500 disabled:opacity-50 text-white font-bold text-sm rounded-2xl shadow-lg shadow-brand-500/25 hover:shadow-brand-500/40 hover:-translate-y-0.5 transition-all flex items-center gap-2"
                  >
                    {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                    {scanning ? "Analyzing..." : "Analyze Message"}
                  </button>
                </div>
              </div>
            )}

            {/* Error Notification */}
            {error && (
              <div className="p-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/60 rounded-2xl text-xs sm:text-sm text-red-700 dark:text-red-400 animate-fade-in flex items-start gap-2.5">
                <span className="p-1 rounded-md bg-red-100 dark:bg-red-900/40 shrink-0">⚠️</span>
                <div>
                  <span className="font-bold block mb-0.5">Analysis Notice:</span>
                  {error}
                </div>
              </div>
            )}

            {/* Live Progress Stepper */}
            {scanning && (
              <div className="pt-4 border-t border-zinc-100 dark:border-zinc-800/80 animate-fade-in">
                <div className="flex items-center justify-between mb-3 px-1">
                  <span className="text-xs font-bold uppercase tracking-wider text-zinc-500 dark:text-zinc-400">
                    Live Telemetry Pipeline
                  </span>
                  <span className="text-xs font-mono text-emerald-600 dark:text-emerald-400 font-semibold flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-ping" />
                    Step {stepIdx + 1} of {SCAN_STEPS.length}
                  </span>
                </div>

                <div className="space-y-1.5">
                  {SCAN_STEPS.map((step, i) => {
                    const done = i < stepIdx;
                    const current = i === stepIdx;
                    return (
                      <div
                        key={step}
                        className={`flex items-center gap-3 py-2 px-3 rounded-xl transition-all ${
                          current
                            ? "bg-brand-50 dark:bg-emerald-950/30 border border-brand-200/50 dark:border-emerald-800/50 translate-x-1"
                            : ""
                        }`}
                      >
                        {done ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                        ) : current ? (
                          <Loader2 className="w-4 h-4 text-brand-600 dark:text-emerald-400 animate-spin shrink-0" />
                        ) : (
                          <Circle className="w-4 h-4 text-zinc-300 dark:text-zinc-700 shrink-0" />
                        )}
                        <span
                          className={`text-xs sm:text-sm ${
                            done
                              ? "text-zinc-400 dark:text-zinc-500"
                              : current
                              ? "text-brand-800 dark:text-emerald-300 font-bold"
                              : "text-zinc-400 dark:text-zinc-600"
                          }`}
                        >
                          {step}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
