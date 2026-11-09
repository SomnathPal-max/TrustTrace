"use client";
import React, { useState } from "react";
import {
  Shield, Link2, MessageSquare, Search, RefreshCw,
  CheckCircle2, Circle, Loader2
} from "lucide-react";
import { startScan, pollScan } from "@/lib/api";
import { Report } from "@/types";

const SCAN_STEPS = [
  "Validating link safety",
  "Analysing domain & DNS",
  "Following redirects",
  "Inspecting TLS certificate",
  "Checking threat intelligence",
  "Correlating with earlier reports",
  "Generating AI explanation",
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
        <div className="bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-xl shadow-slate-200/50 dark:shadow-black/20 overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-slate-200 dark:border-slate-800">
            {[
              { id: "url" as const, label: "Link Scanner", icon: Link2 },
              { id: "message" as const, label: "Message Scanner", icon: MessageSquare },
            ].map(t => (
              <button
                key={t.id}
                onClick={() => { setTab(t.id); setError(null); }}
                className={`flex-1 flex items-center justify-center gap-2 py-4 text-sm font-semibold transition-colors ${
                  tab === t.id
                    ? "text-brand-600 dark:text-brand-400 border-b-2 border-brand-600 dark:border-brand-400 bg-brand-50/50 dark:bg-brand-900/10"
                    : "text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800/50"
                }`}
              >
                <t.icon className="w-4 h-4" />
                {t.label}
              </button>
            ))}
          </div>

          {/* Input area */}
          <div className="p-6 space-y-4">
            {tab === "url" ? (
              <div className="space-y-2">
                <label className="text-sm font-semibold text-slate-700 dark:text-slate-300">Website URL or Domain</label>
                <div className="flex gap-3">
                  <div className="flex-1 relative">
                    <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                      <Search className="w-4 h-4 text-slate-400" />
                    </div>
                    <input
                      type="text"
                      value={value}
                      onChange={e => setValue(e.target.value)}
                      onKeyDown={e => e.key === "Enter" && handleScan()}
                      placeholder="e.g. suspicious-site.com or https://example.com/login"
                      className="w-full pl-10 pr-4 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:ring-2 focus:ring-brand-500 focus:border-brand-500 focus:outline-none transition"
                    />
                  </div>
                  <button
                    onClick={handleScan}
                    disabled={scanning}
                    className="px-6 py-3 bg-brand-600 hover:bg-brand-700 disabled:opacity-50 text-white font-semibold text-sm rounded-xl shadow-lg shadow-brand-600/25 transition flex items-center gap-2 shrink-0"
                  >
                    {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                    Analyze
                  </button>
                </div>
                <p className="text-xs text-slate-400 dark:text-slate-500">
                  Passive inspection only — no scripts executed, no files downloaded, all private addresses blocked.
                </p>
              </div>
            ) : (
              <div className="space-y-2">
                <div className="flex justify-between items-center">
                  <label className="text-sm font-semibold text-slate-700 dark:text-slate-300">Suspicious Message Content</label>
                  <span className="text-xs font-medium text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 px-2 py-0.5 rounded-full border border-amber-200 dark:border-amber-800">
                    Never paste passwords or OTPs
                  </span>
                </div>
                <textarea
                  rows={4}
                  maxLength={5000}
                  value={value}
                  onChange={e => setValue(e.target.value)}
                  placeholder="Paste the suspicious SMS, WhatsApp, or email text here..."
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-xl text-sm text-slate-900 dark:text-white placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:ring-2 focus:ring-brand-500 focus:border-brand-500 focus:outline-none transition resize-none"
                />
                <div className="flex justify-between items-center">
                  <span className="text-xs text-slate-400 dark:text-slate-500">{value.length} / 5,000 characters</span>
                  <button
                    onClick={handleScan}
                    disabled={scanning}
                    className="px-6 py-2.5 bg-brand-600 hover:bg-brand-700 disabled:opacity-50 text-white font-semibold text-sm rounded-xl shadow-lg shadow-brand-600/25 transition flex items-center gap-2"
                  >
                    {scanning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                    Analyze Message
                  </button>
                </div>
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-xl text-sm text-red-700 dark:text-red-400 animate-fade-in">
                {error}
              </div>
            )}

            {/* Stepper */}
            {scanning && (
              <div className="pt-4 border-t border-slate-100 dark:border-slate-800 animate-fade-in">
                <div className="space-y-2">
                  {SCAN_STEPS.map((step, i) => {
                    const done = i < stepIdx;
                    const current = i === stepIdx;
                    return (
                      <div key={step} className={`flex items-center gap-3 py-1.5 px-3 rounded-lg transition-colors ${current ? "bg-brand-50 dark:bg-brand-900/20" : ""}`}>
                        {done ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                        ) : current ? (
                          <Loader2 className="w-4 h-4 text-brand-600 dark:text-brand-400 animate-spin shrink-0" />
                        ) : (
                          <Circle className="w-4 h-4 text-slate-300 dark:text-slate-600 shrink-0" />
                        )}
                        <span className={`text-sm ${done ? "text-slate-500 dark:text-slate-400" : current ? "text-brand-700 dark:text-brand-300 font-semibold" : "text-slate-400 dark:text-slate-500"}`}>
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
