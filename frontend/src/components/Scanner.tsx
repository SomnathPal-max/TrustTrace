"use client";
import React, { useState, useEffect } from "react";
import {
  Shield, Link2, MessageSquare, Search, RefreshCw,
  QrCode, Layers, UploadCloud, Loader2, Sparkles, Activity,
  CheckCircle, AlertTriangle, ExternalLink, ChevronRight
} from "lucide-react";
import { startScan, pollScan, decodeQRCode, startBatchScan, fetchSamples } from "@/lib/api";
import { Report } from "@/types";
import { defang } from "@/lib/defang";

const SCAN_STEPS = [
  "Validating link safety (SSRF Guard)",
  "Analysing domain & DNS telemetry",
  "Tracing HTTP redirect hops",
  "Inspecting TLS certificate chain",
  "Querying threat intelligence feeds",
  "Correlating campaign indicators",
  "Synthesizing explainable AI report",
];

const FALLBACK_SAMPLES = [
  {
    id: "B1",
    group: "safe-looking",
    type: "url",
    title: "State Bank of India (Official)",
    value: "sbi.co.in",
    expected_label: "Low Risk",
    description: "Official State Bank of India portal verifying official-domain allow-list match."
  },
  {
    id: "B2",
    group: "safe-looking",
    type: "url",
    title: "GitHub (Official)",
    value: "github.com",
    expected_label: "Low Risk",
    description: "Popular developer platform showing valid TLS certificates and low-severity headers."
  },
  {
    id: "B3",
    group: "safe-looking",
    type: "url",
    title: "Wikipedia (Official)",
    value: "wikipedia.org",
    expected_label: "Low Risk",
    description: "Demonstrates false-positive prevention on major public informational domains."
  },
  {
    id: "S1",
    group: "suspicious",
    type: "url",
    title: "Fake SBI KYC Portal",
    value: "http://sbi-kyc-update.com/login",
    expected_label: "High Risk",
    description: "Bank brand impersonation combined with phishing keyword in domain."
  },
  {
    id: "S2",
    group: "suspicious",
    type: "url",
    title: "Punycode Google Lookalike",
    value: "http://xn--gogl-qqa.com/login",
    expected_label: "Suspicious",
    description: "Internationalized domain with confusable characters mimicking google."
  },
  {
    id: "S3",
    group: "suspicious",
    type: "message",
    title: "Urgent Bank Threat SMS",
    value: "URGENT: Your SBI bank account will be blocked within 2 hours. Update your PAN card and Aadhaar details immediately to avoid deactivation: http://sbi-kyc-update.com/pan. We will never ask for your password.",
    expected_label: "High Risk",
    description: "Social engineering urgency, threat of suspension, sensitive data lure, and extracted malicious link."
  }
];

interface ScannerProps {
  onReport: (report: Report) => void;
}

export default function Scanner({ onReport }: ScannerProps) {
  const [tab, setTab] = useState<"url" | "message" | "qr" | "batch">("url");
  const [value, setValue] = useState("");
  const [scanning, setScanning] = useState(false);
  const [stepIdx, setStepIdx] = useState(0);
  const [stepName, setStepName] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Cached evaluation & demo test suite
  const [useCached, setUseCached] = useState(false);
  const [samples, setSamples] = useState<any[]>(FALLBACK_SAMPLES);

  useEffect(() => {
    let mounted = true;
    fetchSamples()
      .then((data) => {
        if (mounted && data?.demo_samples && Array.isArray(data.demo_samples)) {
          setSamples(data.demo_samples);
        }
      })
      .catch(() => {
        // Fallback remains active
      });
    return () => {
      mounted = false;
    };
  }, []);

  // QR state
  const [qrFile, setQrFile] = useState<File | null>(null);
  const [qrDecoding, setQrDecoding] = useState(false);
  const [qrDecodedText, setQrDecodedText] = useState<string | null>(null);

  // Batch state
  const [batchInput, setBatchInput] = useState("");
  const [batchRunning, setBatchRunning] = useState(false);
  const [batchResults, setBatchResults] = useState<Array<{ report_id: string; target: string; status: string; report?: Report }>>([]);

  const executeSingleScan = async (scanType: "url" | "message", scanVal: string, cachedMode?: boolean) => {
    const isCached = cachedMode !== undefined ? cachedMode : useCached;
    setScanning(true);
    setError(null);
    setStepIdx(0);
    setStepName(SCAN_STEPS[0]);

    try {
      const init = await startScan(scanType, scanVal, isCached);
      const rid = init.report_id;

      const poll = setInterval(async () => {
        try {
          const s = await pollScan(rid);
          if (s.status === "failed") {
            clearInterval(poll);
            setScanning(false);
            setError(s.error || "Analysis encountered an issue.");
          } else if (s.status === "complete") {
            clearInterval(poll);
            setScanning(false);
            onReport(s.report);
          } else {
            setStepName(s.progress_step || "Analyzing...");
            setStepIdx(s.step_index || 1);
          }
        } catch {
          clearInterval(poll);
          setScanning(false);
          setError("Lost connection to the analysis engine.");
        }
      }, 600);
    } catch (err: any) {
      setScanning(false);
      setError(err.message || "Failed to start analysis.");
    }
  };

  const handleSampleClick = (sample: any) => {
    const scanType = sample.type as "url" | "message";
    setTab(scanType);
    setValue(sample.value);
    executeSingleScan(scanType, sample.value, useCached);
  };

  const handleScan = () => {
    const v = value.trim();
    if (!v) {
      setError("Please enter a URL or message to analyze.");
      return;
    }
    executeSingleScan(tab as "url" | "message", v, useCached);
  };

  const handleQRFile = async (file: File) => {
    setQrFile(file);
    setQrDecoding(true);
    setError(null);
    setQrDecodedText(null);

    try {
      const res = await decodeQRCode(file);
      setQrDecodedText(res.decoded_content);
      // Auto-trigger scan on the extracted target
      executeSingleScan(res.input_type, res.decoded_content, useCached);
    } catch (err: any) {
      setError(err.message || "Failed to decode QR code.");
    } finally {
      setQrDecoding(false);
    }
  };

  const handleBatchScan = async () => {
    const lines = batchInput.split("\n").map(l => l.trim()).filter(Boolean);
    if (lines.length === 0) {
      setError("Please enter at least one URL (one per line, up to 10).");
      return;
    }
    setBatchRunning(true);
    setError(null);

    try {
      const init = await startBatchScan(lines);
      const initialJobs = init.jobs.map((j: any) => ({
        report_id: j.report_id,
        target: j.target,
        status: "queued"
      }));
      setBatchResults(initialJobs);

      // Poll each job
      initialJobs.forEach((job: any) => {
        const interval = setInterval(async () => {
          try {
            const s = await pollScan(job.report_id);
            if (s.status === "complete" || s.status === "failed") {
              clearInterval(interval);
              setBatchResults(prev => prev.map(item => item.report_id === job.report_id ? {
                ...item,
                status: s.status,
                report: s.report
              } : item));
            }
          } catch {
            clearInterval(interval);
          }
        }, 1000);
      });
    } catch (err: any) {
      setError(err.message || "Failed to execute batch scan.");
    } finally {
      setBatchRunning(false);
    }
  };

  return (
    <section id="scanner" className="scroll-mt-20">
      <div className="max-w-3xl mx-auto">
        <div className="cyber-card relative bg-white dark:bg-[#121215] rounded-3xl border border-zinc-200 dark:border-zinc-800/80 shadow-2xl shadow-zinc-200/50 dark:shadow-black/60 overflow-hidden transition-all duration-300">
          
          {/* Animated Scanning Radar Beam */}
          {(scanning || qrDecoding) && <div className="scanner-radar-beam" />}

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
          <div className="grid grid-cols-2 sm:grid-cols-4 border-b border-zinc-200 dark:border-zinc-800/80">
            {[
              { id: "url" as const, label: "Live Link", icon: Link2 },
              { id: "message" as const, label: "Message Scam", icon: MessageSquare },
              { id: "qr" as const, label: "QR Quishing", icon: QrCode },
              { id: "batch" as const, label: "Bulk Audit", icon: Layers },
            ].map(t => (
              <button
                key={t.id}
                onClick={() => { setTab(t.id); setError(null); }}
                className={`flex items-center justify-center gap-2 py-3.5 px-2 text-xs sm:text-sm font-bold transition-all relative ${
                  tab === t.id
                    ? "text-brand-600 dark:text-emerald-400 bg-brand-50/40 dark:bg-emerald-950/20"
                    : "text-zinc-500 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200 hover:bg-zinc-50 dark:hover:bg-zinc-800/30"
                }`}
              >
                <t.icon className="w-4 h-4 shrink-0" />
                <span className="truncate">{t.label}</span>
                {tab === t.id && (
                  <span className="absolute bottom-0 inset-x-0 h-0.5 bg-brand-600 dark:bg-emerald-400 shadow-sm" />
                )}
              </button>
            ))}
          </div>

          {/* Form Content */}
          <div className="p-6 sm:p-8 space-y-5">
            {/* 1. URL SCAN */}
            {tab === "url" && (
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
            )}

            {/* 2. MESSAGE SCAN */}
            {tab === "message" && (
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

            {/* 3. QR QUISHING SCAN (Option 2) */}
            {tab === "qr" && (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <label className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                    Quishing Defense: Upload QR Code Image
                  </label>
                  <span className="text-[11px] font-medium text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 px-2 py-0.5 rounded-full border border-emerald-200/50 dark:border-emerald-800/50">
                    OpenCV Computer Vision
                  </span>
                </div>

                <div
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                      handleQRFile(e.dataTransfer.files[0]);
                    }
                  }}
                  className="border-2 border-dashed border-zinc-200 dark:border-zinc-800 hover:border-brand-500 dark:hover:border-brand-500 rounded-3xl p-8 text-center transition-colors bg-zinc-50/50 dark:bg-[#18181c]/50 relative group cursor-pointer"
                  onClick={() => document.getElementById("qr-input")?.click()}
                >
                  <input
                    id="qr-input"
                    type="file"
                    accept="image/*"
                    className="hidden"
                    onChange={(e) => {
                      if (e.target.files && e.target.files[0]) {
                        handleQRFile(e.target.files[0]);
                      }
                    }}
                  />
                  <div className="p-3 bg-brand-50 dark:bg-brand-950/50 rounded-2xl text-brand-600 dark:text-brand-400 inline-block mb-3 group-hover:scale-110 transition-transform">
                    {qrDecoding ? <Loader2 className="w-8 h-8 animate-spin" /> : <QrCode className="w-8 h-8" />}
                  </div>
                  <h4 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
                    {qrDecoding ? "Decoding QR Matrix..." : "Drop QR Code Image Here"}
                  </h4>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 max-w-sm mx-auto">
                    Supports PNG, JPG, WebP. Automatically extracts embedded phishing URL and executes 7-layer passive inspection.
                  </p>
                </div>

                {qrDecodedText && (
                  <div className="p-3.5 rounded-2xl bg-emerald-50/50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-800 text-xs animate-fade-in flex items-center justify-between">
                    <div>
                      <span className="font-bold text-emerald-800 dark:text-emerald-300 block mb-0.5">Decoded QR Destination:</span>
                      <code className="font-mono text-zinc-700 dark:text-zinc-300">{defang(qrDecodedText)}</code>
                    </div>
                    <span className="text-[11px] font-semibold text-emerald-600 dark:text-emerald-400">Inspecting Target →</span>
                  </div>
                )}
              </div>
            )}

            {/* 4. BULK / BATCH SCAN (Option 3) */}
            {tab === "batch" && (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <label className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                    Bulk Domain Audit (Up to 10 Targets)
                  </label>
                  <span className="text-[11px] font-mono text-zinc-500">
                    1 URL per line
                  </span>
                </div>

                <textarea
                  rows={4}
                  value={batchInput}
                  onChange={(e) => setBatchInput(e.target.value)}
                  placeholder="https://sbi.co.in&#10;https://expired.badssl.com&#10;http://sbi-kyc-update.com/login"
                  className="w-full px-4 py-3 bg-zinc-50 dark:bg-[#18181c] border border-zinc-200 dark:border-zinc-700/80 rounded-2xl text-xs font-mono text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:ring-2 focus:ring-brand-500 dark:focus:ring-emerald-500 focus:outline-none transition-all shadow-inner"
                />

                <div className="flex justify-between items-center">
                  <span className="text-xs text-zinc-500">
                    {batchInput.split("\n").filter(Boolean).length} targets queued
                  </span>
                  <button
                    onClick={handleBatchScan}
                    disabled={batchRunning}
                    className="px-6 py-2.5 bg-gradient-to-r from-brand-600 to-emerald-600 hover:from-brand-500 hover:to-emerald-500 disabled:opacity-50 text-white font-bold text-xs rounded-xl shadow-md transition-all flex items-center gap-2"
                  >
                    {batchRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Layers className="w-3.5 h-3.5" />}
                    {batchRunning ? "Dispatching..." : "Launch Batch Audit"}
                  </button>
                </div>

                {/* Batch Comparative Table */}
                {batchResults.length > 0 && (
                  <div className="mt-4 border border-zinc-200 dark:border-zinc-800 rounded-2xl overflow-hidden animate-fade-in text-xs">
                    <div className="bg-zinc-100 dark:bg-[#18181c] px-3.5 py-2 font-bold text-zinc-700 dark:text-zinc-300 border-b border-zinc-200 dark:border-zinc-800">
                      Batch Inspection Progress
                    </div>
                    <div className="divide-y divide-zinc-100 dark:divide-zinc-800">
                      {batchResults.map((job) => (
                        <div key={job.report_id} className="p-3 flex items-center justify-between hover:bg-zinc-50 dark:hover:bg-[#18181c]/50">
                          <span className="font-mono text-zinc-800 dark:text-zinc-200 truncate max-w-xs">
                            {defang(job.target)}
                          </span>
                          <div className="flex items-center gap-3">
                            {job.status === "complete" && job.report ? (
                              <>
                                <span className="font-bold px-2 py-0.5 rounded text-[11px] bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-400">
                                  {job.report.risk_label} ({job.report.risk_score})
                                </span>
                                <button
                                  onClick={() => onReport(job.report!)}
                                  className="text-brand-600 dark:text-brand-400 font-bold hover:underline flex items-center gap-1"
                                >
                                  View
                                  <ChevronRight className="w-3 h-3" />
                                </button>
                              </>
                            ) : (
                              <span className="flex items-center gap-1.5 text-zinc-400">
                                <Loader2 className="w-3 h-3 animate-spin text-brand-500" />
                                Analyzing...
                              </span>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Benchmark Demo Test Suite & One-Click Samples */}
            <div className="pt-5 border-t border-zinc-200/80 dark:border-zinc-800/80 space-y-3.5">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5">
                <div className="flex items-center gap-2">
                  <div className="p-1 rounded-md bg-brand-50 dark:bg-emerald-950/50 text-brand-600 dark:text-emerald-400">
                    <Sparkles className="w-3.5 h-3.5" />
                  </div>
                  <span className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300">
                    Demo Test Suite & Benchmark Samples
                  </span>
                </div>

                <div className="flex items-center gap-2.5 bg-zinc-50 dark:bg-[#18181c] px-3 py-1.5 rounded-xl border border-zinc-200/60 dark:border-zinc-800">
                  <span className="text-[11px] font-medium text-zinc-600 dark:text-zinc-400">
                    Use Cached Telemetry (Offline Mode)
                  </span>
                  <button
                    type="button"
                    role="switch"
                    aria-checked={useCached}
                    onClick={() => setUseCached(!useCached)}
                    className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none ${
                      useCached ? "bg-emerald-500" : "bg-zinc-300 dark:bg-zinc-700"
                    }`}
                  >
                    <span
                      aria-hidden="true"
                      className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-white shadow-md ring-0 transition duration-200 ease-in-out ${
                        useCached ? "translate-x-4" : "translate-x-0"
                      }`}
                    />
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                {samples.map((sample) => {
                  const isBenign = sample.id.startsWith("B");
                  return (
                    <button
                      key={sample.id}
                      type="button"
                      onClick={() => handleSampleClick(sample)}
                      disabled={scanning}
                      className="group relative flex flex-col p-3 rounded-2xl bg-zinc-50 dark:bg-[#18181c] hover:bg-zinc-100 dark:hover:bg-[#202026] border border-zinc-200/70 dark:border-zinc-800/80 hover:border-brand-500/50 dark:hover:border-emerald-500/50 transition-all text-left shadow-sm disabled:opacity-50"
                    >
                      <div className="flex items-center justify-between w-full mb-1">
                        <span
                          className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            isBenign
                              ? "bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300"
                              : "bg-rose-100 dark:bg-rose-950/60 text-rose-700 dark:text-rose-300"
                          }`}
                        >
                          {sample.id}
                        </span>
                        <span
                          className={`text-[10px] font-semibold px-2 py-0.5 rounded-full border ${
                            sample.expected_label === "Low Risk"
                              ? "bg-emerald-50 dark:bg-emerald-950/40 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-800/60"
                              : sample.expected_label === "Suspicious"
                              ? "bg-amber-50 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-800/60"
                              : "bg-rose-50 dark:bg-rose-950/40 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-800/60"
                          }`}
                        >
                          {sample.expected_label}
                        </span>
                      </div>
                      <div className="font-bold text-xs text-zinc-900 dark:text-zinc-100 group-hover:text-brand-600 dark:group-hover:text-emerald-400 transition-colors truncate">
                        {sample.title}
                      </div>
                      <div className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400 truncate mt-0.5">
                        {sample.type === "message" ? "SMS Lure: 'URGENT: Your SBI...'" : sample.value}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Error Notification */}
            {error && (
              <div className="p-4 bg-red-50 dark:bg-red-950/30 border border-red-200 dark:border-red-900/60 rounded-2xl text-xs sm:text-sm text-red-700 dark:text-red-400 animate-fade-in flex items-start gap-2.5">
                <span className="p-1 rounded-md bg-red-100 dark:bg-red-900/40 shrink-0">⚠️</span>
                <div>
                  <span className="font-bold block mb-0.5">Notice:</span>
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
                  {SCAN_STEPS.map((step, idx) => (
                    <div
                      key={idx}
                      className={`flex items-center gap-2.5 px-3 py-1.5 rounded-xl text-xs transition-all ${
                        idx === stepIdx
                          ? "bg-brand-50 dark:bg-brand-950/40 text-brand-700 dark:text-emerald-300 font-bold border border-brand-200/60 dark:border-brand-800/60"
                          : idx < stepIdx
                          ? "text-emerald-600 dark:text-emerald-400/80 font-medium"
                          : "text-zinc-400 dark:text-zinc-600"
                      }`}
                    >
                      {idx < stepIdx ? (
                        <CheckCircle className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                      ) : idx === stepIdx ? (
                        <Loader2 className="w-3.5 h-3.5 text-brand-500 animate-spin shrink-0" />
                      ) : (
                        <div className="w-3.5 h-3.5 rounded-full border border-zinc-300 dark:border-zinc-700 shrink-0" />
                      )}
                      <span className="truncate">{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
