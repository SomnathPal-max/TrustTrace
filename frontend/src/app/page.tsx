"use client";

import React, { useState, useEffect } from "react";
import {
  Shield, AlertTriangle, CheckCircle, XCircle, Info, ExternalLink,
  ChevronDown, ChevronRight, Copy, Check, RefreshCw, Lock, Database,
  Cpu, History, ArrowRight, Eye, AlertOctagon, Terminal, AlertCircle
} from "lucide-react";
import { Report, RiskLabel, DemoSample } from "@/types";
import { defang } from "@/lib/defang";
import {
  fetchHealth, fetchSecurityControls, fetchSamples, startScan,
  pollScan, commitReport, verifyReport, tamperReport, restoreReport,
  fetchReportsList
} from "@/lib/api";

const SCAN_STEPS = [
  "Validating link safety",
  "Analysing domain",
  "Following redirects",
  "Inspecting certificate",
  "Checking threat intelligence",
  "Correlating with earlier reports",
  "Writing explanation"
];

export default function Home() {
  const [activeTab, setActiveTab] = useState<"url" | "message">("url");
  const [inputValue, setInputValue] = useState("");
  const [useCached, setUseCached] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanStepIndex, setScanStepIndex] = useState(0);
  const [currentStepName, setCurrentStepName] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Security controls modal
  const [showControls, setShowControls] = useState(false);
  const [controlsData, setControlsData] = useState<any[]>([]);

  // History modal
  const [showHistory, setShowHistory] = useState(false);
  const [historyReports, setHistoryReports] = useState<any[]>([]);

  // Web3 state
  const [isCommitting, setIsCommitting] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any | null>(null);
  const [tamperState, setTamperState] = useState<string | null>(null);

  // Demo samples from backend
  const [samples, setSamples] = useState<{ demo_samples: DemoSample[]; extra_tests: DemoSample[] }>({
    demo_samples: [],
    extra_tests: []
  });

  useEffect(() => {
    fetchSamples().then(setSamples).catch(() => {});
    fetchSecurityControls().then(d => setControlsData(d.active_protections || [])).catch(() => {});
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleLoadSample = (s: DemoSample) => {
    setActiveTab(s.type);
    setInputValue(s.value);
    setReport(null);
    setErrorMsg(null);
    setVerificationResult(null);
  };

  const handleStartScan = async (overrideValue?: string, overrideType?: "url" | "message") => {
    const val = overrideValue || inputValue;
    const type = overrideType || activeTab;

    if (!val.trim()) {
      setErrorMsg("Please provide a valid URL or message content to inspect.");
      return;
    }

    setIsScanning(true);
    setReport(null);
    setErrorMsg(null);
    setVerificationResult(null);
    setScanStepIndex(0);
    setCurrentStepName(SCAN_STEPS[0]);

    try {
      const init = await startScan(type, val.trim(), useCached);
      const reportId = init.report_id;

      // Poll scan progress
      const pollInterval = setInterval(async () => {
        try {
          const statusRes = await pollScan(reportId);
          if (statusRes.status === "failed") {
            clearInterval(pollInterval);
            setIsScanning(false);
            setErrorMsg(statusRes.error || "Inspection encountered a safety restriction.");
          } else if (statusRes.status === "complete") {
            clearInterval(pollInterval);
            setIsScanning(false);
            setReport(statusRes.report);
          } else {
            setCurrentStepName(statusRes.progress_step || "Analyzing...");
            setScanStepIndex(statusRes.step_index || 1);
          }
        } catch (err) {
          clearInterval(pollInterval);
          setIsScanning(false);
          setErrorMsg("Connection to scan engine lost. Retrying...");
        }
      }, 700);
    } catch (err: any) {
      setIsScanning(false);
      setErrorMsg(err.message || "Failed to initiate scan.");
    }
  };

  const handleCommit = async () => {
    if (!report) return;
    setIsCommitting(true);
    try {
      const res = await commitReport(report.report_id);
      setReport(prev => prev ? { ...prev, web3: res, report_hash: res.report_hash } : null);
      setVerificationResult(null);
    } catch (err: any) {
      alert(err.message || "Commit failed");
    } finally {
      setIsCommitting(false);
    }
  };

  const handleVerify = async () => {
    if (!report) return;
    setIsVerifying(true);
    try {
      const res = await verifyReport(report.report_id);
      setVerificationResult(res);
    } catch (err: any) {
      alert(err.message || "Verification failed");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleTamper = async () => {
    if (!report) return;
    try {
      const res = await tamperReport(report.report_id);
      setTamperState("Tampered (Simulated alteration applied in DB)");
      // Automatically verify to prove MISMATCH
      const v = await verifyReport(report.report_id);
      setVerificationResult(v);
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleRestore = async () => {
    if (!report) return;
    try {
      const res = await restoreReport(report.report_id);
      setTamperState(null);
      // Automatically verify to prove MATCH again
      const v = await verifyReport(report.report_id);
      setVerificationResult(v);
    } catch (err: any) {
      alert(err.message);
    }
  };

  const openHistory = async () => {
    setShowHistory(true);
    try {
      const data = await fetchReportsList();
      setHistoryReports(data.reports || []);
    } catch (e) {}
  };

  const getRiskColor = (label: RiskLabel) => {
    switch (label) {
      case "Low Risk":
        return "bg-emerald-500/10 text-emerald-700 border-emerald-500/30";
      case "Suspicious":
        return "bg-amber-500/10 text-amber-700 border-amber-500/30";
      case "High Risk":
        return "bg-orange-500/10 text-orange-700 border-orange-500/30";
      case "Confirmed Malicious":
        return "bg-red-500/10 text-red-700 border-red-500/30";
      case "Inconclusive":
      default:
        return "bg-slate-500/10 text-slate-700 border-slate-500/30";
    }
  };

  const getRiskIcon = (label: RiskLabel) => {
    switch (label) {
      case "Low Risk":
        return <CheckCircle className="w-6 h-6 text-emerald-600" />;
      case "Suspicious":
        return <AlertTriangle className="w-6 h-6 text-amber-600" />;
      case "High Risk":
        return <AlertOctagon className="w-6 h-6 text-orange-600" />;
      case "Confirmed Malicious":
        return <XCircle className="w-6 h-6 text-red-600" />;
      case "Inconclusive":
      default:
        return <Info className="w-6 h-6 text-slate-600" />;
    }
  };

  return (
    <div className="max-w-6xl mx-auto px-4 py-8 space-y-8 font-sans">
      {/* HEADER */}
      <header className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-6 border-b border-slate-200 gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-600 rounded-xl text-white shadow-md">
              <Shield className="w-7 h-7" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-slate-900">
                Link & Scam Detective
              </h1>
              <p className="text-xs text-slate-500 font-medium">
                AI-Powered Web Threat Detection & Digital Trust Intelligence · Team APEX WARCODE (HM-6FC44F)
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowControls(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-50 text-emerald-700 border border-emerald-300 hover:bg-emerald-100 transition shadow-sm"
          >
            <Lock className="w-3.5 h-3.5" />
            Security Controls Active
          </button>

          <button
            onClick={openHistory}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-100 text-slate-700 border border-slate-300 hover:bg-slate-200 transition shadow-sm"
          >
            <History className="w-3.5 h-3.5" />
            Reports Log
          </button>
        </div>
      </header>

      {/* QUICK TEST PANEL (3 Benign + 3 Suspicious) */}
      <section className="bg-white rounded-xl p-5 border border-slate-200 shadow-sm space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <h2 className="text-xs font-bold text-slate-600 uppercase tracking-wider flex items-center gap-2">
            <Terminal className="w-4 h-4 text-slate-500" />
            1-Click Demonstration Suite (Section 12.1)
          </h2>
          <div className="flex items-center gap-2">
            <label className="text-xs font-medium text-slate-600 flex items-center gap-1.5 cursor-pointer">
              <input
                type="checkbox"
                checked={useCached}
                onChange={e => setUseCached(e.target.checked)}
                className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
              />
              Use cached sample (for offline demo)
            </label>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Safe-looking Group */}
          <div className="space-y-2">
            <span className="text-[11px] font-semibold text-emerald-700 uppercase tracking-wide">
              Safe-Looking Samples (B1-B3)
            </span>
            <div className="grid grid-cols-3 gap-2">
              {samples.demo_samples.filter(s => s.group === "safe-looking").map(s => (
                <button
                  key={s.id}
                  onClick={() => { handleLoadSample(s); handleStartScan(s.value, s.type); }}
                  className="px-2.5 py-2 text-xs font-medium bg-slate-50 hover:bg-emerald-50 border border-slate-200 hover:border-emerald-300 text-slate-700 hover:text-emerald-800 rounded-lg text-left transition truncate shadow-2xs"
                  title={s.description}
                >
                  <span className="font-bold text-emerald-600 mr-1">{s.id}</span>
                  {s.title}
                </button>
              ))}
            </div>
          </div>

          {/* Suspicious Group */}
          <div className="space-y-2">
            <span className="text-[11px] font-semibold text-orange-700 uppercase tracking-wide">
              Suspicious & Attack Samples (S1-S3)
            </span>
            <div className="grid grid-cols-3 gap-2">
              {samples.demo_samples.filter(s => s.group === "suspicious").map(s => (
                <button
                  key={s.id}
                  onClick={() => { handleLoadSample(s); handleStartScan(s.value, s.type); }}
                  className="px-2.5 py-2 text-xs font-medium bg-slate-50 hover:bg-orange-50 border border-slate-200 hover:border-orange-300 text-slate-700 hover:text-orange-800 rounded-lg text-left transition truncate shadow-2xs"
                  title={s.description}
                >
                  <span className="font-bold text-orange-600 mr-1">{s.id}</span>
                  {s.title}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* More tests dropdown */}
        <div className="pt-2 border-t border-slate-100 flex items-center gap-2 overflow-x-auto text-xs">
          <span className="text-slate-400 font-medium">Extra Tests:</span>
          {samples.extra_tests.map(et => (
            <button
              key={et.id}
              onClick={() => { handleLoadSample(et); handleStartScan(et.value, et.type); }}
              className="px-2 py-1 bg-slate-100 hover:bg-slate-200 rounded text-slate-600 whitespace-nowrap text-[11px] font-medium transition"
            >
              {et.title}
            </button>
          ))}
          <button
            onClick={() => {
              const sim = { id: "SIM", group: "certificate", type: "url" as const, title: "eMudhra Simulation", value: "https://simulated-distrusted-ca.local", expected_label: "High Risk" };
              handleLoadSample(sim);
              handleStartScan(sim.value, sim.type);
            }}
            className="px-2 py-1 bg-purple-50 hover:bg-purple-100 border border-purple-200 rounded text-purple-700 whitespace-nowrap text-[11px] font-semibold transition"
          >
            ★ eMudhra Distrust Simulation (TLS-06)
          </button>
        </div>
      </section>

      {/* INPUT FORM TABS */}
      <section className="bg-white rounded-xl p-6 border border-slate-200 shadow-sm space-y-4">
        <div className="flex border-b border-slate-200">
          <button
            onClick={() => setActiveTab("url")}
            className={`pb-3 px-4 font-semibold text-sm border-b-2 transition ${
              activeTab === "url"
                ? "border-indigo-600 text-indigo-600"
                : "border-transparent text-slate-500 hover:text-slate-700"
            }`}
          >
            Check a Link or Domain
          </button>
          <button
            onClick={() => setActiveTab("message")}
            className={`pb-3 px-4 font-semibold text-sm border-b-2 transition ${
              activeTab === "message"
                ? "border-indigo-600 text-indigo-600"
                : "border-transparent text-slate-500 hover:text-slate-700"
            }`}
          >
            Check an SMS or Message
          </button>
        </div>

        {activeTab === "url" ? (
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-700">Target Web Address or Domain</label>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="e.g. sbi-kyc-update.com or https://example.com"
                value={inputValue}
                onChange={e => setInputValue(e.target.value)}
                onKeyDown={e => e.key === "Enter" && handleStartScan()}
                className="flex-1 px-4 py-2.5 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:outline-none"
              />
              <button
                onClick={() => handleStartScan()}
                disabled={isScanning}
                className="px-6 py-2.5 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-sm rounded-lg transition disabled:opacity-50 shadow-sm flex items-center gap-2"
              >
                {isScanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                Scan Link
              </button>
            </div>
            <p className="text-[11px] text-slate-400">
              URLs are passively inspected without script execution. Internal IP addresses and private subnets are blocked by SSRF Guard.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            <div className="flex justify-between items-center">
              <label className="text-xs font-semibold text-slate-700">Pasted SMS / Email Content</label>
              <span className="text-[11px] text-amber-700 font-semibold bg-amber-50 px-2 py-0.5 rounded border border-amber-200">
                Never paste passwords, OTPs, private keys or seed phrases (HC-13)
              </span>
            </div>
            <textarea
              rows={4}
              maxLength={5000}
              placeholder="Paste suspicious SMS, WhatsApp, or email text here..."
              value={inputValue}
              onChange={e => setInputValue(e.target.value)}
              className="w-full px-4 py-2.5 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-indigo-500 focus:outline-none"
            />
            <div className="flex justify-between items-center text-xs">
              <span className="text-slate-400">{inputValue.length} / 5,000 characters</span>
              <button
                onClick={() => handleStartScan()}
                disabled={isScanning}
                className="px-6 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-sm rounded-lg transition disabled:opacity-50 shadow-sm flex items-center gap-2"
              >
                {isScanning ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Shield className="w-4 h-4" />}
                Analyze Message
              </button>
            </div>
          </div>
        )}

        {/* ERROR DISPLAY */}
        {errorMsg && (
          <div className="p-4 bg-red-50 border border-red-200 rounded-xl flex items-start gap-3 text-red-800 text-sm">
            <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">Security Action / Notice</p>
              <p className="text-xs text-red-700 mt-0.5">{errorMsg}</p>
            </div>
          </div>
        )}

        {/* LIVE PROGRESS STEPPER */}
        {isScanning && (
          <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
            <div className="flex justify-between items-center text-xs">
              <span className="font-bold text-indigo-700 flex items-center gap-2">
                <RefreshCw className="w-3.5 h-3.5 animate-spin text-indigo-600" />
                {currentStepName}
              </span>
              <span className="text-slate-500 font-medium">Step {scanStepIndex} of {SCAN_STEPS.length}</span>
            </div>
            <div className="w-full bg-slate-200 rounded-full h-1.5 overflow-hidden">
              <div
                className="bg-indigo-600 h-1.5 transition-all duration-300"
                style={{ width: `${(scanStepIndex / SCAN_STEPS.length) * 100}%` }}
              />
            </div>
          </div>
        )}
      </section>

      {/* REPORT VIEW (SECTION 9.2) */}
      {report && (
        <main className="space-y-6">
          {/* 1. RISK BANNER */}
          <div className={`p-6 rounded-2xl border ${getRiskColor(report.risk_label)} shadow-sm space-y-4`}>
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                {getRiskIcon(report.risk_label)}
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-2xl font-black tracking-tight uppercase">
                      {report.risk_label}
                    </span>
                    {report.is_cached_sample && (
                      <span className="text-[10px] uppercase tracking-wider font-bold bg-slate-100 text-slate-700 border border-slate-300 px-2 py-0.5 rounded-full">
                        Cached sample result
                      </span>
                    )}
                  </div>
                  <p className="text-xs opacity-90 mt-0.5 font-medium">
                    {report.risk_label === "Low Risk" && "No significant malicious indicators identified within the available checks."}
                    {report.risk_label === "Suspicious" && "One or more indicators require further investigation."}
                    {report.risk_label === "High Risk" && "Multiple significant indicators suggest a substantial security threat."}
                    {report.risk_label === "Confirmed Malicious" && "Supported by authoritative threat intelligence or sufficiently validated evidence."}
                    {report.risk_label === "Inconclusive" && "Insufficient data or unavailable verification sources."}
                  </p>
                </div>
              </div>

              {/* Coverage Meter */}
              <div className="bg-white/80 backdrop-blur-xs p-3 rounded-xl border border-current/20 text-right min-w-[140px]">
                <div className="text-[10px] uppercase font-bold text-slate-500">Evidence Coverage</div>
                <div className="text-xl font-black text-slate-900">{report.evidence_coverage.percent}%</div>
                <div className="text-[10px] text-slate-600 font-medium">
                  {report.evidence_coverage.completed_groups.length} active check groups
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-current/15 flex flex-wrap items-center justify-between text-xs opacity-80 gap-2">
              <div>
                Target: <span className="font-mono font-semibold">{defang(report.input_display)}</span>
              </div>
              <div>
                Analyzed at: <span className="font-semibold">{new Date(report.created_at).toLocaleString()}</span> (UTC: {report.created_at})
              </div>
            </div>
          </div>

          {/* 2. AI EXPLANATION CARD */}
          <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-sm space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                <Cpu className="w-4 h-4 text-indigo-600" />
                Explanation
              </h3>
              <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                report.ai_explanation.generated_by === "llm"
                  ? "bg-purple-50 text-purple-700 border-purple-200"
                  : "bg-slate-100 text-slate-700 border-slate-200"
              }`}>
                {report.ai_explanation.generated_by === "llm" ? "AI Model (Gemini)" : "Deterministic Template Fallback"}
              </span>
            </div>

            <p className="text-xs text-slate-700 leading-relaxed">
              {report.ai_explanation.summary}
            </p>

            {report.ai_explanation.evidence_points.length > 0 && (
              <div className="pt-2 border-t border-slate-100 space-y-2">
                <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">Citing Technical Evidence:</span>
                <ul className="space-y-1">
                  {report.ai_explanation.evidence_points.map((pt, i) => (
                    <li key={i} className="text-xs text-slate-600 flex items-start gap-2">
                      <span className="font-mono text-[10px] bg-slate-100 px-1.5 py-0.5 rounded border border-slate-200 font-bold shrink-0">
                        {pt.finding_id}
                      </span>
                      <span>{pt.explanation}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <p className="text-[10px] text-slate-400 italic pt-2">
              {report.ai_explanation.generated_by === "llm"
                ? "This explanation was generated by an AI model using only the evidence listed in this report. It can make mistakes."
                : "This explanation was generated from a fixed template using the evidence listed in this report because the AI service was unavailable."}
            </p>
          </div>

          {/* 3. CAMPAIGN CLUSTERING BADGE */}
          {report.campaign && report.campaign.linked && (
            <div className={`p-4 rounded-xl border flex items-start gap-3 shadow-xs ${
              report.campaign.strength === "strong"
                ? "bg-rose-50 border-rose-300 text-rose-900"
                : "bg-amber-50 border-amber-300 text-amber-900"
            }`}>
              <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="font-bold text-xs uppercase tracking-wide">
                    {report.campaign.strength === "strong"
                      ? "Linked to Existing Phishing Campaign"
                      : "Possible infrastructure overlap"}
                  </span>
                  <span className="text-[10px] bg-white/70 px-2 py-0.5 rounded font-bold">
                    Cluster Size: {report.campaign.cluster_size} reports
                  </span>
                </div>
                <p className="text-xs">
                  {report.campaign.ai_summary}
                </p>
                <div className="flex flex-wrap gap-1 pt-1">
                  {report.campaign.matched_indicators.map((ind, i) => (
                    <span key={i} className="text-[10px] bg-white px-2 py-0.5 rounded border border-current/20 font-mono">
                      {ind}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* 4. KEY FINDINGS TABLE */}
          <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-sm space-y-3">
            <h3 className="text-sm font-bold text-slate-800 flex items-center justify-between">
              <span>Identified Threat Findings ({report.findings.length})</span>
              <span className="text-xs font-normal text-slate-500">Sorted by severity & points</span>
            </h3>

            {report.findings.length === 0 ? (
              <p className="text-xs text-slate-500 italic py-2">
                No adverse threat findings identified within available passive checks.
              </p>
            ) : (
              <div className="space-y-2">
                {report.findings.map(f => {
                  const isOpen = expandedFindings[f.id];
                  return (
                    <div key={f.id} className="border border-slate-200 rounded-lg overflow-hidden">
                      <button
                        onClick={() => setExpandedFindings(prev => ({ ...prev, [f.id]: !prev[f.id] }))}
                        className="w-full px-4 py-2.5 flex items-center justify-between bg-slate-50/50 hover:bg-slate-50 text-left transition"
                      >
                        <div className="flex items-center gap-2.5">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                            f.severity === "Critical" ? "bg-red-100 text-red-800" :
                            f.severity === "High" ? "bg-orange-100 text-orange-800" :
                            f.severity === "Medium" ? "bg-amber-100 text-amber-800" :
                            "bg-slate-100 text-slate-700"
                          }`}>
                            {f.severity}
                          </span>
                          <span className="font-mono text-xs font-bold text-slate-600">{f.id}</span>
                          <span className="text-xs font-semibold text-slate-800">{f.title}</span>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="text-xs font-mono text-slate-500">+{f.points} pts</span>
                          {isOpen ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                        </div>
                      </button>

                      {isOpen && (
                        <div className="p-4 bg-white border-t border-slate-100 text-xs space-y-2.5">
                          <p className="text-slate-700">{f.description}</p>
                          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] pt-1">
                            <div className="p-2 bg-slate-50 rounded border border-slate-100">
                              <span className="font-bold text-slate-600 block">Potential Impact:</span>
                              <span className="text-slate-600">{f.potential_impact}</span>
                            </div>
                            <div className="p-2 bg-slate-50 rounded border border-slate-100">
                              <span className="font-bold text-slate-600 block">Recommended Action:</span>
                              <span className="text-slate-600">{f.recommendation}</span>
                            </div>
                          </div>
                          <div className="text-[11px] text-slate-400 italic">
                            Source: {f.source} · Limitation: {f.limitation}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* 5. TLS CERTIFICATE & WEB TRUST CARD */}
          {report.tls && (
            <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-sm space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                  <Lock className="w-4 h-4 text-indigo-600" />
                  TLS Certificate & Digital Trust Analysis
                </h3>
                <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full border ${
                  report.tls.tls_verdict === "Valid configuration"
                    ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                    : report.tls.tls_verdict === "Potentially compromised trust"
                    ? "bg-red-50 text-red-700 border-red-300"
                    : "bg-amber-50 text-amber-700 border-amber-300"
                }`}>
                  Verdict: {report.tls.tls_verdict}
                </span>
              </div>

              {/* Standard HTTPS Note (Appendix F) */}
              <div className="p-3 bg-indigo-50/60 border border-indigo-200 rounded-lg text-xs text-indigo-900 flex items-start gap-2">
                <Info className="w-4 h-4 text-indigo-600 shrink-0 mt-0.5" />
                <span>{report.tls.https_note}</span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 space-y-1">
                  <span className="font-bold text-slate-700 block">Certificate Details:</span>
                  <p className="text-slate-600 truncate">Subject: {report.tls.subject}</p>
                  <p className="text-slate-600 truncate">Issuer: {report.tls.issuer}</p>
                  <p className="text-slate-600">Validity: {report.tls.days_remaining} days remaining</p>
                  <p className="text-slate-600 font-mono text-[11px] truncate">SHA-256: {report.tls.certificate_sha256}</p>
                </div>
                <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 space-y-1">
                  <span className="font-bold text-slate-700 block">Cryptographic Specifications:</span>
                  <p className="text-slate-600">Key: {report.tls.public_key_algorithm} ({report.tls.public_key_size} bits)</p>
                  <p className="text-slate-600">Signature: {report.tls.signature_algorithm}</p>
                  <p className="text-slate-600">Trust Result: {report.tls.trust_result}</p>
                  <p className="text-slate-600 font-mono text-[11px] truncate">SPKI Hash: {report.tls.spki_sha256}</p>
                </div>
              </div>
            </div>
          )}

          {/* 6. REDIRECT CHAIN */}
          {report.redirect_chain.length > 0 && (
            <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-sm space-y-3">
              <h3 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                <ArrowRight className="w-4 h-4 text-indigo-600" />
                Redirect Chain Analysis ({report.redirect_chain.length} hop{report.redirect_chain.length > 1 ? "s" : ""})
              </h3>
              <div className="space-y-2">
                {report.redirect_chain.map((hop, i) => (
                  <div key={i} className="flex items-center gap-2 text-xs p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                    <span className="font-mono font-bold bg-slate-200 px-1.5 py-0.5 rounded text-[10px]">
                      {hop.status_code || "200"}
                    </span>
                    <span className="font-mono text-slate-700 flex-1 truncate">{hop.url}</span>
                    <span className={`text-[10px] font-semibold px-2 py-0.5 rounded ${
                      hop.same_site ? "bg-emerald-100 text-emerald-800" : "bg-orange-100 text-orange-800"
                    }`}>
                      {hop.same_site ? "Same Site" : "Cross-Domain"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 7. THREAT INTELLIGENCE & SECURITY HEADERS */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Threat Intel */}
            <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-sm space-y-3">
              <h3 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                <Database className="w-4 h-4 text-indigo-600" />
                Threat Intelligence Feeds
              </h3>
              <div className="space-y-2 text-xs">
                {report.threat_intel.feeds_queried.map((feed, i) => {
                  const answered = report.threat_intel.feeds_answered.includes(feed);
                  return (
                    <div key={i} className="flex items-center justify-between p-2 bg-slate-50 rounded border border-slate-100">
                      <span className="font-medium text-slate-700">{feed}</span>
                      <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        answered ? "bg-emerald-100 text-emerald-800" : "bg-slate-200 text-slate-600"
                      }`}>
                        {answered ? "Answered" : "Unavailable"}
                      </span>
                    </div>
                  );
                })}
              </div>
              <p className="text-[11px] text-slate-400 italic">
                Absence of a match in these sources does not prove a site is safe.
              </p>
            </div>

            {/* Security Headers */}
            <div className="bg-white rounded-xl p-5 border border-slate-200 shadow-sm space-y-3">
              <h3 className="text-sm font-bold text-slate-800 flex items-center gap-2">
                <Shield className="w-4 h-4 text-indigo-600" />
                Security Headers Evaluation
              </h3>
              <div className="space-y-1.5 text-xs max-h-48 overflow-y-auto">
                {report.security_headers.map((h, i) => (
                  <div key={i} className="flex items-center justify-between p-1.5 bg-slate-50 rounded">
                    <span className="font-mono text-slate-700 text-[11px]">{h.header_name}</span>
                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                      h.present ? "bg-emerald-100 text-emerald-800" : "bg-amber-100 text-amber-800"
                    }`}>
                      {h.present ? "Present" : "Missing"}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* 8. WEB3 VERIFICATION PANEL (SECTION 9.2 #10) */}
          <div className="bg-white rounded-xl p-6 border border-slate-200 shadow-sm space-y-5">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <h3 className="text-sm font-bold text-slate-900 flex items-center gap-2">
                <Database className="w-4 h-4 text-indigo-600" />
                Web3 Decentralized Proof Registry
              </h3>
              <span className="text-xs font-mono text-slate-500">
                Network: Ethereum Sepolia / Hardhat Testnet
              </span>
            </div>

            {/* Two Privacy Statements (HC-07 & HC-08, Appendix F) */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
              <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-slate-600">
                <span className="font-bold text-slate-800 block mb-1">Strict Off-Chain Privacy:</span>
                Only a cryptographic hash, timestamp, status and reporter address are stored on-chain. Raw URLs, messages and personal data stay in our private database.
              </div>
              <div className="p-3 bg-slate-50 rounded-lg border border-slate-200 text-slate-600">
                <span className="font-bold text-slate-800 block mb-1">Integrity vs. Truth:</span>
                A blockchain record proves a report has not changed since it was recorded. It does not prove the report is true.
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                onClick={handleCommit}
                disabled={isCommitting || report.web3?.status === "committed"}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white font-semibold text-xs rounded-lg transition disabled:opacity-50 shadow-sm flex items-center gap-2"
              >
                {isCommitting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5" />}
                {report.web3?.status === "committed" ? "Report Committed On-Chain" : "Save and Verify Report"}
              </button>

              <button
                onClick={handleVerify}
                disabled={isVerifying || (!report.is_committed && !report.web3)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-900 text-white font-semibold text-xs rounded-lg transition disabled:opacity-50 shadow-sm flex items-center gap-2"
              >
                {isVerifying ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}
                Verify Integrity
              </button>

              <button
                onClick={() => {
                  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `trusttrace-report-${report.report_id}.json`;
                  a.click();
                }}
                className="px-4 py-2 bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold text-xs rounded-lg transition border border-slate-300 shadow-2xs"
              >
                Download JSON Report
              </button>
            </div>

            {/* Verification Result Badge & Side-by-Side Comparison */}
            {verificationResult && (
              <div className={`p-4 rounded-xl border space-y-3 ${
                verificationResult.result_code === "MATCH"
                  ? "bg-emerald-50 border-emerald-300 text-emerald-900"
                  : "bg-red-50 border-red-300 text-red-900"
              }`}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2 font-bold text-sm">
                    {verificationResult.result_code === "MATCH" ? (
                      <CheckCircle className="w-5 h-5 text-emerald-600" />
                    ) : (
                      <AlertOctagon className="w-5 h-5 text-red-600" />
                    )}
                    <span>VERIFICATION RESULT: {verificationResult.result_code}</span>
                  </div>
                  {verificationResult.explorer_url && (
                    <a
                      href={verificationResult.explorer_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-xs font-semibold text-indigo-700 hover:underline flex items-center gap-1"
                    >
                      View on Etherscan <ExternalLink className="w-3 h-3" />
                    </a>
                  )}
                </div>

                <p className="text-xs">{verificationResult.message}</p>

                {/* Side by side hashes */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono pt-1">
                  <div className="p-2 bg-white rounded border border-current/20">
                    <span className="font-sans font-bold block text-[10px] text-slate-500">Recomputed Stored Hash:</span>
                    <span className="break-all">{verificationResult.recomputed_hash}</span>
                  </div>
                  <div className="p-2 bg-white rounded border border-current/20">
                    <span className="font-sans font-bold block text-[10px] text-slate-500">Committed On-Chain Hash:</span>
                    <span className="break-all">{verificationResult.onchain_hash || "Not on-chain"}</span>
                  </div>
                </div>
              </div>
            )}

            {/* Demo Mode Tamper Suite */}
            <div className="pt-3 border-t border-slate-100 space-y-2">
              <span className="text-[11px] font-bold text-slate-500 uppercase tracking-wider">
                Demo-Mode Cryptographic Tamper Simulator:
              </span>
              <div className="flex gap-2">
                <button
                  onClick={handleTamper}
                  className="px-3 py-1.5 text-xs bg-rose-100 hover:bg-rose-200 text-rose-800 rounded border border-rose-300 font-medium transition"
                >
                  Simulate Database Tampering
                </button>
                <button
                  onClick={handleRestore}
                  className="px-3 py-1.5 text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 rounded border border-slate-300 font-medium transition"
                >
                  Restore Original Report
                </button>
              </div>
              {tamperState && <p className="text-[11px] text-rose-700 font-semibold">{tamperState}</p>}
            </div>
          </div>

          {/* 9. STANDARD DISCLAIMER */}
          <div className="p-4 bg-slate-100 border border-slate-200 rounded-xl text-center text-xs text-slate-600">
            {report.disclaimer}
          </div>
        </main>
      )}

      {/* SECURITY CONTROLS MODAL */}
      {showControls && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-xl w-full p-6 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex justify-between items-center border-b pb-3">
              <h3 className="font-bold text-base text-slate-900 flex items-center gap-2">
                <Lock className="w-5 h-5 text-indigo-600" />
                Active Security & Privacy Controls
              </h3>
              <button onClick={() => setShowControls(false)} className="text-slate-400 hover:text-slate-600 text-lg">✕</button>
            </div>
            <div className="space-y-3">
              {controlsData.map((c, i) => (
                <div key={i} className="p-3 bg-slate-50 rounded-lg border border-slate-200 space-y-1">
                  <span className="font-bold text-xs text-indigo-800 block">{c.name}</span>
                  <p className="text-xs text-slate-600">{c.description}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* HISTORY MODAL */}
      {showHistory && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-xs z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl max-w-2xl w-full p-6 space-y-4 max-h-[85vh] overflow-y-auto">
            <div className="flex justify-between items-center border-b pb-3">
              <h3 className="font-bold text-base text-slate-900 flex items-center gap-2">
                <History className="w-5 h-5 text-indigo-600" />
                Verifiable Reports Log
              </h3>
              <button onClick={() => setShowHistory(false)} className="text-slate-400 hover:text-slate-600 text-lg">✕</button>
            </div>
            <div className="space-y-2">
              {historyReports.map((h, i) => (
                <div key={i} className="p-3 bg-slate-50 rounded-lg border border-slate-200 flex items-center justify-between text-xs">
                  <div>
                    <span className="font-mono font-bold text-slate-800 block">{defang(h.input_display || h.registrable_domain)}</span>
                    <span className="text-[10px] text-slate-400">{h.created_at}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${getRiskColor(h.risk_label)}`}>
                      {h.risk_label}
                    </span>
                    {h.is_committed && (
                      <span className="text-[10px] bg-indigo-50 text-indigo-700 px-1.5 py-0.5 rounded font-bold border border-indigo-200">
                        On-Chain
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
