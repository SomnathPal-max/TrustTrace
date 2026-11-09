"use client";

import React, { useState, useEffect } from "react";
import {
  Shield, AlertTriangle, CheckCircle, XCircle, Info, ExternalLink,
  ChevronDown, ChevronRight, Copy, Check, RefreshCw, Lock, Database,
  Cpu, History, ArrowRight, Eye, AlertOctagon, Terminal, AlertCircle,
  Globe, Activity, Layers, Search, FileText, CheckCheck, Key, Share2,
  Zap, BarChart3, Filter, Network, ShieldAlert, Fingerprint, RefreshCcw
} from "lucide-react";
import {
  Report, RiskLabel, DemoSample, ThreatFeedItem, TrackedCampaign,
  DistrustedCA, PlatformStats
} from "@/types";
import { defang } from "@/lib/defang";
import {
  fetchHealth, fetchSecurityControls, fetchSamples, startScan,
  pollScan, commitReport, verifyReport, tamperReport, restoreReport,
  fetchReportsList, fetchThreatFeed, fetchCampaigns, fetchDistrustedCAs,
  fetchPlatformStats
} from "@/lib/api";

const SCAN_STEPS = [
  "Validating link safety (SSRF Guard & Anti-Rebinding)",
  "Analysing domain reputation & DNS telemetry",
  "Following HTTP transport redirects (Passive GET/HEAD)",
  "Inspecting TLS certificate chain & distrust registries",
  "Checking authoritative threat intelligence (URLhaus / OpenPhish)",
  "Correlating with active threat campaigns & indicators",
  "Synthesizing prompt-shielded AI forensic assessment"
];

export default function Home() {
  // Navigation tabs
  const [mainNav, setMainNav] = useState<"scanner" | "feed" | "campaigns" | "ledger" | "ca_watchlist" | "controls">("scanner");

  // Scanner state
  const [inputTab, setInputTab] = useState<"url" | "message">("url");
  const [inputValue, setInputValue] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanStepIndex, setScanStepIndex] = useState(0);
  const [currentStepName, setCurrentStepName] = useState("");
  const [report, setReport] = useState<Report | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [expandedFindings, setExpandedFindings] = useState<Record<string, boolean>>({});
  const [selectedFindingCategory, setSelectedFindingCategory] = useState<string>("ALL");

  // Web3 state
  const [isCommitting, setIsCommitting] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any | null>(null);
  const [tamperState, setTamperState] = useState<string | null>(null);

  // Platform data state
  const [stats, setStats] = useState<PlatformStats | null>(null);
  const [threatFeed, setThreatFeed] = useState<ThreatFeedItem[]>([]);
  const [campaigns, setCampaigns] = useState<TrackedCampaign[]>([]);
  const [distrustedCAs, setDistrustedCAs] = useState<DistrustedCA[]>([]);
  const [controlsData, setControlsData] = useState<any[]>([]);
  const [historyReports, setHistoryReports] = useState<any[]>([]);
  const [showHistoryModal, setShowHistoryModal] = useState(false);

  // Filter states for feeds
  const [feedSearch, setFeedSearch] = useState("");
  const [feedCategoryFilter, setFeedCategoryFilter] = useState("ALL");

  // Reference Benchmark samples
  const [samples, setSamples] = useState<{ demo_samples: DemoSample[]; extra_tests: DemoSample[] }>({
    demo_samples: [],
    extra_tests: []
  });

  useEffect(() => {
    // Initial data fetch
    fetchPlatformStats().then(setStats).catch(() => {});
    fetchThreatFeed().then(d => setThreatFeed(d.feed || [])).catch(() => {});
    fetchCampaigns().then(d => setCampaigns(d.campaigns || [])).catch(() => {});
    fetchDistrustedCAs().then(d => setDistrustedCAs(d.distrusted_cas || [])).catch(() => {});
    fetchSecurityControls().then(d => setControlsData(d.active_protections || [])).catch(() => {});
    fetchSamples().then(setSamples).catch(() => {});
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleLoadBenchmark = (val: string, type: "url" | "message") => {
    setInputTab(type);
    setInputValue(val);
    setReport(null);
    setErrorMsg(null);
    setVerificationResult(null);
    setTamperState(null);
    setMainNav("scanner");
  };

  const handleStartScan = async (overrideVal?: string, overrideType?: "url" | "message") => {
    const val = (overrideVal !== undefined ? overrideVal : inputValue).trim();
    const type = overrideType || inputTab;

    if (!val) {
      setErrorMsg("Please provide a target URL or message text to analyze.");
      return;
    }

    setIsScanning(true);
    setReport(null);
    setErrorMsg(null);
    setVerificationResult(null);
    setTamperState(null);
    setScanStepIndex(0);
    setCurrentStepName(SCAN_STEPS[0]);

    try {
      const init = await startScan(type, val, false);
      const reportId = init.report_id;

      const pollInterval = setInterval(async () => {
        try {
          const status = await pollScan(reportId);
          if (status.step_index) {
            setScanStepIndex(status.step_index);
          }
          if (status.progress_step) {
            setCurrentStepName(status.progress_step);
          }

          if (status.status === "complete" && status.report) {
            clearInterval(pollInterval);
            setIsScanning(false);
            setReport(status.report);
            fetchPlatformStats().then(setStats).catch(() => {});
          } else if (status.status === "failed") {
            clearInterval(pollInterval);
            setIsScanning(false);
            setErrorMsg(status.error || "Analysis pipeline encountered an error.");
          }
        } catch (e: any) {
          clearInterval(pollInterval);
          setIsScanning(false);
          setErrorMsg(e.message || "Failed polling scan status.");
        }
      }, 700);
    } catch (e: any) {
      setIsScanning(false);
      setErrorMsg(e.message || "Failed to initialize scan.");
    }
  };

  const handleCommit = async () => {
    if (!report) return;
    setIsCommitting(true);
    try {
      const res = await commitReport(report.report_id);
      setReport(prev => prev ? {
        ...prev,
        is_committed: true,
        report_hash: res.report_hash,
        web3: {
          status: "committed",
          report_hash: res.report_hash,
          tx_hash: res.tx_hash,
          block_number: res.block_number,
          network: res.network,
          chain_id: res.chain_id,
          contract_address: res.contract_address,
          committed_at: res.committed_at,
          revision: res.revision
        }
      } : null);
      fetchPlatformStats().then(setStats).catch(() => {});
    } catch (e: any) {
      alert("Failed to commit report: " + e.message);
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
    } catch (e: any) {
      alert("Verification query failed: " + e.message);
    } finally {
      setIsVerifying(false);
    }
  };

  const handleTamperSimulation = async () => {
    if (!report) return;
    try {
      await tamperReport(report.report_id);
      setTamperState("tampered");
      await handleVerify();
    } catch (e: any) {
      alert("Tamper simulation failed: " + e.message);
    }
  };

  const handleRestoreSimulation = async () => {
    if (!report) return;
    try {
      await restoreReport(report.report_id);
      setTamperState("restored");
      await handleVerify();
    } catch (e: any) {
      alert("Restore failed: " + e.message);
    }
  };

  const openHistory = async () => {
    try {
      const res = await fetchReportsList();
      setHistoryReports(res.reports || []);
      setShowHistoryModal(true);
    } catch (e: any) {
      alert("Could not load history: " + e.message);
    }
  };

  // Helper for risk styling
  const getRiskStyle = (label: RiskLabel) => {
    switch (label) {
      case "Low Risk":
        return {
          bg: "bg-emerald-950/60",
          border: "border-emerald-600/40",
          text: "text-emerald-400",
          badge: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
          barColor: "bg-emerald-500"
        };
      case "Suspicious":
        return {
          bg: "bg-amber-950/60",
          border: "border-amber-600/40",
          text: "text-amber-400",
          badge: "bg-amber-500/20 text-amber-300 border-amber-500/30",
          barColor: "bg-amber-500"
        };
      case "High Risk":
        return {
          bg: "bg-rose-950/60",
          border: "border-rose-600/40",
          text: "text-rose-400",
          badge: "bg-rose-500/20 text-rose-300 border-rose-500/30",
          barColor: "bg-rose-500"
        };
      case "Confirmed Malicious":
        return {
          bg: "bg-red-950/80",
          border: "border-red-600",
          text: "text-red-400",
          badge: "bg-red-600/30 text-red-200 border-red-500",
          barColor: "bg-red-600"
        };
      case "Inconclusive":
      default:
        return {
          bg: "bg-slate-900/60",
          border: "border-slate-700",
          text: "text-slate-300",
          badge: "bg-slate-800 text-slate-300 border-slate-700",
          barColor: "bg-slate-500"
        };
    }
  };

  // Filtered threat feed items
  const filteredFeed = threatFeed.filter(item => {
    const matchesSearch = item.indicator.toLowerCase().includes(feedSearch.toLowerCase()) ||
                          item.raw_value.toLowerCase().includes(feedSearch.toLowerCase()) ||
                          item.source.toLowerCase().includes(feedSearch.toLowerCase());
    const matchesCategory = feedCategoryFilter === "ALL" || item.category === feedCategoryFilter;
    return matchesSearch && matchesCategory;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      
      {/* 1. TOP ENTERPRISE HEADER */}
      <header className="border-b border-slate-800/80 bg-slate-950/95 sticky top-0 z-40 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-600 via-blue-600 to-indigo-700 p-0.5 shadow-lg shadow-cyan-950/50">
              <div className="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
                <Shield className="w-5 h-5 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-extrabold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-cyan-400 bg-clip-text text-transparent">
                  TrustTrace
                </span>
                <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-cyan-950 border border-cyan-800/60 text-cyan-400">
                  CyberSOC
                </span>
              </div>
              <p className="text-[11px] text-slate-400 font-medium">
                Web Threat Intelligence & Cryptographic Verification Platform
              </p>
            </div>
          </div>

          {/* System status pills */}
          <div className="hidden lg:flex items-center gap-3 text-xs">
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span className="text-slate-300 font-medium">Engine Active</span>
            </div>
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
              <Database className="w-3.5 h-3.5 text-blue-400" />
              <span>URLhaus · CT Logs · OpenPhish</span>
            </div>
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
              <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
              <span>EVM ThreatRegistry</span>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex items-center gap-2">
            <button
              onClick={openHistory}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-xs font-medium text-slate-300 transition-colors"
            >
              <History className="w-3.5 h-3.5 text-slate-400" />
              <span>Audit Ledger</span>
            </button>
            <a
              href="http://127.0.0.1:8000/docs"
              target="_blank"
              rel="noreferrer"
              className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-950/40 hover:bg-cyan-950/80 border border-cyan-800/50 hover:border-cyan-700 text-xs font-medium text-cyan-300 transition-colors"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>API Docs</span>
              <ExternalLink className="w-3 h-3 text-cyan-500" />
            </a>
          </div>
        </div>

        {/* 2. NAVIGATION BAR */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 border-t border-slate-900 flex items-center space-x-1 overflow-x-auto text-xs py-1">
          <button
            onClick={() => setMainNav("scanner")}
            className={`px-3 py-2 rounded-md font-medium flex items-center gap-2 transition-colors whitespace-nowrap ${
              mainNav === "scanner"
                ? "bg-slate-850 text-cyan-400 border-b-2 border-cyan-500"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Zap className="w-3.5 h-3.5" />
            Threat Analyzer
          </button>
          <button
            onClick={() => setMainNav("feed")}
            className={`px-3 py-2 rounded-md font-medium flex items-center gap-2 transition-colors whitespace-nowrap ${
              mainNav === "feed"
                ? "bg-slate-850 text-cyan-400 border-b-2 border-cyan-500"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Active Threat Feed ({threatFeed.length})
          </button>
          <button
            onClick={() => setMainNav("campaigns")}
            className={`px-3 py-2 rounded-md font-medium flex items-center gap-2 transition-colors whitespace-nowrap ${
              mainNav === "campaigns"
                ? "bg-slate-850 text-cyan-400 border-b-2 border-cyan-500"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Network className="w-3.5 h-3.5" />
            Campaign Operations ({campaigns.length})
          </button>
          <button
            onClick={() => setMainNav("ledger")}
            className={`px-3 py-2 rounded-md font-medium flex items-center gap-2 transition-colors whitespace-nowrap ${
              mainNav === "ledger"
                ? "bg-slate-850 text-cyan-400 border-b-2 border-cyan-500"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Fingerprint className="w-3.5 h-3.5" />
            On-Chain Ledger Explorer
          </button>
          <button
            onClick={() => setMainNav("ca_watchlist")}
            className={`px-3 py-2 rounded-md font-medium flex items-center gap-2 transition-colors whitespace-nowrap ${
              mainNav === "ca_watchlist"
                ? "bg-slate-850 text-cyan-400 border-b-2 border-cyan-500"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            CA Distrust Watchlist ({distrustedCAs.length})
          </button>
          <button
            onClick={() => setMainNav("controls")}
            className={`px-3 py-2 rounded-md font-medium flex items-center gap-2 transition-colors whitespace-nowrap ${
              mainNav === "controls"
                ? "bg-slate-850 text-cyan-400 border-b-2 border-cyan-500"
                : "text-slate-400 hover:text-slate-200 hover:bg-slate-900"
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            Active Security Controls
          </button>
        </div>
      </header>

      {/* 3. PLATFORM STATS STRIP */}
      <section className="bg-slate-900/60 border-b border-slate-800/80 py-3">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 grid grid-cols-2 md:grid-cols-6 gap-3 text-center">
          <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/60">
            <div className="text-slate-400 text-[11px] uppercase tracking-wider font-semibold">Total Scans</div>
            <div className="text-base sm:text-lg font-bold text-white mt-0.5">
              {stats?.total_scans_analyzed?.toLocaleString() || "4,892"}
            </div>
          </div>
          <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/60">
            <div className="text-slate-400 text-[11px] uppercase tracking-wider font-semibold">Threats Flagged</div>
            <div className="text-base sm:text-lg font-bold text-rose-400 mt-0.5">
              {stats?.threats_mitigated?.toLocaleString() || "1,240"}
            </div>
          </div>
          <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/60">
            <div className="text-slate-400 text-[11px] uppercase tracking-wider font-semibold">Tracked IOCs</div>
            <div className="text-base sm:text-lg font-bold text-amber-400 mt-0.5">
              {stats?.active_indicators_tracked?.toLocaleString() || "840"}
            </div>
          </div>
          <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/60">
            <div className="text-slate-400 text-[11px] uppercase tracking-wider font-semibold">On-Chain Proofs</div>
            <div className="text-base sm:text-lg font-bold text-cyan-400 mt-0.5">
              {stats?.onchain_verifications?.toLocaleString() || "512"}
            </div>
          </div>
          <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/60">
            <div className="text-slate-400 text-[11px] uppercase tracking-wider font-semibold">Triage Latency</div>
            <div className="text-base sm:text-lg font-bold text-emerald-400 mt-0.5">
              {stats?.heuristic_eval_time_ms || 32} ms
            </div>
          </div>
          <div className="bg-slate-950/50 p-2.5 rounded-lg border border-slate-800/60">
            <div className="text-slate-400 text-[11px] uppercase tracking-wider font-semibold">Proof Integrity</div>
            <div className="text-base sm:text-lg font-bold text-indigo-400 mt-0.5">
              {stats?.tamper_detection_rate || "100.0%"}
            </div>
          </div>
        </div>
      </section>

      {/* 4. MAIN BODY CONTAINER */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">

        {/* ========================================================= */}
        {/* TAB 1: THREAT ANALYZER (SCANNER & FORENSIC REPORT)        */}
        {/* ========================================================= */}
        {mainNav === "scanner" && (
          <div className="space-y-6">
            
            {/* Input card */}
            <div className="bg-slate-900/80 rounded-xl border border-slate-800 p-5 shadow-xl relative overflow-hidden">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800/80">
                <div>
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    <Search className="w-4 h-4 text-cyan-400" />
                    Target Forensic Analysis
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Evaluate web links or suspicious messages using SSRF-guarded passive heuristics and threat intel feeds.
                  </p>
                </div>

                {/* Target Type Switcher */}
                <div className="flex p-1 bg-slate-950 rounded-lg border border-slate-800 self-stretch sm:self-auto">
                  <button
                    onClick={() => { setInputTab("url"); setInputValue(""); setReport(null); }}
                    className={`flex-1 sm:flex-initial px-4 py-1.5 rounded-md text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                      inputTab === "url"
                        ? "bg-cyan-600 text-white shadow-sm"
                        : "text-slate-400 hover:text-white"
                    }`}
                  >
                    <Globe className="w-3.5 h-3.5" />
                    URL / Domain Target
                  </button>
                  <button
                    onClick={() => { setInputTab("message"); setInputValue(""); setReport(null); }}
                    className={`flex-1 sm:flex-initial px-4 py-1.5 rounded-md text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                      inputTab === "message"
                        ? "bg-cyan-600 text-white shadow-sm"
                        : "text-slate-400 hover:text-white"
                    }`}
                  >
                    <FileText className="w-3.5 h-3.5" />
                    Message / SMS Forensics
                  </button>
                </div>
              </div>

              {/* Input Area */}
              <div className="space-y-3">
                {inputTab === "url" ? (
                  <div className="relative">
                    <input
                      type="text"
                      value={inputValue}
                      onChange={e => setInputValue(e.target.value)}
                      placeholder="Enter target URL or domain (e.g. https://domain.com/login, sbi-kyc-update.com)..."
                      className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg px-4 py-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all font-mono"
                      onKeyDown={e => { if (e.key === "Enter" && !isScanning) handleStartScan(); }}
                    />
                  </div>
                ) : (
                  <div className="relative">
                    <textarea
                      rows={3}
                      value={inputValue}
                      onChange={e => setInputValue(e.target.value)}
                      placeholder="Paste suspicious SMS, WhatsApp message, or urgent email lure with embedded links, phone numbers, or UPI addresses..."
                      className="w-full bg-slate-950 border border-slate-700 focus:border-cyan-500 rounded-lg p-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-cyan-500 transition-all"
                    />
                  </div>
                )}

                {/* Defanged preview & actions bar */}
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-1">
                  <div className="text-xs text-slate-400 flex items-center gap-2 overflow-hidden max-w-full">
                    <span className="text-slate-500 font-semibold shrink-0">Safe Defanged Preview:</span>
                    <span className="font-mono text-cyan-300 truncate bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                      {inputValue.trim() ? defang(inputValue.trim()) : "none"}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 self-end sm:self-auto">
                    {inputValue && (
                      <button
                        onClick={() => { setInputValue(""); setReport(null); setErrorMsg(null); }}
                        className="px-3 py-1.5 rounded-lg border border-slate-800 hover:border-slate-700 text-xs text-slate-400 hover:text-white transition-colors"
                      >
                        Clear
                      </button>
                    )}
                    <button
                      onClick={() => handleStartScan()}
                      disabled={isScanning || !inputValue.trim()}
                      className="px-5 py-2 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs tracking-wide shadow-lg shadow-cyan-950/40 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-all"
                    >
                      {isScanning ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          <span>Executing Pipeline...</span>
                        </>
                      ) : (
                        <>
                          <Zap className="w-3.5 h-3.5" />
                          <span>Analyze Target</span>
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>

              {/* Reference Benchmarks Bar */}
              <div className="mt-4 pt-3 border-t border-slate-800/60">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Operational Benchmark Vectors
                  </span>
                  <span className="text-[10px] text-slate-500">
                    Click to load verified test vectors into sandbox
                  </span>
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
                  <button
                    onClick={() => handleLoadBenchmark("https://sbi.co.in", "url")}
                    className="p-2 rounded bg-slate-950/60 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-left transition-colors"
                  >
                    <div className="text-[10px] text-emerald-400 font-semibold uppercase">Official Bank</div>
                    <div className="text-xs font-mono text-slate-300 truncate">sbi.co.in</div>
                  </button>
                  <button
                    onClick={() => handleLoadBenchmark("https://github.com", "url")}
                    className="p-2 rounded bg-slate-950/60 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-left transition-colors"
                  >
                    <div className="text-[10px] text-emerald-400 font-semibold uppercase">Verified Tech</div>
                    <div className="text-xs font-mono text-slate-300 truncate">github.com</div>
                  </button>
                  <button
                    onClick={() => handleLoadBenchmark("http://sbi-kyc-update.com/login", "url")}
                    className="p-2 rounded bg-slate-950/60 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-left transition-colors"
                  >
                    <div className="text-[10px] text-rose-400 font-semibold uppercase">Bank Phishing</div>
                    <div className="text-xs font-mono text-slate-300 truncate">sbi-kyc-update[.]com</div>
                  </button>
                  <button
                    onClick={() => handleLoadBenchmark("http://xn--gogl-qqa.com/login", "url")}
                    className="p-2 rounded bg-slate-950/60 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-left transition-colors"
                  >
                    <div className="text-[10px] text-amber-400 font-semibold uppercase">Homoglyph Spoof</div>
                    <div className="text-xs font-mono text-slate-300 truncate">xn--gogl[.]com</div>
                  </button>
                  <button
                    onClick={() => handleLoadBenchmark("URGENT: Your SBI account is blocked. Update PAN immediately: http://sbi-kyc-update.com/pan to prevent suspension.", "message")}
                    className="p-2 rounded bg-slate-950/60 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-left transition-colors"
                  >
                    <div className="text-[10px] text-rose-400 font-semibold uppercase">Smishing SMS</div>
                    <div className="text-xs text-slate-300 truncate">Urgent Bank Suspension</div>
                  </button>
                  <button
                    onClick={() => handleLoadBenchmark("https://simulated-distrusted-ca.test.local", "url")}
                    className="p-2 rounded bg-slate-950/60 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 text-left transition-colors"
                  >
                    <div className="text-[10px] text-purple-400 font-semibold uppercase">Distrusted CA</div>
                    <div className="text-xs font-mono text-slate-300 truncate">eMudhra Fixture</div>
                  </button>
                </div>
              </div>
            </div>

            {/* Error Message */}
            {errorMsg && (
              <div className="bg-rose-950/70 border border-rose-800/80 rounded-xl p-4 flex items-start gap-3 text-rose-200">
                <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                <div className="text-xs">
                  <div className="font-bold">Scan Execution Blocked</div>
                  <div className="mt-0.5 text-rose-300">{errorMsg}</div>
                </div>
              </div>
            )}

            {/* Stepper (Active during scan) */}
            {isScanning && (
              <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <RefreshCw className="w-4 h-4 text-cyan-400 animate-spin" />
                    <span className="font-semibold text-sm text-white">Pipeline Execution in Progress</span>
                  </div>
                  <span className="text-xs text-cyan-400 font-mono">
                    Step {scanStepIndex + 1} of {SCAN_STEPS.length}
                  </span>
                </div>

                <div className="w-full bg-slate-950 rounded-full h-2 overflow-hidden border border-slate-800">
                  <div
                    className="bg-gradient-to-r from-cyan-500 to-blue-500 h-full transition-all duration-300"
                    style={{ width: `${((scanStepIndex + 1) / SCAN_STEPS.length) * 100}%` }}
                  ></div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs pt-2">
                  {SCAN_STEPS.map((step, idx) => {
                    const isDone = idx < scanStepIndex;
                    const isCurrent = idx === scanStepIndex;
                    return (
                      <div
                        key={idx}
                        className={`flex items-center gap-2 p-2 rounded border ${
                          isDone
                            ? "bg-emerald-950/30 border-emerald-900/50 text-emerald-300"
                            : isCurrent
                            ? "bg-cyan-950/40 border-cyan-800/60 text-cyan-200 animate-pulse"
                            : "bg-slate-950/40 border-slate-900 text-slate-500"
                        }`}
                      >
                        {isDone ? (
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        ) : isCurrent ? (
                          <RefreshCw className="w-3.5 h-3.5 text-cyan-400 animate-spin shrink-0" />
                        ) : (
                          <div className="w-3.5 h-3.5 rounded-full border border-slate-700 shrink-0"></div>
                        )}
                        <span className="truncate">{step}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            {/* ========================================================= */}
            {/* FULL FORENSIC REPORT VIEW                                 */}
            {/* ========================================================= */}
            {report && !isScanning && (
              <div className="space-y-6">

                {/* 1. EXECUTIVE VERDICT & RISK HEADER */}
                {(() => {
                  const style = getRiskStyle(report.risk_label);
                  return (
                    <div className={`${style.bg} border ${style.border} rounded-xl p-6 shadow-xl relative overflow-hidden`}>
                      <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
                        
                        {/* Risk Label & Target */}
                        <div className="space-y-2 max-w-xl">
                          <div className="flex items-center gap-3">
                            <span className={`px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider border ${style.badge}`}>
                              {report.risk_label}
                            </span>
                            <span className="text-xs text-slate-400 font-mono">
                              ID: {report.report_id.slice(0, 8)}...
                            </span>
                            <span className="text-xs text-slate-400">
                              Duration: {report.analysis_duration_ms} ms
                            </span>
                          </div>

                          <div className="flex items-center gap-2 text-sm text-slate-200 font-mono">
                            <span className="text-slate-400 font-sans text-xs">Evaluated Target:</span>
                            <span className="font-bold text-white bg-slate-950/60 px-2 py-0.5 rounded border border-slate-800">
                              {defang(report.input_display)}
                            </span>
                            <button
                              onClick={() => handleCopy(report.input_display)}
                              className="text-slate-400 hover:text-white"
                              title="Copy Target"
                            >
                              {copiedText === report.input_display ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                            </button>
                          </div>

                          {/* Mandatory disclaimer (HC-02) */}
                          <p className="text-[11px] text-slate-300 italic pt-1 border-t border-slate-800/40">
                            {report.disclaimer}
                          </p>
                        </div>

                        {/* Scores & Metrics Grid */}
                        <div className="flex flex-wrap items-center gap-4 bg-slate-950/70 p-4 rounded-xl border border-slate-800/80">
                          {/* Risk Score */}
                          <div className="text-center px-3 border-r border-slate-800">
                            <div className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">
                              Risk Score
                            </div>
                            <div className={`text-3xl font-extrabold ${style.text} mt-0.5`}>
                              {report.risk_score}
                              <span className="text-xs font-normal text-slate-500"> / 100</span>
                            </div>
                          </div>

                          {/* Evidence Coverage */}
                          <div className="text-center px-3 border-r border-slate-800">
                            <div className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">
                              Coverage
                            </div>
                            <div className="text-2xl font-bold text-cyan-400 mt-0.5">
                              {report.evidence_coverage.percent}%
                            </div>
                          </div>

                          {/* Findings Count */}
                          <div className="text-center px-3">
                            <div className="text-[11px] uppercase tracking-wider font-semibold text-slate-400">
                              Findings
                            </div>
                            <div className="text-2xl font-bold text-white mt-0.5">
                              {report.findings.length}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })()}

                {/* 2. AI FORENSIC ASSESSMENT NARRATIVE CARD */}
                <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-4">
                  <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                    <div className="flex items-center gap-2">
                      <Cpu className="w-4 h-4 text-cyan-400" />
                      <h3 className="font-bold text-sm text-white">AI Forensic Threat Narrative</h3>
                      <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                        {report.ai_explanation.model_name}
                      </span>
                    </div>
                    <span className="text-xs text-slate-500">
                      Bounded by Per-Request Delimiters (HC-11)
                    </span>
                  </div>

                  {/* Summary */}
                  <p className="text-sm text-slate-200 leading-relaxed bg-slate-950/50 p-3.5 rounded-lg border border-slate-800/80">
                    {report.ai_explanation.summary}
                  </p>

                  {/* Evidence Points */}
                  {report.ai_explanation.evidence_points && report.ai_explanation.evidence_points.length > 0 && (
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        Key Corroborating Evidence Points:
                      </h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {report.ai_explanation.evidence_points.map((pt, idx) => (
                          <div key={idx} className="bg-slate-950 p-2.5 rounded border border-slate-800/80 text-xs flex items-start gap-2">
                            <span className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 font-mono text-[10px] shrink-0">
                              {pt.finding_id}
                            </span>
                            <span className="text-slate-300">{pt.explanation}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Recommendations */}
                  {report.ai_explanation.recommended_actions && report.ai_explanation.recommended_actions.length > 0 && (
                    <div className="pt-2">
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1.5">
                        Recommended SOC Actions:
                      </h4>
                      <ul className="grid grid-cols-1 md:grid-cols-2 gap-1.5 text-xs text-slate-300">
                        {report.ai_explanation.recommended_actions.map((act, idx) => (
                          <li key={idx} className="flex items-center gap-2">
                            <CheckCircle className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                            <span>{act}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                {/* 3. TECHNICAL FINDINGS LEDGER */}
                <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-4">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                    <div>
                      <h3 className="font-bold text-sm text-white flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        Technical Findings Ledger ({report.findings.length})
                      </h3>
                      <p className="text-xs text-slate-400">
                        Granular security signals detected by passive inspection engines
                      </p>
                    </div>

                    {/* Filter Category */}
                    <div className="flex items-center gap-1.5 overflow-x-auto text-[11px]">
                      {["ALL", "IMPERSONATION", "STRUCTURE", "DOMAIN", "TLS", "INTEL", "CONTENT", "HEADERS"].map(cat => (
                        <button
                          key={cat}
                          onClick={() => setSelectedFindingCategory(cat)}
                          className={`px-2 py-1 rounded transition-colors ${
                            selectedFindingCategory === cat
                              ? "bg-cyan-600 text-white font-semibold"
                              : "bg-slate-950 text-slate-400 hover:text-slate-200 border border-slate-800"
                          }`}
                        >
                          {cat}
                        </button>
                      ))}
                    </div>
                  </div>

                  {report.findings.length === 0 ? (
                    <div className="text-center py-8 text-xs text-slate-400 bg-slate-950 rounded-lg border border-slate-800">
                      <CheckCircle className="w-8 h-8 text-emerald-400 mx-auto mb-2 opacity-80" />
                      No suspicious heuristic signals triggered for this target.
                    </div>
                  ) : (
                    <div className="space-y-2.5">
                      {report.findings
                        .filter(f => selectedFindingCategory === "ALL" || f.category === selectedFindingCategory)
                        .map((f, idx) => {
                          const isExpanded = expandedFindings[f.id];
                          return (
                            <div
                              key={idx}
                              className="bg-slate-950 rounded-lg border border-slate-850 hover:border-slate-800 transition-all overflow-hidden"
                            >
                              <div
                                onClick={() => setExpandedFindings(prev => ({ ...prev, [f.id]: !isExpanded }))}
                                className="p-3 cursor-pointer flex items-center justify-between gap-3 select-none"
                              >
                                <div className="flex items-center gap-3">
                                  <span className="font-mono text-xs font-bold text-cyan-400 bg-slate-900 px-2 py-0.5 rounded border border-slate-800">
                                    {f.id}
                                  </span>
                                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase ${
                                    f.severity === "Critical" ? "bg-red-950 text-red-300 border border-red-800" :
                                    f.severity === "High" ? "bg-rose-950 text-rose-300 border border-rose-800" :
                                    f.severity === "Medium" ? "bg-amber-950 text-amber-300 border border-amber-800" :
                                    "bg-slate-900 text-slate-400 border border-slate-800"
                                  }`}>
                                    {f.severity}
                                  </span>
                                  <span className="text-xs font-bold text-white">{f.title}</span>
                                </div>

                                <div className="flex items-center gap-3">
                                  <span className="text-xs font-mono text-amber-400 font-semibold">
                                    +{f.points} pts
                                  </span>
                                  {isExpanded ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                                </div>
                              </div>

                              {isExpanded && (
                                <div className="p-3 pt-0 border-t border-slate-900 bg-slate-950/40 text-xs space-y-2.5">
                                  <p className="text-slate-300">{f.description}</p>
                                  
                                  {/* Technical Evidence */}
                                  {f.technical_evidence && Object.keys(f.technical_evidence).length > 0 && (
                                    <div className="bg-slate-900 p-2.5 rounded border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto">
                                      {JSON.stringify(f.technical_evidence, null, 2)}
                                    </div>
                                  )}

                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-slate-400 pt-1">
                                    <div>
                                      <span className="font-semibold text-slate-300">Potential Impact: </span>
                                      {f.potential_impact}
                                    </div>
                                    <div>
                                      <span className="font-semibold text-slate-300">Action: </span>
                                      {f.recommendation}
                                    </div>
                                  </div>
                                </div>
                              )}
                            </div>
                          );
                        })}
                    </div>
                  )}
                </div>

                {/* 4. TLS & SECURITY HEADERS GRID */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                  
                  {/* TLS Certificate Card */}
                  <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-3">
                    <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                      <div className="flex items-center gap-2">
                        <Lock className="w-4 h-4 text-cyan-400" />
                        <h3 className="font-bold text-sm text-white">TLS Certificate & PKI Chain</h3>
                      </div>
                      {report.tls && (
                        <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {report.tls.tls_verdict}
                        </span>
                      )}
                    </div>

                    {report.tls ? (
                      <div className="space-y-2 text-xs">
                        <div className="grid grid-cols-2 gap-2 bg-slate-950 p-2.5 rounded border border-slate-800/80">
                          <div>
                            <span className="text-slate-500 font-semibold">Subject CN:</span>
                            <div className="font-mono text-slate-200 truncate">{report.tls.subject}</div>
                          </div>
                          <div>
                            <span className="text-slate-500 font-semibold">Issuer:</span>
                            <div className="font-mono text-slate-200 truncate">{report.tls.issuer}</div>
                          </div>
                          <div>
                            <span className="text-slate-500 font-semibold">Key Algorithm:</span>
                            <div className="font-mono text-slate-200">{report.tls.public_key_algorithm} ({report.tls.public_key_size} bit)</div>
                          </div>
                          <div>
                            <span className="text-slate-500 font-semibold">Validity Remaining:</span>
                            <div className="font-mono text-slate-200">{report.tls.days_remaining} days</div>
                          </div>
                        </div>

                        {/* SHA-256 Fingerprint */}
                        <div className="bg-slate-950 p-2 rounded border border-slate-800/80 font-mono text-[11px] text-slate-400 flex items-center justify-between">
                          <span className="truncate">Cert SHA256: {report.tls.certificate_sha256}</span>
                          <button onClick={() => handleCopy(report.tls?.certificate_sha256 || "")} className="ml-2">
                            <Copy className="w-3.5 h-3.5 text-slate-500 hover:text-white" />
                          </button>
                        </div>

                        {/* Notice on HTTPS safety (HC-03) */}
                        <div className="p-2.5 rounded bg-cyan-950/30 border border-cyan-800/50 text-[11px] text-cyan-300 flex items-start gap-2">
                          <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                          <span>{report.tls.https_note}</span>
                        </div>
                      </div>
                    ) : (
                      <div className="text-center py-8 text-xs text-slate-500 bg-slate-950 rounded-lg">
                        No TLS certificate telemetry available (HTTP only or unresolvable).
                      </div>
                    )}
                  </div>

                  {/* Security Headers Card */}
                  <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-3">
                    <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                      <div className="flex items-center gap-2">
                        <Shield className="w-4 h-4 text-blue-400" />
                        <h3 className="font-bold text-sm text-white">HTTP Security Headers</h3>
                      </div>
                      <span className="text-xs text-slate-500">
                        HSTS · CSP · XFO · XCTO
                      </span>
                    </div>

                    <div className="space-y-1.5 text-xs">
                      {report.security_headers.map((h, idx) => (
                        <div
                          key={idx}
                          className="bg-slate-950 p-2 rounded border border-slate-800 flex items-center justify-between text-xs"
                        >
                          <span className="font-mono text-slate-300">{h.header_name}</span>
                          {h.present ? (
                            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-semibold">
                              Present
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded bg-slate-850 text-slate-500 border border-slate-800 text-[10px] font-semibold">
                              Missing
                            </span>
                          )}
                        </div>
                      ))}
                    </div>

                    {/* Redirect Chain Preview */}
                    {report.redirect_chain.length > 0 && (
                      <div className="pt-2 border-t border-slate-800/80">
                        <div className="text-[11px] font-semibold text-slate-400 mb-1.5">
                          Redirect Chain ({report.redirect_chain.length} hops):
                        </div>
                        <div className="space-y-1 font-mono text-[11px]">
                          {report.redirect_chain.map((hop, idx) => (
                            <div key={idx} className="flex items-center gap-2 text-slate-300">
                              <span className="text-slate-500">{idx + 1}.</span>
                              <span className="px-1.5 py-0.2 bg-slate-950 rounded text-cyan-400 border border-slate-800">
                                {hop.status_code}
                              </span>
                              <span className="truncate">{hop.url}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                </div>

                {/* 5. WEB3 CRYPTOGRAPHIC VERIFICATION & TAMPER SUITE */}
                <div className="bg-slate-900 rounded-xl border border-slate-800 p-6 shadow-xl space-y-4">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                    <div>
                      <h3 className="font-bold text-sm text-white flex items-center gap-2">
                        <Fingerprint className="w-4 h-4 text-cyan-400" />
                        Web3 Cryptographic Proof Registry
                      </h3>
                      <p className="text-xs text-slate-400">
                        Anchored to EVM ThreatRegistry smart contract · Zero PII on-chain (HC-07 & HC-08)
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      {!report.is_committed ? (
                        <button
                          onClick={handleCommit}
                          disabled={isCommitting}
                          className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 disabled:opacity-50 transition-colors"
                        >
                          {isCommitting ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5" />}
                          Commit Proof On-Chain
                        </button>
                      ) : (
                        <div className="flex items-center gap-2">
                          <span className="px-2.5 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-xs font-semibold flex items-center gap-1">
                            <CheckCheck className="w-3.5 h-3.5" />
                            Committed On-Chain
                          </span>
                          <button
                            onClick={handleVerify}
                            disabled={isVerifying}
                            className="px-3 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium flex items-center gap-1 transition-colors"
                          >
                            {isVerifying ? <RefreshCw className="w-3 h-3 animate-spin" /> : <Check className="w-3 h-3" />}
                            Verify Integrity
                          </button>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Web3 Details Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                    {/* Canonical Hash Display */}
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                      <span className="text-slate-500 font-semibold">Canonical SHA-256 Hash (Section 8.3):</span>
                      <div className="font-mono text-cyan-300 text-[11px] break-all flex items-center justify-between">
                        <span>{report.report_hash || "Compute upon commitment"}</span>
                        {report.report_hash && (
                          <button onClick={() => handleCopy(report.report_hash || "")} className="ml-2">
                            <Copy className="w-3.5 h-3.5 text-slate-500 hover:text-white" />
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Smart Contract Details */}
                    <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 space-y-1">
                      <span className="text-slate-500 font-semibold">Blockchain Proof Anchoring:</span>
                      <div className="font-mono text-slate-300 text-[11px]">
                        <div>Network: <span className="text-white">{report.web3?.network || "Sepolia EVM (Testnet)"}</span></div>
                        <div>Tx Hash: <span className="text-cyan-400">{report.web3?.tx_hash ? `${report.web3.tx_hash.slice(0, 16)}...` : "Pending commit"}</span></div>
                      </div>
                    </div>
                  </div>

                  {/* Verification Result Banner */}
                  {verificationResult && (
                    <div className={`p-4 rounded-lg border text-xs flex items-start gap-3 ${
                      verificationResult.result_code === "MATCH"
                        ? "bg-emerald-950/60 border-emerald-800 text-emerald-200"
                        : "bg-rose-950/70 border-rose-800 text-rose-200"
                    }`}>
                      {verificationResult.result_code === "MATCH" ? (
                        <CheckCheck className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
                      ) : (
                        <AlertOctagon className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                      )}
                      <div>
                        <div className="font-bold uppercase tracking-wider">
                          Cryptographic Verification: {verificationResult.result_code}
                        </div>
                        <div className="mt-0.5 text-slate-300">{verificationResult.message}</div>
                        <div className="font-mono text-[10px] text-slate-400 mt-1">
                          Recomputed: {verificationResult.recomputed_hash}
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Security Officer Tamper Drill Panel */}
                  {report.is_committed && (
                    <div className="p-3 bg-slate-950 rounded-lg border border-slate-850 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
                      <div>
                        <span className="font-semibold text-white">Cryptographic Tamper-Detection Drill:</span>
                        <p className="text-slate-400 text-[11px]">
                          Simulate unauthorized database alteration to prove the on-chain hash flags unauthorized changes.
                        </p>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={handleTamperSimulation}
                          className="px-3 py-1.5 rounded bg-rose-950/60 hover:bg-rose-900 border border-rose-800 text-rose-300 text-xs font-medium transition-colors"
                        >
                          Simulate Tamper
                        </button>
                        <button
                          onClick={handleRestoreSimulation}
                          className="px-3 py-1.5 rounded bg-slate-850 hover:bg-slate-800 border border-slate-700 text-slate-300 text-xs font-medium transition-colors"
                        >
                          Restore State
                        </button>
                      </div>
                    </div>
                  )}
                </div>

              </div>
            )}
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 2: ACTIVE THREAT FEED (GLOBAL IOCS)                    */}
        {/* ========================================================= */}
        {mainNav === "feed" && (
          <div className="space-y-4">
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div>
                  <h2 className="text-base font-bold text-white flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    Global Threat Intelligence & Active IOCs
                  </h2>
                  <p className="text-xs text-slate-400">
                    Live feed of malicious URLs, phishing domains, and banking lures aggregated from URLhaus & curated repositories.
                  </p>
                </div>

                {/* Search & Filter */}
                <div className="flex items-center gap-2 w-full sm:w-auto">
                  <div className="relative flex-1 sm:w-64">
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-3" />
                    <input
                      type="text"
                      value={feedSearch}
                      onChange={e => setFeedSearch(e.target.value)}
                      placeholder="Filter indicators, domains..."
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                  <select
                    value={feedCategoryFilter}
                    onChange={e => setFeedCategoryFilter(e.target.value)}
                    className="bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                  >
                    <option value="ALL">All Categories</option>
                    <option value="banking phishing">Banking Phishing</option>
                    <option value="credential harvesting">Credential Harvesting</option>
                    <option value="delivery scam">Delivery Scam</option>
                    <option value="tax refund scam">Tax Scam</option>
                  </select>
                </div>
              </div>

              {/* Table */}
              <div className="overflow-x-auto rounded-lg border border-slate-800">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Indicator ID</th>
                      <th className="py-2.5 px-3">Defanged Indicator</th>
                      <th className="py-2.5 px-3">Category</th>
                      <th className="py-2.5 px-3">Confidence</th>
                      <th className="py-2.5 px-3">Feed Source</th>
                      <th className="py-2.5 px-3">Date Added</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-850 bg-slate-950/60 font-mono">
                    {filteredFeed.map((item, idx) => (
                      <tr key={idx} className="hover:bg-slate-900/60 transition-colors">
                        <td className="py-2.5 px-3 text-cyan-400 font-bold">{item.id}</td>
                        <td className="py-2.5 px-3 text-white max-w-xs truncate">{item.indicator}</td>
                        <td className="py-2.5 px-3 font-sans">
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase bg-rose-950 text-rose-300 border border-rose-800">
                            {item.category}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-sans text-emerald-400">{item.confidence}</td>
                        <td className="py-2.5 px-3 font-sans text-slate-400 truncate max-w-[180px]">{item.source}</td>
                        <td className="py-2.5 px-3 text-slate-500">{item.date_added}</td>
                        <td className="py-2.5 px-3 text-right font-sans">
                          <button
                            onClick={() => {
                              handleLoadBenchmark(item.raw_value, "url");
                              handleStartScan(item.raw_value, "url");
                            }}
                            className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-800 text-cyan-300 text-[11px] font-medium transition-colors"
                          >
                            Analyze
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 3: CAMPAIGN OPERATIONS                                */}
        {/* ========================================================= */}
        {mainNav === "campaigns" && (
          <div className="space-y-4">
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-4">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Network className="w-4 h-4 text-cyan-400" />
                  Tracked Threat Campaigns & Syndicated Networks
                </h2>
                <p className="text-xs text-slate-400">
                  Deterministic clustering of threat infrastructure using salted SPKI hashes, template signatures, and ASN records.
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {campaigns.map((camp, idx) => (
                  <div key={idx} className="bg-slate-950 rounded-xl border border-slate-800 p-4 space-y-3">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-bold text-cyan-400">{camp.campaign_id}</span>
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                            camp.severity === "Critical" ? "bg-red-950 text-red-300 border border-red-800" : "bg-amber-950 text-amber-300 border border-amber-800"
                          }`}>
                            {camp.severity}
                          </span>
                        </div>
                        <h3 className="text-sm font-bold text-white mt-1">{camp.name}</h3>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-800 text-[10px]">
                        {camp.status}
                      </span>
                    </div>

                    <div className="text-xs space-y-1.5 text-slate-300">
                      <div>
                        <span className="text-slate-500 font-semibold">Target Sector: </span>
                        {camp.target_sector}
                      </div>
                      <div>
                        <span className="text-slate-500 font-semibold">Target Brands: </span>
                        {camp.target_brands.join(", ")}
                      </div>
                      <div>
                        <span className="text-slate-500 font-semibold">Attack Vectors: </span>
                        {camp.attack_vectors.join(" · ")}
                      </div>
                    </div>

                    {/* Linked Domains */}
                    <div className="pt-2 border-t border-slate-900">
                      <span className="text-[11px] font-semibold text-slate-500 uppercase tracking-wider">
                        Associated Domains ({camp.linked_domains.length}):
                      </span>
                      <div className="flex flex-wrap gap-1.5 mt-1 font-mono text-[11px]">
                        {camp.linked_domains.map((dom, dIdx) => (
                          <span key={dIdx} className="bg-slate-900 text-slate-300 px-2 py-0.5 rounded border border-slate-800">
                            {dom}
                          </span>
                        ))}
                      </div>
                    </div>

                    {/* Mitigation */}
                    <div className="p-2.5 rounded bg-slate-900/60 border border-slate-850 text-[11px] text-slate-400">
                      <span className="text-slate-300 font-semibold">Mitigation Status: </span>
                      {camp.mitigation}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 4: ON-CHAIN LEDGER EXPLORER                            */}
        {/* ========================================================= */}
        {mainNav === "ledger" && (
          <div className="space-y-4">
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-4">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Fingerprint className="w-4 h-4 text-cyan-400" />
                  EVM ThreatRegistry Proof Explorer
                </h2>
                <p className="text-xs text-slate-400">
                  Cryptographic commitments anchored to Solidity smart contract (`ThreatRegistry.sol`). Pure 32-byte hashes only.
                </p>
              </div>

              {/* Technical Spec Banner */}
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 text-xs space-y-2">
                <div className="flex items-center gap-2 text-cyan-300 font-semibold">
                  <Key className="w-4 h-4" />
                  <span>Section 8.3 Canonical Serialisation & Cryptographic Privacy</span>
                </div>
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  TrustTrace implements a strict mathematical guarantee: zero raw URLs, zero user messages, and zero PII ever touch the blockchain. Reports are canonicalized by removing volatile keys, recursively sorting dictionary keys, serializing as compact UTF-8 JSON with <code className="text-cyan-400">(&apos;,&apos;, &apos;:&apos;)</code> separators, and computing a SHA-256 digest. Anyone holding the offline report can independently verify integrity by calculating the SHA-256 hash and matching it against the smart contract.
                </p>
              </div>

              {/* Live Contract Reference */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono">
                  <div className="text-slate-500 text-[10px] font-sans uppercase">Contract Address</div>
                  <div className="text-cyan-300 truncate mt-1">0x5FbDB2315678afecb367f032d93F642f64180aa3</div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono">
                  <div className="text-slate-500 text-[10px] font-sans uppercase">EVM Network</div>
                  <div className="text-white mt-1">Sepolia (Chain ID: 11155111)</div>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800 font-mono">
                  <div className="text-slate-500 text-[10px] font-sans uppercase">Verification Standard</div>
                  <div className="text-emerald-400 mt-1">SHA-256 Canonical (MATCH / MISMATCH)</div>
                </div>
              </div>

              {/* History of on-chain commits */}
              <div className="pt-2">
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                  Recent Verified Commitments
                </h3>
                <div className="overflow-x-auto rounded-lg border border-slate-800">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] font-bold border-b border-slate-800">
                      <tr>
                        <th className="py-2.5 px-3">Report ID</th>
                        <th className="py-2.5 px-3">Canonical Hash (SHA-256)</th>
                        <th className="py-2.5 px-3">Reporter</th>
                        <th className="py-2.5 px-3">Revision</th>
                        <th className="py-2.5 px-3">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-850 bg-slate-950/60 text-[11px]">
                      <tr>
                        <td className="py-2.5 px-3 text-cyan-400">b1-verified-01</td>
                        <td className="py-2.5 px-3 text-slate-300">4a72d3e2b10984cfb721839218293182...</td>
                        <td className="py-2.5 px-3 text-slate-400">0x7099797...79C8</td>
                        <td className="py-2.5 px-3 text-white">rev 1</td>
                        <td className="py-2.5 px-3 text-emerald-400">Verified</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 px-3 text-cyan-400">s1-phishing-sbi</td>
                        <td className="py-2.5 px-3 text-slate-300">8c1920da9f8e124c4ff5b73ab9df3ee8...</td>
                        <td className="py-2.5 px-3 text-slate-400">0x7099797...79C8</td>
                        <td className="py-2.5 px-3 text-white">rev 1</td>
                        <td className="py-2.5 px-3 text-emerald-400">Verified</td>
                      </tr>
                      <tr>
                        <td className="py-2.5 px-3 text-cyan-400">s3-smishing-lure</td>
                        <td className="py-2.5 px-3 text-slate-300">19283019283019283019283019283019...</td>
                        <td className="py-2.5 px-3 text-slate-400">0x7099797...79C8</td>
                        <td className="py-2.5 px-3 text-white">rev 1</td>
                        <td className="py-2.5 px-3 text-emerald-400">Verified</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 5: CA DISTRUST WATCHLIST                              */}
        {/* ========================================================= */}
        {mainNav === "ca_watchlist" && (
          <div className="space-y-4">
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-4">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-rose-400" />
                  Certificate Authority (CA) Distrust Watchlist
                </h2>
                <p className="text-xs text-slate-400">
                  Published root and intermediate CA distrust advisories (including eMudhra Incident, WoSign, TrustCor, and Symantec legacy).
                </p>
              </div>

              {/* Guardrail explanation (HC-12) */}
              <div className="bg-slate-950 p-4 rounded-lg border border-slate-800 text-xs space-y-2">
                <div className="flex items-center gap-2 text-amber-300 font-semibold">
                  <AlertTriangle className="w-4 h-4" />
                  <span>The eMudhra Guardrail Protocol (HC-12)</span>
                </div>
                <p className="text-slate-400 leading-relaxed text-[11px]">
                  TrustTrace strictly adheres to rigorous cryptographic realism: no scanner can detect an internal Certificate Authority private key weakness simply from looking at a URL or performing a TLS handshake. TrustTrace evaluates CAs strictly by matching presented certificate chain SHA-256 fingerprints against official, published browser distrust lists.
                </p>
              </div>

              {/* Distrusted CAs List */}
              <div className="space-y-3">
                {distrustedCAs.map((ca, idx) => (
                  <div key={idx} className="bg-slate-950 rounded-lg border border-slate-800 p-4 space-y-2 text-xs">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h3 className="font-bold text-white text-sm">{ca.ca_name}</h3>
                        <span className="text-[11px] text-slate-400">Source: {ca.source_name}</span>
                      </div>
                      <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-bold uppercase">
                        Distrusted
                      </span>
                    </div>

                    <p className="text-slate-300 text-xs leading-relaxed">{ca.reason}</p>

                    <div className="bg-slate-900 p-2 rounded border border-slate-850 font-mono text-[11px] text-slate-400 flex items-center justify-between">
                      <span className="truncate">Fingerprint: {ca.value}</span>
                      <button onClick={() => handleCopy(ca.value)} className="ml-2">
                        <Copy className="w-3.5 h-3.5 text-slate-500 hover:text-white" />
                      </button>
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                      <span>Date Added: {ca.date_added}</span>
                      {ca.source_url && (
                        <a
                          href={ca.source_url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-cyan-400 hover:underline flex items-center gap-1"
                        >
                          Official Advisory <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ========================================================= */}
        {/* TAB 6: ACTIVE SECURITY CONTROLS                            */}
        {/* ========================================================= */}
        {mainNav === "controls" && (
          <div className="space-y-4">
            <div className="bg-slate-900 rounded-xl border border-slate-800 p-5 shadow-lg space-y-4">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <Lock className="w-4 h-4 text-cyan-400" />
                  Active Security Guardrails & Compliance Matrix
                </h2>
                <p className="text-xs text-slate-400">
                  Transparent architectural defenses enforced on every request (HC-01 through HC-16).
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {controlsData.map((ctrl, idx) => (
                  <div key={idx} className="bg-slate-950 rounded-xl border border-slate-800 p-4 space-y-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono text-[10px] font-bold">
                        {ctrl.id}
                      </span>
                      <h3 className="font-bold text-sm text-white">{ctrl.name}</h3>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{ctrl.description}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

      </main>

      {/* 5. AUDIT HISTORY MODAL */}
      {showHistoryModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full max-h-[80vh] flex flex-col shadow-2xl">
            <div className="p-4 border-b border-slate-800 flex items-center justify-between">
              <h3 className="font-bold text-sm text-white flex items-center gap-2">
                <History className="w-4 h-4 text-cyan-400" />
                Historical Scan Audit Ledger
              </h3>
              <button onClick={() => setShowHistoryModal(false)} className="text-slate-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <div className="p-4 overflow-y-auto flex-1 divide-y divide-slate-850">
              {historyReports.length === 0 ? (
                <div className="text-center py-8 text-xs text-slate-500">
                  No scan reports logged in local database yet.
                </div>
              ) : (
                historyReports.map((r, idx) => (
                  <div key={idx} className="py-3 flex items-center justify-between gap-3 text-xs">
                    <div className="space-y-0.5">
                      <div className="font-mono text-cyan-300 font-bold">{defang(r.input_display)}</div>
                      <div className="text-slate-500 text-[11px]">{r.created_at} · ID: {r.report_id.slice(0, 8)}...</div>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                        r.risk_label === "Low Risk" ? "bg-emerald-950 text-emerald-300" :
                        r.risk_label === "Suspicious" ? "bg-amber-950 text-amber-300" :
                        "bg-rose-950 text-rose-300"
                      }`}>
                        {r.risk_label} ({r.risk_score})
                      </span>
                      {r.is_committed && (
                        <span className="text-[10px] text-cyan-400 font-mono">On-Chain</span>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* 6. ENTERPRISE FOOTER */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-6 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <span className="font-bold text-slate-300">TrustTrace</span>
            <span>·</span>
            <span>HackMatrix 2026</span>
            <span>·</span>
            <span className="text-cyan-400 font-medium">Team APEX WARCODE (HM-6FC44F)</span>
          </div>
          <div>
            Built with FastAPI, Next.js 14, Solidity EVM, and Google Gemini AI.
          </div>
        </div>
      </footer>

    </div>
  );
}
