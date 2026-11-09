"use client";
import React, { useState } from "react";
import {
  CheckCircle, AlertTriangle, AlertOctagon, XCircle, Info,
  Cpu, Lock, ArrowRight, Database, Shield, ChevronDown, ChevronRight,
  Download, Sparkles, Link2, Clock, Fingerprint, RefreshCw, Loader2,
  ChevronUp
} from "lucide-react";
import { Report, RiskLabel, Finding } from "@/types";
import { defang } from "@/lib/defang";
import { commitReport, verifyReport, tamperReport, restoreReport } from "@/lib/api";

/* ── Risk Helpers ────────────────────────────────────────────────────────── */

const riskMeta: Record<RiskLabel, { color: string; bg: string; border: string; darkBg: string; darkBorder: string; icon: typeof CheckCircle; desc: string }> = {
  "Low Risk":             { color: "text-emerald-700 dark:text-emerald-400", bg: "bg-emerald-50", border: "border-emerald-200", darkBg: "dark:bg-emerald-900/20", darkBorder: "dark:border-emerald-800", icon: CheckCircle,   desc: "No significant malicious indicators detected within available checks." },
  "Suspicious":           { color: "text-amber-700 dark:text-amber-400",     bg: "bg-amber-50",   border: "border-amber-200",   darkBg: "dark:bg-amber-900/20",   darkBorder: "dark:border-amber-800",   icon: AlertTriangle, desc: "One or more indicators require further investigation." },
  "High Risk":            { color: "text-orange-700 dark:text-orange-400",   bg: "bg-orange-50",  border: "border-orange-200",  darkBg: "dark:bg-orange-900/20",  darkBorder: "dark:border-orange-800",  icon: AlertOctagon,  desc: "Multiple significant indicators suggest a security threat." },
  "Confirmed Malicious":  { color: "text-red-700 dark:text-red-400",         bg: "bg-red-50",     border: "border-red-200",     darkBg: "dark:bg-red-900/20",     darkBorder: "dark:border-red-800",     icon: XCircle,       desc: "Confirmed by authoritative threat intelligence feeds." },
  "Inconclusive":         { color: "text-slate-600 dark:text-slate-400",     bg: "bg-slate-100",  border: "border-slate-200",   darkBg: "dark:bg-slate-800",      darkBorder: "dark:border-slate-700",   icon: Info,          desc: "Insufficient data or unavailable verification sources." },
};

const sevColors: Record<string, string> = {
  Critical: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  High: "bg-orange-100 text-orange-800 dark:bg-orange-900/30 dark:text-orange-400",
  Medium: "bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400",
  Low: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
  Info: "bg-slate-100 text-slate-700 dark:bg-slate-700 dark:text-slate-300",
};

/* ── Sub-Components ──────────────────────────────────────────────────────── */

function SectionCard({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-sm p-5 sm:p-6 ${className}`}>
      {children}
    </div>
  );
}

function SectionTitle({ icon: Icon, children }: { icon: typeof Shield; children: React.ReactNode }) {
  return (
    <h3 className="text-sm font-bold text-slate-800 dark:text-slate-200 flex items-center gap-2 mb-4">
      <Icon className="w-4 h-4 text-brand-600 dark:text-brand-400" />
      {children}
    </h3>
  );
}

/* ── Main Component ──────────────────────────────────────────────────────── */

export default function ReportView({ report }: { report: Report }) {
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [committing, setCommitting] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verResult, setVerResult] = useState<any>(null);
  const [tamperState, setTamperState] = useState<string | null>(null);
  const [web3Data, setWeb3Data] = useState(report.web3);
  const [tamperOpen, setTamperOpen] = useState(false);

  const rm = riskMeta[report.risk_label] || riskMeta["Inconclusive"];
  const RiskIcon = rm.icon;

  const handleCommit = async () => {
    setCommitting(true);
    try {
      const res = await commitReport(report.report_id);
      setWeb3Data(res);
      setVerResult(null);
    } catch (e: any) { alert(e.message); }
    finally { setCommitting(false); }
  };

  const handleVerify = async () => {
    setVerifying(true);
    try { setVerResult(await verifyReport(report.report_id)); }
    catch (e: any) { alert(e.message); }
    finally { setVerifying(false); }
  };

  const handleTamper = async () => {
    try {
      await tamperReport(report.report_id);
      setTamperState("Database tampered for demonstration");
      setVerResult(await verifyReport(report.report_id));
    } catch (e: any) { alert(e.message); }
  };

  const handleRestore = async () => {
    try {
      await restoreReport(report.report_id);
      setTamperState(null);
      setVerResult(await verifyReport(report.report_id));
    } catch (e: any) { alert(e.message); }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6 animate-slide-up">
      {/* ── 1. Risk Banner ────────────────────────────────────────────── */}
      <div className={`rounded-2xl border-2 ${rm.border} ${rm.darkBorder} ${rm.bg} ${rm.darkBg} p-6 sm:p-8`}>
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-start gap-4">
            <div className={`p-3 rounded-xl ${rm.bg} ${rm.darkBg}`}>
              <RiskIcon className={`w-8 h-8 ${rm.color}`} />
            </div>
            <div>
              <h2 className={`text-2xl sm:text-3xl font-black tracking-tight ${rm.color}`}>{report.risk_label}</h2>
              <p className="text-sm text-slate-600 dark:text-slate-400 mt-1">{rm.desc}</p>
            </div>
          </div>
          <div className="flex gap-4 text-center shrink-0">
            <div className="bg-white/70 dark:bg-slate-800/70 backdrop-blur rounded-xl px-4 py-2 border border-slate-200/50 dark:border-slate-700/50">
              <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Score</div>
              <div className="text-2xl font-black text-slate-900 dark:text-white">{report.risk_score}</div>
            </div>
            <div className="bg-white/70 dark:bg-slate-800/70 backdrop-blur rounded-xl px-4 py-2 border border-slate-200/50 dark:border-slate-700/50">
              <div className="text-xs font-medium text-slate-500 dark:text-slate-400">Coverage</div>
              <div className="text-2xl font-black text-slate-900 dark:text-white">{report.evidence_coverage.percent}%</div>
            </div>
          </div>
        </div>
        <div className="mt-4 pt-4 border-t border-slate-200/50 dark:border-slate-700/50 flex flex-wrap gap-x-6 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
          <span className="flex items-center gap-1"><Link2 className="w-3 h-3" /> <span className="font-mono">{defang(report.input_display)}</span></span>
          <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {new Date(report.created_at).toLocaleString()}</span>
          {report.analysis_duration_ms > 0 && <span className="flex items-center gap-1"><RefreshCw className="w-3 h-3" /> {report.analysis_duration_ms}ms</span>}
        </div>
      </div>

      {/* ── 2. AI Explanation ──────────────────────────────────────────── */}
      <SectionCard>
        <div className="flex items-center justify-between mb-4">
          <SectionTitle icon={Sparkles}>AI Explanation</SectionTitle>
          <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${
            report.ai_explanation.generated_by === "llm"
              ? "bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400"
              : "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-400"
          }`}>
            {report.ai_explanation.generated_by === "llm" ? "Gemini AI" : "Template"}
          </span>
        </div>
        <p className="text-sm text-slate-700 dark:text-slate-300 leading-relaxed">{report.ai_explanation.summary}</p>
        {report.ai_explanation.evidence_points.length > 0 && (
          <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800 space-y-2">
            <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">Evidence Citations</span>
            {report.ai_explanation.evidence_points.map((pt, i) => (
              <div key={i} className="flex items-start gap-2 text-sm">
                <span className="font-mono text-xs bg-brand-100 dark:bg-brand-900/30 text-brand-700 dark:text-brand-400 px-2 py-0.5 rounded font-bold shrink-0">{pt.finding_id}</span>
                <span className="text-slate-600 dark:text-slate-400">{pt.explanation}</span>
              </div>
            ))}
          </div>
        )}
        <p className="text-xs text-slate-400 dark:text-slate-500 mt-4 italic">{report.ai_explanation.limitations_note}</p>
      </SectionCard>

      {/* ── 3. Campaign ───────────────────────────────────────────────── */}
      {report.campaign?.linked && (
        <div className={`rounded-2xl border-2 p-5 flex items-start gap-3 ${
          report.campaign.strength === "strong"
            ? "bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-800 text-red-800 dark:text-red-300"
            : "bg-amber-50 dark:bg-amber-900/20 border-amber-300 dark:border-amber-800 text-amber-800 dark:text-amber-300"
        }`}>
          <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <span className="font-bold text-sm">{report.campaign.strength === "strong" ? "Linked to Known Phishing Campaign" : "Possible Infrastructure Overlap"}</span>
            <p className="text-xs opacity-90">{report.campaign.ai_summary}</p>
            <div className="flex flex-wrap gap-1.5 pt-1">
              {report.campaign.matched_indicators.map((ind, i) => (
                <span key={i} className="text-xs font-mono bg-white/60 dark:bg-slate-800/60 px-2 py-0.5 rounded border border-current/20">{ind}</span>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── 4. Findings ───────────────────────────────────────────────── */}
      <SectionCard>
        <SectionTitle icon={AlertTriangle}>Threat Findings ({report.findings.length})</SectionTitle>
        {report.findings.length === 0 ? (
          <p className="text-sm text-slate-500 dark:text-slate-400 italic">No adverse threat findings identified.</p>
        ) : (
          <div className="space-y-2">
            {[...report.findings].sort((a, b) => b.points - a.points).map(f => {
              const isOpen = expanded[f.id];
              return (
                <div key={f.id} className="border border-slate-200 dark:border-slate-700 rounded-xl overflow-hidden">
                  <button
                    onClick={() => setExpanded(p => ({ ...p, [f.id]: !p[f.id] }))}
                    className="w-full px-4 py-3 flex items-center justify-between hover:bg-slate-50 dark:hover:bg-slate-800/50 text-left transition"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className={`text-xs font-bold px-2 py-0.5 rounded uppercase shrink-0 ${sevColors[f.severity] || sevColors.Info}`}>{f.severity}</span>
                      <span className="text-xs font-mono font-bold text-slate-500 dark:text-slate-400 shrink-0">{f.id}</span>
                      <span className="text-sm font-semibold text-slate-800 dark:text-slate-200 truncate">{f.title}</span>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="text-xs font-mono text-slate-400">+{f.points}</span>
                      {isOpen ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
                    </div>
                  </button>
                  {isOpen && (
                    <div className="px-4 py-4 bg-slate-50 dark:bg-slate-800/30 border-t border-slate-100 dark:border-slate-800 text-sm space-y-3 animate-fade-in">
                      <p className="text-slate-700 dark:text-slate-300">{f.description}</p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        <div className="p-3 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700">
                          <span className="text-xs font-bold text-slate-500 dark:text-slate-400 block mb-1">Potential Impact</span>
                          <span className="text-xs text-slate-600 dark:text-slate-300">{f.potential_impact}</span>
                        </div>
                        <div className="p-3 bg-white dark:bg-slate-800 rounded-lg border border-slate-200 dark:border-slate-700">
                          <span className="text-xs font-bold text-slate-500 dark:text-slate-400 block mb-1">Recommendation</span>
                          <span className="text-xs text-slate-600 dark:text-slate-300">{f.recommendation}</span>
                        </div>
                      </div>
                      <p className="text-xs text-slate-400 dark:text-slate-500 italic">Source: {f.source} · Limitation: {f.limitation}</p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </SectionCard>

      {/* ── 5. Technical Details Grid ─────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* TLS */}
        {report.tls && (
          <SectionCard>
            <SectionTitle icon={Lock}>TLS Certificate</SectionTitle>
            <div className="flex items-center justify-between mb-3">
              <span className={`text-xs font-bold px-2.5 py-1 rounded-full border ${
                report.tls.tls_verdict === "Valid configuration"
                  ? "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800"
                  : "bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800"
              }`}>{report.tls.tls_verdict}</span>
            </div>
            <div className="space-y-2 text-xs text-slate-600 dark:text-slate-400">
              <p><span className="font-semibold text-slate-700 dark:text-slate-300">Subject:</span> {report.tls.subject}</p>
              <p><span className="font-semibold text-slate-700 dark:text-slate-300">Issuer:</span> {report.tls.issuer}</p>
              <p><span className="font-semibold text-slate-700 dark:text-slate-300">Remaining:</span> {report.tls.days_remaining} days</p>
              <p><span className="font-semibold text-slate-700 dark:text-slate-300">Key:</span> {report.tls.public_key_algorithm} ({report.tls.public_key_size}-bit)</p>
              <p className="font-mono text-[11px] break-all"><span className="font-sans font-semibold text-slate-700 dark:text-slate-300">SHA-256:</span> {report.tls.certificate_sha256}</p>
            </div>
            <div className="mt-3 p-2.5 bg-blue-50 dark:bg-blue-900/10 border border-blue-200 dark:border-blue-800 rounded-lg text-xs text-blue-700 dark:text-blue-400 flex items-start gap-2">
              <Info className="w-3.5 h-3.5 shrink-0 mt-0.5" />
              <span>{report.tls.https_note}</span>
            </div>
          </SectionCard>
        )}

        {/* Security Headers */}
        <SectionCard>
          <SectionTitle icon={Shield}>Security Headers</SectionTitle>
          <div className="space-y-1.5">
            {report.security_headers.map((h, i) => (
              <div key={i} className="flex items-center justify-between py-1.5 px-2 rounded-lg hover:bg-slate-50 dark:hover:bg-slate-800/50">
                <span className="text-xs font-mono text-slate-700 dark:text-slate-300">{h.header_name}</span>
                <span className={`text-xs font-bold px-2 py-0.5 rounded ${h.present
                  ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
                  : "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400"
                }`}>{h.present ? "Present" : "Missing"}</span>
              </div>
            ))}
          </div>
        </SectionCard>

        {/* Threat Intel */}
        <SectionCard>
          <SectionTitle icon={Database}>Threat Intelligence</SectionTitle>
          <div className="space-y-2">
            {report.threat_intel.feeds_queried.map((feed, i) => (
              <div key={i} className="flex items-center justify-between p-2.5 bg-slate-50 dark:bg-slate-800 rounded-lg border border-slate-100 dark:border-slate-700">
                <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{feed}</span>
                <span className={`text-xs font-bold px-2 py-0.5 rounded ${
                  report.threat_intel.feeds_answered.includes(feed)
                    ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400"
                    : "bg-slate-200 text-slate-600 dark:bg-slate-700 dark:text-slate-400"
                }`}>{report.threat_intel.feeds_answered.includes(feed) ? "Responded" : "Unavailable"}</span>
              </div>
            ))}
          </div>
          <p className="text-xs text-slate-400 dark:text-slate-500 italic mt-3">Absence of a match does not prove a site is trustworthy.</p>
        </SectionCard>

        {/* Redirects */}
        {report.redirect_chain.length > 0 && (
          <SectionCard>
            <SectionTitle icon={ArrowRight}>Redirect Chain ({report.redirect_chain.length})</SectionTitle>
            <div className="space-y-2">
              {report.redirect_chain.map((hop, i) => (
                <div key={i} className="flex items-center gap-2 py-2 px-3 bg-slate-50 dark:bg-slate-800 rounded-lg border border-slate-100 dark:border-slate-700 text-xs">
                  <span className="font-mono font-bold bg-slate-200 dark:bg-slate-700 text-slate-700 dark:text-slate-300 px-1.5 py-0.5 rounded shrink-0">{hop.status_code}</span>
                  <span className="font-mono text-slate-600 dark:text-slate-400 truncate flex-1">{hop.url}</span>
                  <span className={`font-bold px-2 py-0.5 rounded shrink-0 ${hop.same_site ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400" : "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400"}`}>
                    {hop.same_site ? "Same Site" : "Cross-Domain"}
                  </span>
                </div>
              ))}
            </div>
          </SectionCard>
        )}
      </div>

      {/* ── 6. Web3 Verification ──────────────────────────────────────── */}
      <SectionCard>
        <div className="flex items-center justify-between mb-4">
          <SectionTitle icon={Fingerprint}>Blockchain Verification</SectionTitle>
          <span className="text-xs font-mono text-slate-400 dark:text-slate-500">Ethereum / Hardhat</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-5 text-xs text-slate-600 dark:text-slate-400">
          <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
            <span className="font-bold text-slate-700 dark:text-slate-300 block mb-1">Off-Chain Privacy</span>
            Only a cryptographic hash, timestamp, and reporter address go on-chain. Raw URLs and personal data remain private.
          </div>
          <div className="p-3 bg-slate-50 dark:bg-slate-800 rounded-xl border border-slate-200 dark:border-slate-700">
            <span className="font-bold text-slate-700 dark:text-slate-300 block mb-1">Integrity ≠ Truth</span>
            A blockchain record proves a report has not been altered. It does not prove the report is correct.
          </div>
        </div>

        <div className="flex flex-wrap gap-3 mb-4">
          <button onClick={handleCommit} disabled={committing || web3Data?.status === "committed"} className="px-4 py-2.5 bg-brand-600 hover:bg-brand-700 disabled:opacity-50 text-white font-semibold text-xs rounded-xl shadow-lg shadow-brand-600/20 transition flex items-center gap-2">
            {committing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Lock className="w-3.5 h-3.5" />}
            {web3Data?.status === "committed" ? "Committed On-Chain" : "Commit to Blockchain"}
          </button>
          <button onClick={handleVerify} disabled={verifying || !web3Data} className="px-4 py-2.5 bg-slate-800 dark:bg-slate-700 hover:bg-slate-900 dark:hover:bg-slate-600 disabled:opacity-50 text-white font-semibold text-xs rounded-xl transition flex items-center gap-2">
            {verifying ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <CheckCircle className="w-3.5 h-3.5" />}
            Verify Integrity
          </button>
          <button
            onClick={() => {
              const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
              const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
              a.download = `trusttrace-${report.report_id}.json`; a.click();
            }}
            className="px-4 py-2.5 bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 font-semibold text-xs rounded-xl border border-slate-200 dark:border-slate-700 transition flex items-center gap-2"
          >
            <Download className="w-3.5 h-3.5" /> Download Report
          </button>
        </div>

        {/* Verification Result */}
        {verResult && (
          <div className={`p-4 rounded-xl border-2 mb-4 animate-fade-in ${
            verResult.result_code === "MATCH"
              ? "bg-emerald-50 dark:bg-emerald-900/20 border-emerald-300 dark:border-emerald-800"
              : "bg-red-50 dark:bg-red-900/20 border-red-300 dark:border-red-800"
          }`}>
            <div className="flex items-center gap-2 mb-2">
              {verResult.result_code === "MATCH"
                ? <CheckCircle className="w-5 h-5 text-emerald-600 dark:text-emerald-400" />
                : <AlertOctagon className="w-5 h-5 text-red-600 dark:text-red-400" />}
              <span className={`font-bold text-sm ${verResult.result_code === "MATCH" ? "text-emerald-800 dark:text-emerald-300" : "text-red-800 dark:text-red-300"}`}>
                VERIFICATION: {verResult.result_code}
              </span>
            </div>
            <p className={`text-xs mb-3 ${verResult.result_code === "MATCH" ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400"}`}>{verResult.message}</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs font-mono">
              <div className="p-2 bg-white/70 dark:bg-slate-800/70 rounded-lg border border-slate-200/50 dark:border-slate-700/50">
                <span className="font-sans font-bold text-slate-500 dark:text-slate-400 block text-[10px] mb-0.5">Stored Hash</span>
                <span className="break-all text-slate-700 dark:text-slate-300">{verResult.recomputed_hash}</span>
              </div>
              <div className="p-2 bg-white/70 dark:bg-slate-800/70 rounded-lg border border-slate-200/50 dark:border-slate-700/50">
                <span className="font-sans font-bold text-slate-500 dark:text-slate-400 block text-[10px] mb-0.5">On-Chain Hash</span>
                <span className="break-all text-slate-700 dark:text-slate-300">{verResult.onchain_hash || "N/A"}</span>
              </div>
            </div>
          </div>
        )}

        {/* Tamper testing (collapsible) */}
        <div className="border-t border-slate-100 dark:border-slate-800 pt-3">
          <button onClick={() => setTamperOpen(!tamperOpen)} className="flex items-center gap-2 text-xs font-semibold text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300 transition">
            {tamperOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
            Advanced: Tamper Testing
          </button>
          {tamperOpen && (
            <div className="mt-3 flex gap-2 animate-fade-in">
              <button onClick={handleTamper} className="px-3 py-1.5 text-xs bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 text-red-700 dark:text-red-400 rounded-lg border border-red-200 dark:border-red-800 font-medium transition">Simulate Tamper</button>
              <button onClick={handleRestore} className="px-3 py-1.5 text-xs bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 rounded-lg border border-slate-200 dark:border-slate-700 font-medium transition">Restore Original</button>
              {tamperState && <span className="text-xs text-red-600 dark:text-red-400 font-medium self-center">{tamperState}</span>}
            </div>
          )}
        </div>
      </SectionCard>

      {/* ── 7. Disclaimer ─────────────────────────────────────────────── */}
      <div className="text-center text-xs text-slate-400 dark:text-slate-500 py-4">
        {report.disclaimer}
      </div>
    </div>
  );
}
