"use client";
import React, { useState, useEffect, useCallback } from "react";
import {
  History, Shield, Link2, MessageSquare, CheckCircle, AlertTriangle,
  AlertOctagon, XCircle, Info, RefreshCw, Database,
  ChevronRight, Filter, Loader2
} from "lucide-react";
import { fetchReportsList, fetchReport } from "@/lib/api";
import { Report, RiskLabel } from "@/types";
import { defang } from "@/lib/defang";

interface ReportSummary {
  report_id: string;
  created_at: string;
  input_type: "url" | "message";
  input_display: string;
  registrable_domain: string;
  risk_label: RiskLabel;
  risk_score: number;
  is_committed: boolean;
  report_hash?: string;
}

interface ReportsHistoryProps {
  onSelectReport?: (report: Report) => void;
}

const riskBadges: Record<RiskLabel, { bg: string; text: string; icon: typeof CheckCircle }> = {
  "Low Risk": {
    bg: "bg-emerald-50 dark:bg-emerald-950/40 border-emerald-200 dark:border-emerald-800",
    text: "text-emerald-700 dark:text-emerald-400",
    icon: CheckCircle
  },
  "Suspicious": {
    bg: "bg-amber-50 dark:bg-amber-950/40 border-amber-200 dark:border-amber-800",
    text: "text-amber-700 dark:text-amber-400",
    icon: AlertTriangle
  },
  "High Risk": {
    bg: "bg-orange-50 dark:bg-orange-950/40 border-orange-200 dark:border-orange-800",
    text: "text-orange-700 dark:text-orange-400",
    icon: AlertOctagon
  },
  "Confirmed Malicious": {
    bg: "bg-red-50 dark:bg-red-950/40 border-red-200 dark:border-red-800",
    text: "text-red-700 dark:text-red-400",
    icon: XCircle
  },
  "Inconclusive": {
    bg: "bg-zinc-100 dark:bg-zinc-800 border-zinc-200 dark:border-zinc-700",
    text: "text-zinc-700 dark:text-zinc-300",
    icon: Info
  }
};

export default function ReportsHistory({ onSelectReport }: ReportsHistoryProps) {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedLabel, setSelectedLabel] = useState<string>("");
  const [committedFilter, setCommittedFilter] = useState<string>("all");
  const [inspectingId, setInspectingId] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const committedParam = committedFilter === "all" ? undefined : committedFilter === "committed";
      const labelParam = selectedLabel || undefined;
      const data = await fetchReportsList(labelParam, committedParam);
      setReports(Array.isArray(data) ? data : []);
    } catch (err: any) {
      setError(err?.message || "Failed to load scan records");
    } finally {
      setLoading(false);
    }
  }, [selectedLabel, committedFilter]);

  useEffect(() => {
    loadReports();
  }, [loadReports]);

  const handleInspect = async (reportId: string) => {
    if (!onSelectReport) return;
    setInspectingId(reportId);
    try {
      const full = await fetchReport(reportId);
      onSelectReport(full);
      const resultsEl = document.getElementById("results");
      if (resultsEl) {
        resultsEl.scrollIntoView({ behavior: "smooth" });
      }
    } catch (err: any) {
      alert("Failed to load full report: " + (err?.message || "Unknown error"));
    } finally {
      setInspectingId(null);
    }
  };

  const formatDate = (isoStr: string) => {
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit"
      });
    } catch {
      return isoStr;
    }
  };

  return (
    <section id="reports" className="scroll-mt-20">
      <div className="cyber-card bg-white dark:bg-[#121215] rounded-3xl border border-zinc-200 dark:border-zinc-800 p-6 sm:p-8 shadow-sm">
        {/* Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-zinc-200 dark:border-zinc-800">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-brand-50 dark:bg-brand-950/40 text-brand-600 dark:text-brand-400 border border-brand-200/40 dark:border-brand-800/40">
                <History className="w-5 h-5" />
              </div>
              <h2 className="text-2xl font-black text-zinc-900 dark:text-zinc-100">
                Scan Audit History
              </h2>
            </div>
            <p className="mt-1 text-sm text-zinc-500 dark:text-zinc-400">
              Tamper-evident log of inspected links, messages, and smart contract proofs.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => loadReports()}
              disabled={loading}
              className="inline-flex items-center gap-2 px-3.5 py-2 text-xs font-semibold text-zinc-700 dark:text-zinc-200 bg-zinc-100 hover:bg-zinc-200 dark:bg-[#18181c] dark:hover:bg-zinc-800 rounded-xl transition-all duration-200 hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50 border border-zinc-200/50 dark:border-zinc-700/50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-3 pt-6 pb-4">
          <div className="flex items-center gap-1.5 text-xs text-zinc-500 dark:text-zinc-400">
            <Filter className="w-3.5 h-3.5" />
            <span>Filter:</span>
          </div>

          <select
            value={selectedLabel}
            onChange={(e) => setSelectedLabel(e.target.value)}
            className="text-xs rounded-xl bg-zinc-50 dark:bg-[#18181c] border border-zinc-200 dark:border-zinc-700 px-3 py-1.5 text-zinc-800 dark:text-zinc-200 focus:outline-none focus:ring-2 focus:ring-brand-500 transition-all"
          >
            <option value="">All Risk Levels</option>
            <option value="Low Risk">Low Risk</option>
            <option value="Suspicious">Suspicious</option>
            <option value="High Risk">High Risk</option>
            <option value="Confirmed Malicious">Confirmed Malicious</option>
            <option value="Inconclusive">Inconclusive</option>
          </select>

          <select
            value={committedFilter}
            onChange={(e) => setCommittedFilter(e.target.value)}
            className="text-xs rounded-xl bg-zinc-50 dark:bg-[#18181c] border border-zinc-200 dark:border-zinc-700 px-3 py-1.5 text-zinc-800 dark:text-zinc-200 focus:outline-none focus:ring-2 focus:ring-brand-500 transition-all"
          >
            <option value="all">All Proof States</option>
            <option value="committed">On-Chain Verified</option>
            <option value="uncommitted">Local Storage Only</option>
          </select>

          <div className="ml-auto text-xs text-zinc-400">
            {reports.length} {reports.length === 1 ? "record" : "records"} found
          </div>
        </div>

        {/* Content State */}
        {loading && reports.length === 0 ? (
          <div className="py-16 text-center">
            <Loader2 className="w-8 h-8 text-brand-500 animate-spin mx-auto mb-3" />
            <p className="text-sm text-zinc-500 dark:text-zinc-400">Loading audit records from database...</p>
          </div>
        ) : error ? (
          <div className="py-12 text-center">
            <p className="text-sm text-red-500 dark:text-red-400 mb-2">{error}</p>
            <button
              onClick={() => loadReports()}
              className="text-xs font-semibold text-brand-600 dark:text-brand-400 hover:underline"
            >
              Try again
            </button>
          </div>
        ) : reports.length === 0 ? (
          <div className="py-16 text-center border border-dashed border-zinc-200 dark:border-zinc-800 rounded-2xl">
            <Shield className="w-10 h-10 text-zinc-300 dark:text-zinc-600 mx-auto mb-3" />
            <p className="text-sm font-semibold text-zinc-700 dark:text-zinc-300">No scan records found</p>
            <p className="text-xs text-zinc-400 mt-1 max-w-sm mx-auto">
              Run a scan using the scanner above to generate passive telemetry and cryptographic proof records.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-zinc-200 dark:border-zinc-800 text-xs font-semibold text-zinc-500 dark:text-zinc-400">
                  <th className="py-3 px-4">Target (Defanged)</th>
                  <th className="py-3 px-4">Risk Verdict</th>
                  <th className="py-3 px-4">Score</th>
                  <th className="py-3 px-4">Web3 Status</th>
                  <th className="py-3 px-4">Time</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800/60">
                {reports.map((r) => {
                  const badge = riskBadges[r.risk_label] || riskBadges["Inconclusive"];
                  const Icon = badge.icon;
                  const isCurrent = inspectingId === r.report_id;

                  return (
                    <tr
                      key={r.report_id}
                      className="hover:bg-zinc-50/70 dark:hover:bg-[#18181c]/70 transition-colors group"
                    >
                      {/* Target */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <span className="p-1 rounded-md bg-zinc-100 dark:bg-zinc-800 text-zinc-500 dark:text-zinc-400 flex-shrink-0">
                            {r.input_type === "url" ? (
                              <Link2 className="w-3.5 h-3.5" />
                            ) : (
                              <MessageSquare className="w-3.5 h-3.5" />
                            )}
                          </span>
                          <span
                            className="font-mono text-xs font-medium text-zinc-800 dark:text-zinc-200 truncate max-w-xs block"
                            title={r.input_display}
                          >
                            {defang(r.input_display || r.registrable_domain || "Unknown target")}
                          </span>
                        </div>
                      </td>

                      {/* Risk Verdict */}
                      <td className="py-3.5 px-4">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold border ${badge.bg} ${badge.text}`}
                        >
                          <Icon className="w-3.5 h-3.5" />
                          {r.risk_label}
                        </span>
                      </td>

                      {/* Score */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-xs font-semibold text-zinc-700 dark:text-zinc-300">
                            {r.risk_score}
                          </span>
                          <div className="w-12 h-1.5 rounded-full bg-zinc-100 dark:bg-zinc-800 overflow-hidden">
                            <div
                              className={`h-full transition-all duration-500 ${
                                r.risk_score >= 70
                                  ? "bg-red-500"
                                  : r.risk_score >= 40
                                  ? "bg-amber-500"
                                  : "bg-emerald-500"
                              }`}
                              style={{ width: `${Math.min(100, r.risk_score)}%` }}
                            />
                          </div>
                        </div>
                      </td>

                      {/* Web3 Status */}
                      <td className="py-3.5 px-4">
                        {r.is_committed ? (
                          <span className="inline-flex items-center gap-1 text-xs font-semibold text-brand-600 dark:text-brand-400">
                            <Database className="w-3 h-3" />
                            On-Chain
                          </span>
                        ) : (
                          <span className="text-xs text-zinc-400">
                            Local
                          </span>
                        )}
                      </td>

                      {/* Time */}
                      <td className="py-3.5 px-4 text-xs text-zinc-500 dark:text-zinc-400 whitespace-nowrap">
                        {formatDate(r.created_at)}
                      </td>

                      {/* Action */}
                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => handleInspect(r.report_id)}
                          disabled={isCurrent}
                          className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg text-xs font-semibold text-brand-600 hover:text-brand-700 dark:text-brand-400 dark:hover:text-brand-300 hover:bg-brand-50 dark:hover:bg-brand-950/40 transition-all hover:scale-[1.02] active:scale-[0.98] disabled:opacity-50"
                        >
                          {isCurrent ? (
                            <>
                              <Loader2 className="w-3 h-3 animate-spin" />
                              Loading...
                            </>
                          ) : (
                            <>
                              Inspect
                              <ChevronRight className="w-3 h-3" />
                            </>
                          )}
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}
