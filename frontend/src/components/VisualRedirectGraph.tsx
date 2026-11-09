"use client";
import React, { useState } from "react";
import { ArrowRight, Globe, Lock, ShieldAlert, Server, ExternalLink } from "lucide-react";
import { Report } from "@/types";
import { defang } from "@/lib/defang";

interface VisualRedirectGraphProps {
  report: Report;
}

export default function VisualRedirectGraph({ report }: VisualRedirectGraphProps) {
  const [selectedHop, setSelectedHop] = useState<number | null>(null);

  const chain = report.redirect_chain || [];
  const startUrl = report.input_display || report.registrable_domain || "origin";
  const hops = [
    {
      index: 0,
      url: startUrl,
      status: "Start",
      same_site: true,
      domain: report.registrable_domain || "Origin Host"
    },
    ...chain.map((h, i) => {
      let domain = "Destination Host";
      try {
        const u = new URL(h.url);
        domain = u.hostname;
      } catch {}
      return {
        index: i + 1,
        url: h.url,
        status: `${h.status_code}`,
        same_site: h.same_site,
        domain
      };
    })
  ];

  return (
    <div className="cyber-card p-5 sm:p-6 bg-white dark:bg-[#121215] rounded-2xl border border-zinc-200 dark:border-zinc-800 shadow-sm space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-brand-600 dark:text-brand-400" />
          <h4 className="text-sm font-bold text-zinc-900 dark:text-zinc-100">
            Visual Redirect & Network Topology Graph
          </h4>
        </div>
        <span className="text-[11px] font-mono text-zinc-500">
          {hops.length} Total Nodes
        </span>
      </div>

      {/* Interactive Node Graph */}
      <div className="overflow-x-auto py-4">
        <div className="flex items-center min-w-max gap-3 px-2">
          {hops.map((hop, idx) => {
            const isLast = idx === hops.length - 1;
            const isSelected = selectedHop === idx;

            return (
              <React.Fragment key={idx}>
                {/* Node Box */}
                <div
                  onClick={() => setSelectedHop(idx)}
                  className={`cyber-card cursor-pointer p-3.5 rounded-2xl border transition-all duration-300 w-52 shrink-0 ${
                    isSelected
                      ? "ring-2 ring-brand-500 border-brand-500 bg-brand-50/30 dark:bg-brand-950/30"
                      : isLast
                      ? "bg-zinc-50 dark:bg-[#18181c] border-emerald-300 dark:border-emerald-800/80"
                      : !hop.same_site
                      ? "bg-orange-50/50 dark:bg-orange-950/20 border-orange-300 dark:border-orange-800/80"
                      : "bg-zinc-50 dark:bg-[#18181c] border-zinc-200 dark:border-zinc-800"
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-[10px] font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded bg-zinc-200 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
                      {idx === 0 ? "Entrypoint" : isLast ? "Destination" : `Hop ${idx}`}
                    </span>
                    <span
                      className={`text-[11px] font-bold font-mono px-1.5 py-0.2 rounded ${
                        hop.status === "Start"
                          ? "text-zinc-500"
                          : hop.same_site
                          ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/50 dark:text-emerald-400"
                          : "bg-orange-100 text-orange-800 dark:bg-orange-950/50 dark:text-orange-400"
                      }`}
                    >
                      {hop.status}
                    </span>
                  </div>

                  <div className="text-xs font-semibold text-zinc-900 dark:text-zinc-100 truncate mb-1">
                    {hop.domain}
                  </div>

                  <div
                    className="text-[11px] font-mono text-zinc-500 dark:text-zinc-400 truncate"
                    title={hop.url}
                  >
                    {defang(hop.url)}
                  </div>

                  {!hop.same_site && (
                    <div className="mt-2 flex items-center gap-1 text-[10px] text-orange-600 dark:text-orange-400 font-bold">
                      <ShieldAlert className="w-3 h-3" />
                      Domain Shift Warning
                    </div>
                  )}
                </div>

                {/* Animated Directional Arrow */}
                {!isLast && (
                  <div className="flex items-center text-zinc-300 dark:text-zinc-600 shrink-0">
                    <div className="w-4 h-0.5 bg-zinc-300 dark:bg-zinc-700" />
                    <ArrowRight className="w-4 h-4 -ml-1 text-brand-500 animate-pulse" />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Selected Node Details Drawer */}
      {selectedHop !== null && (
        <div className="p-3.5 rounded-xl bg-zinc-50 dark:bg-[#18181c] border border-zinc-200 dark:border-zinc-800 text-xs animate-fade-in space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="font-bold text-zinc-800 dark:text-zinc-200">
              Inspecting Node #{selectedHop}: {hops[selectedHop].domain}
            </span>
            <button
              onClick={() => setSelectedHop(null)}
              className="text-[11px] text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200"
            >
              Dismiss
            </button>
          </div>
          <p className="font-mono text-[11px] text-zinc-600 dark:text-zinc-400 break-all">
            Full Defanged URL: {defang(hops[selectedHop].url)}
          </p>
          <div className="flex gap-4 pt-1 text-[11px] text-zinc-500">
            <span>Protocol: {hops[selectedHop].url.startsWith("https") ? "HTTPS (Encrypted)" : "HTTP (Cleartext)"}</span>
            <span>Same Origin: {hops[selectedHop].same_site ? "Yes (Safe context)" : "No (Cross-Domain Redirect)"}</span>
          </div>
        </div>
      )}
    </div>
  );
}
