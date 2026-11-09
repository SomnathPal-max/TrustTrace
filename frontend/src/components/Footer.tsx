"use client";
import React from "react";
import { Shield, Lock, Database, Cpu, ExternalLink, Terminal, Heart } from "lucide-react";

export default function Footer() {
  return (
    <footer className="mt-20 border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900/80 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-12">
          {/* Brand & Purpose */}
          <div className="md:col-span-2 space-y-4">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-gradient-to-tr from-brand-600 to-cyan-500 text-white shadow-md shadow-brand-500/20">
                <Shield className="w-5 h-5" />
              </div>
              <span className="text-xl font-black tracking-tight text-slate-900 dark:text-white">
                TrustTrace
              </span>
              <span className="text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded-md bg-brand-100 text-brand-700 dark:bg-brand-900/40 dark:text-brand-300">
                v1.0-Prod
              </span>
            </div>
            <p className="text-sm text-slate-600 dark:text-slate-400 max-w-md leading-relaxed">
              Enterprise-grade scam and malicious link detective. Combines 7-layer passive telemetry, AI threat correlation, and EVM smart contract immutability to expose phishing attacks before compromise.
            </p>
            <div className="flex flex-wrap items-center gap-2 pt-2">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                <Cpu className="w-3 h-3 text-brand-500" />
                AI Correlation
              </span>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                <Lock className="w-3 h-3 text-emerald-500" />
                Zero PII Off-Chain
              </span>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                <Database className="w-3 h-3 text-cyan-500" />
                Tamper-Evident Proofs
              </span>
            </div>
          </div>

          {/* Quick Links */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white mb-3">
              Platform Navigation
            </h3>
            <ul className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
              <li>
                <a href="#scanner" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                  Threat Scanner
                </a>
              </li>
              <li>
                <a href="#how-it-works" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                  How It Works
                </a>
              </li>
              <li>
                <a href="#features" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                  Security Architecture
                </a>
              </li>
              <li>
                <a href="#history" className="hover:text-brand-600 dark:hover:text-brand-400 transition-colors">
                  Audit History
                </a>
              </li>
            </ul>
          </div>

          {/* Developer & Hackathon Info */}
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white mb-3">
              HackMatrix 2026
            </h3>
            <div className="space-y-2 text-sm text-slate-600 dark:text-slate-400">
              <p className="font-semibold text-slate-900 dark:text-slate-200">
                Team APEX WARCODE
              </p>
              <p className="text-xs font-mono text-slate-500">
                Team Code: HM-6FC44F
              </p>
              <p className="text-xs leading-relaxed text-slate-500">
                Somnath Pal (Lead) · Sreya Roy · Sudhansu Kumar · Sukriti Singh
              </p>
              <div className="pt-2">
                <a
                  href="http://localhost:8000/docs"
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-brand-600 dark:text-brand-400 hover:underline"
                >
                  <Terminal className="w-3.5 h-3.5" />
                  FastAPI OpenAPI Docs
                  <ExternalLink className="w-3 h-3" />
                </a>
              </div>
            </div>
          </div>
        </div>

        {/* Mandatory Safety Notice (HC-02) */}
        <div className="pt-8 border-t border-slate-100 dark:border-slate-800/80">
          <div className="p-4 rounded-2xl bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-800 text-xs text-slate-600 dark:text-slate-400 leading-relaxed mb-6">
            <span className="font-bold text-slate-900 dark:text-slate-200 block mb-1">
              Safety & Verification Disclaimer:
            </span>
            No automated analysis tool can guarantee a website or message is completely safe. TrustTrace performs passive observation, multi-factor heuristic risk scoring, and cryptographic proof logging to provide actionable security intelligence. It does not replace comprehensive enterprise defense-in-depth or organizational risk assessments.
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500 gap-4">
            <p>
              © {new Date().getFullYear()} TrustTrace · HackMatrix 2026. All rights reserved.
            </p>
            <p className="flex items-center gap-1">
              Engineered with <Heart className="w-3 h-3 text-red-500 fill-red-500" /> by Team APEX WARCODE
            </p>
          </div>
        </div>
      </div>
    </footer>
  );
}
