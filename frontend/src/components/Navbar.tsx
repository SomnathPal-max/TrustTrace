"use client";
import React, { useState } from "react";
import { Shield, Menu, X, Sun, Moon, Search, FileText, Lock, Layers, Sparkles } from "lucide-react";
import { useTheme } from "@/components/ThemeProvider";
import AISettingsModal from "@/components/AISettingsModal";

const NAV_LINKS = [
  { label: "Scan", href: "#scanner", icon: Search },
  { label: "How It Works", href: "#how-it-works", icon: Layers },
  { label: "Security", href: "#security", icon: Lock },
  { label: "Reports", href: "#reports", icon: FileText },
];

export default function Navbar() {
  const { resolvedTheme, toggleTheme } = useTheme();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [aiModalOpen, setAiModalOpen] = useState(false);

  return (
    <>
      <nav className="sticky top-0 z-50 border-b border-zinc-200/80 dark:border-zinc-800/80 bg-white/80 dark:bg-[#0d0d10]/90 backdrop-blur-xl transition-colors">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <a href="#" className="flex items-center gap-2.5 shrink-0 group">
              <div className="p-2 bg-gradient-to-tr from-brand-600 to-emerald-400 rounded-xl text-white shadow-md shadow-brand-500/20 group-hover:scale-105 transition-transform">
                <Shield className="w-5 h-5" />
              </div>
              <div className="hidden sm:block">
                <div className="flex items-center gap-2">
                  <span className="text-lg font-black tracking-tight text-zinc-900 dark:text-zinc-100">
                    TrustTrace
                  </span>
                  <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-brand-50 text-brand-700 dark:bg-brand-950/60 dark:text-brand-300 border border-brand-200/50 dark:border-brand-800/50">
                    SOC v1.0
                  </span>
                </div>
                <span className="hidden lg:inline text-xs text-zinc-400 dark:text-zinc-400 font-medium">
                  Link & Scam Detective
                </span>
              </div>
            </a>

            {/* Desktop nav */}
            <div className="hidden md:flex items-center gap-1">
              {NAV_LINKS.map(link => (
                <a
                  key={link.href}
                  href={link.href}
                  className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-zinc-600 dark:text-zinc-300 hover:text-brand-600 dark:hover:text-brand-400 rounded-lg hover:bg-zinc-100 dark:hover:bg-zinc-800/60 transition-all hover:-translate-y-0.5"
                >
                  <link.icon className="w-4 h-4" />
                  {link.label}
                </a>
              ))}
            </div>

            {/* Right actions */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => setAiModalOpen(true)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold text-purple-700 dark:text-purple-300 bg-purple-50 dark:bg-purple-950/40 hover:bg-purple-100 dark:hover:bg-purple-900/60 border border-purple-200 dark:border-purple-800/50 transition-all hover:scale-105"
                title="Configure Gemini AI"
              >
                <Sparkles className="w-3.5 h-3.5 text-purple-600 dark:text-purple-400" />
                <span className="hidden sm:inline">AI Engine</span>
              </button>

              <button
                onClick={toggleTheme}
                className="p-2.5 rounded-xl text-zinc-500 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 hover:text-zinc-900 dark:hover:text-zinc-100 transition-all hover:scale-105"
                aria-label="Toggle theme"
              >
                {resolvedTheme === "dark" ? <Sun className="w-4 h-4 text-amber-400" /> : <Moon className="w-4 h-4" />}
              </button>

              <button
                onClick={() => setMobileOpen(!mobileOpen)}
                className="md:hidden p-2 rounded-lg text-zinc-500 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors"
                aria-label="Toggle menu"
              >
                {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
              </button>
            </div>
          </div>
        </div>

        {/* Mobile menu */}
        {mobileOpen && (
          <div className="md:hidden border-t border-zinc-200 dark:border-zinc-800 bg-white dark:bg-[#111114] animate-fade-in">
            <div className="px-4 py-3 space-y-1">
              {NAV_LINKS.map(link => (
                <a
                  key={link.href}
                  href={link.href}
                  onClick={() => setMobileOpen(false)}
                  className="flex items-center gap-2 px-3 py-2.5 text-sm font-medium text-zinc-700 dark:text-zinc-200 hover:bg-zinc-100 dark:hover:bg-zinc-800 rounded-lg transition-colors"
                >
                  <link.icon className="w-4 h-4" />
                  {link.label}
                </a>
              ))}
            </div>
          </div>
        )}
      </nav>

      {/* AI Settings Modal (Option 1) */}
      <AISettingsModal isOpen={aiModalOpen} onClose={() => setAiModalOpen(false)} />
    </>
  );
}
