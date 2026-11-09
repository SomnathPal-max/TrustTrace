"use client";
import React, { useState, useEffect } from "react";
import { Sparkles, X, CheckCircle, AlertTriangle, Key, Cpu, RefreshCw, Eye, EyeOff } from "lucide-react";
import { fetchAISettings, updateAISettings, testAISettings } from "@/lib/api";

interface AISettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export default function AISettingsModal({ isOpen, onClose }: AISettingsModalProps) {
  const [apiKey, setApiKey] = useState("");
  const [keyPreview, setKeyPreview] = useState("");
  const [model, setModel] = useState("gemini-flash-latest");
  const [modelsList, setModelsList] = useState<string[]>([]);
  const [showKey, setShowKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ status: string; message: string } | null>(null);
  const [isConfigured, setIsConfigured] = useState(false);

  useEffect(() => {
    if (isOpen) {
      fetchAISettings()
        .then((data) => {
          setIsConfigured(data.api_key_configured);
          setKeyPreview(data.key_preview || "");
          setModel(data.model || "gemini-flash-latest");
          setModelsList(data.available_models || ["gemini-flash-latest", "gemini-3.8-flash", "gemini-2.5-pro"]);
          setTestResult(null);
        })
        .catch(() => {});
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await updateAISettings(apiKey || undefined, model);
      setIsConfigured(res.api_key_configured);
      setKeyPreview(res.key_preview);
      setApiKey("");
      setTestResult({ status: "success", message: "AI configuration saved successfully." });
    } catch (err: any) {
      setTestResult({ status: "error", message: err.message || "Failed to save AI configuration." });
    } finally {
      setSaving(false);
    }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const res = await testAISettings();
      setTestResult(res);
    } catch (err: any) {
      setTestResult({ status: "error", message: err.message || "API test connection failed." });
    } finally {
      setTesting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-fade-in">
      <div className="cyber-card relative w-full max-w-lg bg-white dark:bg-[#121215] border border-zinc-200 dark:border-zinc-800 rounded-3xl p-6 sm:p-8 shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between pb-4 border-b border-zinc-100 dark:border-zinc-800">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-xl bg-purple-50 dark:bg-purple-950/40 text-purple-600 dark:text-purple-400 border border-purple-200/50 dark:border-purple-800/50">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-lg font-black text-zinc-900 dark:text-zinc-100">
                Gemini AI Engine Settings
              </h3>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                Configure Google Gemini API key & neural explanation model
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-200 rounded-lg transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Status Indicator */}
        <div className="mt-5 p-3.5 rounded-2xl bg-zinc-50 dark:bg-[#18181c] border border-zinc-200/80 dark:border-zinc-800 flex items-center justify-between text-xs">
          <div className="flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${isConfigured ? "bg-emerald-500 animate-pulse" : "bg-amber-500"}`} />
            <span className="font-semibold text-zinc-700 dark:text-zinc-300">
              Status: {isConfigured ? "Live Gemini AI Active" : "Deterministic Fallback Active"}
            </span>
          </div>
          <span className="font-mono text-zinc-500 text-[11px]">
            Key: {keyPreview || "None"}
          </span>
        </div>

        {/* Settings Form */}
        <div className="mt-5 space-y-4">
          <div>
            <label className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300 block mb-1.5">
              Google Gemini Model
            </label>
            <div className="relative">
              <select
                value={model}
                onChange={(e) => setModel(e.target.value)}
                className="w-full px-3.5 py-2.5 text-xs rounded-xl bg-zinc-50 dark:bg-[#18181c] border border-zinc-200 dark:border-zinc-700 text-zinc-800 dark:text-zinc-200 focus:outline-none focus:ring-2 focus:ring-brand-500 font-mono"
              >
                {modelsList.map((m) => (
                  <option key={m} value={m}>
                    {m} {m === "gemini-flash-latest" ? "(Recommended)" : ""}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label className="text-xs font-bold uppercase tracking-wider text-zinc-700 dark:text-zinc-300 block mb-1.5">
              Gemini API Key
            </label>
            <div className="relative flex items-center">
              <input
                type={showKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={isConfigured ? "Key is set. Enter new key to change..." : "Paste Gemini API Key..."}
                className="w-full pl-3.5 pr-10 py-2.5 text-xs rounded-xl bg-zinc-50 dark:bg-[#18181c] border border-zinc-200 dark:border-zinc-700 text-zinc-800 dark:text-zinc-200 focus:outline-none focus:ring-2 focus:ring-brand-500 font-mono"
              />
              <button
                type="button"
                onClick={() => setShowKey(!showKey)}
                className="absolute right-3 text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300"
              >
                {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            <p className="mt-1 text-[11px] text-zinc-400">
              Boundary marker defense (HC-05) prevents prompt injection when evaluating untrusted link content.
            </p>
          </div>
        </div>

        {/* Feedback Alert */}
        {testResult && (
          <div className={`mt-4 p-3 rounded-xl border text-xs flex items-start gap-2 animate-fade-in ${
            testResult.status === "success"
              ? "bg-emerald-50 dark:bg-emerald-950/30 border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300"
              : "bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-800 text-red-800 dark:text-red-300"
          }`}>
            {testResult.status === "success" ? (
              <CheckCircle className="w-4 h-4 shrink-0 text-emerald-500 mt-0.5" />
            ) : (
              <AlertTriangle className="w-4 h-4 shrink-0 text-red-500 mt-0.5" />
            )}
            <span>{testResult.message}</span>
          </div>
        )}

        {/* Actions */}
        <div className="mt-6 flex flex-wrap items-center justify-between gap-3 pt-4 border-t border-zinc-100 dark:border-zinc-800">
          <button
            onClick={handleTest}
            disabled={testing || !isConfigured}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold text-zinc-700 dark:text-zinc-300 bg-zinc-100 dark:bg-[#18181c] hover:bg-zinc-200 dark:hover:bg-zinc-800 rounded-xl transition disabled:opacity-50 border border-zinc-200 dark:border-zinc-700"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${testing ? "animate-spin" : ""}`} />
            Test Connection
          </button>

          <div className="flex gap-2">
            <button
              onClick={onClose}
              className="px-4 py-2 text-xs font-semibold text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-white rounded-xl transition"
            >
              Close
            </button>
            <button
              onClick={handleSave}
              disabled={saving}
              className="px-5 py-2 text-xs font-bold text-white bg-brand-600 hover:bg-brand-700 rounded-xl shadow-md shadow-brand-500/20 transition disabled:opacity-50"
            >
              {saving ? "Saving..." : "Save Settings"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
