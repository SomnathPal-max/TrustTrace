const API_BASE = process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000";

export async function fetchHealth() {
  const res = await fetch(`${API_BASE}/api/health`);
  if (!res.ok) throw new Error("Backend unavailable");
  return res.json();
}

export async function fetchSecurityControls() {
  const res = await fetch(`${API_BASE}/api/security-controls`);
  if (!res.ok) throw new Error("Failed to load security controls");
  return res.json();
}

export async function fetchSamples() {
  const res = await fetch(`${API_BASE}/api/samples`);
  if (!res.ok) throw new Error("Failed to load samples");
  return res.json();
}

export async function startScan(type: "url" | "message", value: string, use_cached: boolean = false) {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type, value, use_cached })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Failed to start scan");
  }
  return res.json();
}

export async function pollScan(reportId: string) {
  const res = await fetch(`${API_BASE}/api/scans/${reportId}`);
  if (!res.ok) throw new Error("Failed to poll scan status");
  return res.json();
}

export async function fetchReport(reportId: string) {
  const res = await fetch(`${API_BASE}/api/reports/${reportId}`);
  if (!res.ok) throw new Error("Failed to fetch report");
  return res.json();
}

export async function fetchReportsList(label?: string, committed?: boolean) {
  const params = new URLSearchParams();
  if (label) params.append("label", label);
  if (committed !== undefined) params.append("committed", String(committed));
  const res = await fetch(`${API_BASE}/api/reports?${params.toString()}`);
  if (!res.ok) throw new Error("Failed to load reports");
  return res.json();
}

export async function commitReport(reportId: string) {
  const res = await fetch(`${API_BASE}/api/reports/${reportId}/commit`, {
    method: "POST"
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Failed to commit report on-chain");
  }
  return res.json();
}

export async function verifyReport(reportId: string) {
  const res = await fetch(`${API_BASE}/api/reports/${reportId}/verify`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "Failed to verify integrity");
  }
  return res.json();
}

export async function tamperReport(reportId: string) {
  const res = await fetch(`${API_BASE}/api/demo/tamper/${reportId}`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to simulate tamper");
  return res.json();
}

export async function restoreReport(reportId: string) {
  const res = await fetch(`${API_BASE}/api/demo/restore/${reportId}`, {
    method: "POST"
  });
  if (!res.ok) throw new Error("Failed to restore report");
  return res.json();
}


export async function fetchPlatformStats() {
  const res = await fetch(`${API_BASE}/api/stats`);
  if (!res.ok) throw new Error("Failed to load platform stats");
  return res.json();
}
