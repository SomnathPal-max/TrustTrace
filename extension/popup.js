const BACKEND_BASE = "http://localhost:8000";

let currentUrl = "";

document.addEventListener("DOMContentLoaded", async () => {
  const targetEl = document.getElementById("targetUrl");
  const scanBtn = document.getElementById("scanBtn");
  const progressArea = document.getElementById("progressArea");
  const progressStep = document.getElementById("progressStep");
  const errorBox = document.getElementById("errorBox");
  const resultCard = document.getElementById("resultCard");

  // Query current active browser tab
  try {
    if (chrome && chrome.tabs) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.url) {
        currentUrl = tab.url;
        targetEl.textContent = currentUrl;
      } else {
        targetEl.textContent = "No active URL in this tab";
      }
    } else {
      currentUrl = "https://example.com";
      targetEl.textContent = currentUrl;
    }
  } catch (err) {
    targetEl.textContent = "Unable to read active tab";
  }

  scanBtn.addEventListener("click", async () => {
    if (!currentUrl || currentUrl.startsWith("chrome://") || currentUrl.startsWith("edge://")) {
      showError("Cannot analyze internal browser system pages.");
      return;
    }

    errorBox.classList.add("hidden");
    resultCard.classList.add("hidden");
    progressArea.classList.remove("hidden");
    scanBtn.disabled = true;

    try {
      // 1. Dispatch scan to local FastAPI backend
      const res = await fetch(`${BACKEND_BASE}/api/scans`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: "url", value: currentUrl, force_refresh: false })
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || "Failed to start inspection.");
      }

      const init = await res.json();
      const reportId = init.report_id;

      // 2. Poll until complete
      const poll = setInterval(async () => {
        try {
          const pRes = await fetch(`${BACKEND_BASE}/api/scans/${reportId}`);
          if (!pRes.ok) throw new Error("Connection lost.");

          const data = await pRes.json();
          if (data.status === "failed") {
            clearInterval(poll);
            progressArea.classList.add("hidden");
            scanBtn.disabled = false;
            showError(data.error || "Inspection encountered an error.");
          } else if (data.status === "complete" && data.report) {
            clearInterval(poll);
            progressArea.classList.add("hidden");
            scanBtn.disabled = false;
            renderResult(data.report);
          } else {
            progressStep.textContent = data.progress_step || "Analyzing 7-layer telemetry...";
          }
        } catch (e) {
          clearInterval(poll);
          progressArea.classList.add("hidden");
          scanBtn.disabled = false;
          showError("Lost connection to TrustTrace backend at " + BACKEND_BASE);
        }
      }, 700);

    } catch (err) {
      progressArea.classList.add("hidden");
      scanBtn.disabled = false;
      showError(err.message || "Could not connect to TrustTrace server.");
    }
  });

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove("hidden");
  }

  function renderResult(report) {
    resultCard.classList.remove("hidden");

    const riskLabelEl = document.getElementById("riskLabel");
    riskLabelEl.textContent = report.risk_label;
    riskLabelEl.className = "risk-label " + getRiskClass(report.risk_label);

    document.getElementById("riskScore").textContent = report.risk_score;
    document.getElementById("findingsCount").textContent = report.findings ? report.findings.length : 0;
    document.getElementById("coveragePercent").textContent = report.evidence_coverage ? `${report.evidence_coverage.percent}%` : "100%";
    document.getElementById("web3Status").textContent = report.web3?.status === "committed" ? "Verified" : "Local";

    const summary = report.ai_explanation ? report.ai_explanation.summary : "Analysis completed successfully.";
    document.getElementById("aiSummary").textContent = summary;
  }

  function getRiskClass(label) {
    switch (label) {
      case "Low Risk": return "risk-low";
      case "Suspicious": return "risk-suspicious";
      case "High Risk": return "risk-high";
      case "Confirmed Malicious": return "risk-malicious";
      default: return "risk-inconclusive";
    }
  }
});
