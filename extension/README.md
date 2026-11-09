# TrustTrace — Browser Extension (Manifest v3)

Lightweight browser extension allowing security analysts to inspect active tab links against the TrustTrace 7-layer passive telemetry pipeline with a single click.

## How to Install in Chrome / Edge / Brave

1. Open your browser and navigate to:
   * Chrome: `chrome://extensions/`
   * Edge: `edge://extensions/`
   * Brave: `brave://extensions/`
2. Enable **Developer mode** (toggle switch in the top-right corner).
3. Click the **Load unpacked** button in the top-left.
4. Select the `D:\TrustTrace\extension` folder.
5. The **TrustTrace Detective** icon will appear in your browser extensions toolbar!

## How It Works

1. Navigate to any website or suspicious link in your browser.
2. Click the TrustTrace extension icon in the toolbar.
3. Click **Scan Current Tab**.
4. The extension queries your local TrustTrace API (`http://localhost:8000`), performs SSRF checking, DNS/RDAP evaluation, TLS auditing, and threat feed correlation, returning:
   * Risk Label (Low Risk, Suspicious, High Risk, Confirmed Malicious, Inconclusive)
   * Risk Score (0–100)
   * AI Threat Explanation
   * One-click deep-link to the full cryptographic report on your local dashboard.
