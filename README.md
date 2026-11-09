# Link & Scam Detective (TrustTrace)
**AI-Powered Web Threat Detection & Digital Trust Intelligence**  
*HackMatrix 2026 — Team APEX WARCODE (HM-6FC44F)*  
*Team Members: Somnath Pal (Leader), Sreya Roy, Sudhansu Kumar, Sukriti Singh*

---

## 1. Product Overview
Link & Scam Detective helps individuals and organizations identify phishing websites, fraudulent links, online scams, and compromised web trust infrastructures before they cause harm. The platform runs safe, passive cybersecurity checks, extracts structured indicators, uses an AI explainer grounded strictly in technical evidence, assigns one of five fixed risk labels, and enables users to commit a tamper-evident cryptographic fingerprint (SHA-256) of the report to an EVM blockchain for independent verification.

---

## 2. Architecture Overview
```
+-------------------------------------------------------------------------+
|                  Next.js Frontend Client (TypeScript)                  |
|  - Defanged UI (HC-16)             - 3+3 Demo Test Suites               |
|  - Real-time Scanning Stepper      - Web3 Verification & Tamper Suite   |
+------------------------------------+------------------------------------+
                                     | JSON REST API (/api)
+------------------------------------v------------------------------------+
|                  FastAPI Backend Server (Python 3.11+)                  |
|  +-------------------------+  +---------------------------------------+ |
|  | Multi-Layer SSRF Guard  |  | Passive Analyzers (URL, TLS, Headers) | |
|  +-------------------------+  +---------------------------------------+ |
|  | Threat Feeds & Datasets |  | Pure Deterministic Scoring Engine    | |
|  +-------------------------+  +---------------------------------------+ |
|  | Explainable AI & Guard  |  | Deterministic Campaign Correlator    | |
|  +-------------------------+  +---------------------------------------+ |
|  | Web3 Canonical Serializer & Blockchain Contract Client (Hardhat/EVM) |
+------------------+-----------------------+---------------------+--------+
                   |                       |                     |
     +-------------v-------------+   +-----v-----+   +-----------v--------+
     | Storage (SQLite/Postgres) |   | Threat DB |   | Solidity Contract  |
     | Scans, Indicators, Commits|   | URLhaus   |   | ThreatRegistry.sol |
     +---------------------------+   +-----------+   +--------------------+
```

---

## 3. Analysis Pipeline
1. **SSRF Guard & Validation**: Validates host, port (80, 443, 8080, 8443), resolves DNS, and blocks private/loopback/cloud-metadata addresses.
2. **Lexical & Structure Analysis**: Punycode/homoglyphs, brand keyword matching, suspicious TLDs, URL shorteners, redirect parameters.
3. **Passive Network & TLS Inspection**: Dual TLS handshake, X.509 cert chain analysis, distrusted CA list match (eMudhra incident check), security headers.
4. **Threat Intelligence**: URLhaus check + curated offline fallback dataset.
5. **Deterministic Scoring Engine**: Computes capped scores per category and assigns one of 5 strict labels: `Low Risk`, `Suspicious`, `High Risk`, `Confirmed Malicious`, `Inconclusive`.
6. **AI Explanation**: Grounded plain-English summary citing only specific finding IDs.
7. **Campaign Correlation**: Deterministically links to prior scans via shared SPKI cert hashes, message template hashes, or host IPs.
8. **Web3 Verification**: Canonical UTF-8 JSON serialization hashed with SHA-256 and committed on-chain.

---

## 4. Key Security & Privacy Guarantees
- **HC-01 & HC-02**: Exactly 5 risk labels; the word "safe" is never used as a verdict.
- **HC-07 & HC-08**: Strict Off-Chain Privacy — raw URLs, messages, and PII are never sent on-chain. The blockchain record establishes integrity and history, not truth.
- **HC-09 & HC-10**: Multi-layer SSRF protection and non-intrusive passive inspection only.
- **HC-11 & HC-13**: AI Prompt-Injection defenses and automated PII/credential redaction.
- **HC-12**: eMudhra guardrail — no claim of detecting CA internal key flaws from a URL.

---

## 5. Quickstart & Local Setup
See documentation in `/docs` for detailed local setup instructions, test runs, and testnet deployment records.
