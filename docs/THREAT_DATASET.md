# Bundled Curated Demonstration Benchmark Reference

**Dataset File**: `backend/data/threat_dataset.json`  
**Compilation Date**: 2026-11-10  
**Version**: 1.1.0  

## Purpose & Scope
This dataset provides a curated local threat benchmark ensuring deterministic offline evaluation and resilience when live external threat feed APIs (such as abuse.ch URLhaus API) are unconfigured, rate-limited, or unavailable in isolated test environments.

## Dataset Structure & Attribution
All entries are curated demonstration benchmark indicators designed specifically to evaluate passive detection capabilities:
1. **Curated Demonstration Phishing Targets**:
   - High-risk credential harvesting indicators and brand impersonation domains (e.g. `sbi-kyc-update.com/login`).
   - Labeled transparently as `TrustTrace Curated Demonstration Benchmark`.
2. **Deterministic Campaign Cluster Fixtures**:
   - Seeded threat infrastructure indicators sharing campaign metadata (IPs, targeting tags, and lure patterns).

## Safety & Passive Lookups
All entries in this dataset represent demonstration threat indicators. They are evaluated exclusively through offline hash/lexical matching. **No outbound connection or script execution is ever initiated against listed demonstration domains.**
