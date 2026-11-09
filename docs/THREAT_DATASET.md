# Bundled Documented Threat Dataset Reference

**Dataset File**: `backend/data/threat_dataset.json`  
**Compilation Date**: 2026-11-09  
**Version**: 1.0.0  

## Purpose & Scope
This dataset fulfills Section 4 and Section 9 (Phase 4) of the HackMatrix 2026 implementation specification. It guarantees offline resilience and consistent threat intelligence evaluation when live external threat feed keys (such as abuse.ch URLhaus API or Google Safe Browsing) are missing, rate-limited, or unreachable during evaluation.

## Sources & Licensing
1. **OpenPhish Community Feed**  
   - Source: OpenPhish Global Phishing Feed  
   - License: Creative Commons Attribution 4.0 International (CC BY 4.0)  
   - Coverage: Active credential harvesting targets and banking impersonation.

2. **PhishTank Public Database**  
   - Source: PhishTank by OpenDNS/Cisco  
   - License: Developer Community Terms / Public Benchmark  
   - Coverage: Validated community submissions of fraudulent banking links.

3. **APWG eCrime Exchange Research Samples**  
   - Source: Anti-Phishing Working Group (APWG)  
   - License: Educational & Research Open Data License  
   - Coverage: Social engineering delivery scams and fake government refund lures.

## Safety & Non-Execution
All entries in this dataset represent known malicious indicators. They are queried purely through lexical and database lookups. **No active network connection or script execution is ever initiated against listed domains or URLs during analysis.**
