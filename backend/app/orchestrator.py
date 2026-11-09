import time
import json
import uuid
import os
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from backend.app.core.job_runner import job_runner, SCAN_STEPS
from backend.app.core.ssrf import ssrf_guard
from backend.app.core.safe_client import safe_client, defang_url
from backend.app.analyzers.url_analyzer import url_analyzer
from backend.app.analyzers.domain_analyzer import domain_analyzer
from backend.app.analyzers.tls_analyzer import tls_analyzer
from backend.app.analyzers.header_analyzer import header_analyzer
from backend.app.analyzers.threat_intel import threat_intel_client
from backend.app.analyzers.message_analyzer import message_analyzer
from backend.app.scoring.engine import scoring_engine
from backend.app.llm.explainer import ai_explainer
from backend.app.correlation.engine import campaign_correlator
from backend.app.db.models import ScanRecord, IndicatorRecord
from backend.app.models import (
    ScanRequest, Report, RiskLabel, EvidenceCoverage, Finding, CheckRecord,
    ThreatIntelSummary, CampaignInfo
)

def run_scan_pipeline(report_id: str, request: ScanRequest, db: Session):
    t0 = time.time()
    try:
        # Check cached sample mode for demo reliability (Section 7.1 & Section 9 Phase 10)
        if request.use_cached:
            fixtures_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "fixtures", "cached_samples.json"))
            if os.path.exists(fixtures_path):
                with open(fixtures_path, "r", encoding="utf-8") as f:
                    cached_fixtures = json.load(f)
                
                matched_key = None
                req_val = request.value.strip().lower()
                if "sbi.co.in" in req_val:
                    matched_key = "B1"
                elif "github.com" in req_val:
                    matched_key = "B2"
                elif "wikipedia.org" in req_val:
                    matched_key = "B3"
                elif "sbi-kyc-update.com" in req_val and request.type == "url":
                    matched_key = "S1"
                elif "xn--gogl" in req_val:
                    matched_key = "S2"
                elif request.type == "message" or "blocked within 2 hours" in req_val:
                    matched_key = "S3"
                elif "simulated-distrusted-ca" in req_val:
                    matched_key = "SIM"

                if matched_key and matched_key in cached_fixtures:
                    cached_data = cached_fixtures[matched_key]
                    cached_data["report_id"] = report_id
                    cached_data["created_at"] = datetime.now(timezone.utc).isoformat()
                    cached_data["is_cached_sample"] = True
                    
                    rep_obj = Report.model_validate(cached_data)
                    record = ScanRecord(
                        report_id=report_id,
                        created_at=rep_obj.created_at,
                        input_type=rep_obj.input_type,
                        risk_label=rep_obj.risk_label.value,
                        risk_score=rep_obj.risk_score,
                        full_report_json=json.dumps(rep_obj.model_dump(), sort_keys=True),
                        is_committed=False,
                        is_demo_seed=False
                    )
                    db.add(record)
                    db.commit()
                    job_runner.mark_complete(report_id, rep_obj.model_dump())
                    return

        completed_groups = []
        unavailable_groups = []
        all_findings = []
        all_checks = []

        # HANDLE MESSAGE SCANS
        if request.type == "message":
            job_runner.update_step(report_id, "Analysing message content")
            t_msg0 = time.time()
            msg_res = message_analyzer.analyze(request.value)
            all_findings.extend(msg_res["findings"])
            all_checks.append(CheckRecord(
                check_id="CHK-MESSAGE-RULES",
                status="flagged" if msg_res["findings"] else "passed",
                duration_ms=int((time.time() - t_msg0) * 1000),
                short_note=f"Analyzed message rules; triggered {len(msg_res['message_analysis'].signals_triggered)} signals."
            ))

            completed_groups.append("Lexical analysis")

            # Calculate score and label for message
            msg_label = msg_res["label"]
            msg_score = msg_res["score"]

            coverage = EvidenceCoverage(
                percent=80 if msg_res["technical_corroboration"] else 60,
                completed_groups=["Message analysis", "Lexical analysis"],
                unavailable_groups=[]
            )

            job_runner.update_step(report_id, "Correlating with earlier reports")
            # Extract indicators
            temp_rep = Report(
                report_id=report_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                input_type="message",
                input_display=msg_res["redacted_text"],
                risk_label=msg_label,
                risk_score=msg_score,
                evidence_coverage=coverage,
                message_analysis=msg_res["message_analysis"],
                ai_explanation=ai_explainer._generate_template_explanation(msg_label, all_findings, coverage),
                analysis_duration_ms=int((time.time() - t0) * 1000)
            )
            current_indicators = campaign_correlator.extract_indicators_from_report(temp_rep)
            campaign = campaign_correlator.correlate(current_indicators, db)

            job_runner.update_step(report_id, "Writing explanation")
            explanation = ai_explainer.generate_explanation(
                risk_label=msg_label,
                findings=all_findings,
                coverage=coverage,
                input_type="message",
                redacted_input=msg_res["redacted_text"]
            )

            report = scoring_engine.assemble_report(
                report_id=report_id,
                input_type="message",
                input_display=msg_res["redacted_text"],
                normalized_url="",
                registrable_domain="",
                final_url="",
                final_domain="",
                resolved_ips=[],
                findings=all_findings,
                checks=all_checks,
                coverage=coverage,
                risk_label=msg_label,
                risk_score=msg_score,
                redirect_chain=[],
                tls=None,
                security_headers=[],
                threat_intel=ThreatIntelSummary(),
                campaign=campaign,
                message_analysis=msg_res["message_analysis"],
                ai_explanation=explanation,
                duration_ms=int((time.time() - t0) * 1000),
                is_cached_sample=bool(request.use_cached)
            )

        # HANDLE URL SCANS
        else:
            raw_url = request.value.strip()

            # Step 1: Validating link safety (SSRF Guard)
            job_runner.update_step(report_id, SCAN_STEPS[0])
            t_chk0 = time.time()
            validation = ssrf_guard.validate_url(raw_url)
            if not validation.is_safe:
                # SSRF block: reject per HC-09
                error_msg = f"This address cannot be analysed because it points to a private or internal network. The SSRF guard blocked it for safety. ({validation.rule_blocked})"
                job_runner.mark_failed(report_id, error_msg)
                return

            all_checks.append(CheckRecord(
                check_id="CHK-SSRF-GUARD",
                status="passed",
                duration_ms=int((time.time() - t_chk0) * 1000),
                short_note="SSRF validation passed. Publicly routable destination."
            ))

            # Step 2: Analysing domain & lexical structure
            job_runner.update_step(report_id, SCAN_STEPS[1])
            t_lex = time.time()
            lex_res = url_analyzer.analyze(raw_url)
            all_findings.extend(lex_res["findings"])
            norm = lex_res["normalization"]
            completed_groups.append("Lexical analysis")
            all_checks.append(CheckRecord(
                check_id="CHK-LEXICAL",
                status="flagged" if lex_res["findings"] else "passed",
                duration_ms=int((time.time() - t_lex) * 1000),
                short_note=f"Lexical analysis complete. {len(lex_res['findings'])} finding(s)."
            ))

            # Domain & DNS
            t_dom = time.time()
            dom_res = domain_analyzer.analyze(
                norm["host"],
                norm["registrable_domain"],
                lex_res["is_official_match"]
            )
            all_findings.extend(dom_res["findings"])
            resolved_ips = dom_res["resolved_ips"]

            if dom_res["dns_available"]:
                completed_groups.append("Domain and DNS")
                all_checks.append(CheckRecord(
                    check_id="CHK-DNS-RDAP",
                    status="passed",
                    duration_ms=int((time.time() - t_dom) * 1000),
                    short_note=f"Resolved {len(resolved_ips)} IP(s). Age: {dom_res.get('domain_age_days')} days."
                ))
            else:
                unavailable_groups.append("Domain and DNS")
                all_checks.append(CheckRecord(
                    check_id="CHK-DNS-RDAP",
                    status="unavailable",
                    duration_ms=int((time.time() - t_dom) * 1000),
                    short_note="DNS resolution failed."
                ))

            # Step 3: Following redirects (Safe HTTP Client)
            job_runner.update_step(report_id, SCAN_STEPS[2])
            redirect_chain = []
            final_headers = {}
            final_url = norm["normalized_url"]
            final_domain = norm["registrable_domain"]

            is_simulation = (norm["host"] == "simulated-distrusted-ca.local")

            if dom_res["dns_available"] and not is_simulation:
                t_fetch = time.time()
                http_res = safe_client.get(norm["normalized_url"])
                redirect_chain = http_res.redirect_chain
                final_headers = http_res.headers
                final_url = http_res.url
                final_norm = url_analyzer.normalize_url(final_url)
                final_domain = final_norm["registrable_domain"]

                if http_res.error:
                    unavailable_groups.append("Redirect and fetch")
                    all_checks.append(CheckRecord(
                        check_id="CHK-REDIRECT-FETCH",
                        status="unavailable",
                        duration_ms=http_res.duration_ms,
                        short_note=f"Fetch failed: {http_res.error}"
                    ))
                else:
                    completed_groups.append("Redirect and fetch")
                    all_checks.append(CheckRecord(
                        check_id="CHK-REDIRECT-FETCH",
                        status="passed",
                        duration_ms=http_res.duration_ms,
                        short_note=f"Fetched final destination with {len(redirect_chain)} hop(s)."
                    ))
            else:
                unavailable_groups.append("Redirect and fetch")

            # Step 4: Inspecting certificate & Security headers
            job_runner.update_step(report_id, SCAN_STEPS[3])
            t_tls = time.time()
            tls_res = tls_analyzer.analyze(
                norm["host"],
                resolved_ips[0] if resolved_ips else None,
                is_simulation=is_simulation
            )
            all_findings.extend(tls_res["findings"])
            tls_report = tls_res.get("tls_report")

            if tls_res["tls_available"]:
                completed_groups.append("TLS")
                all_checks.append(CheckRecord(
                    check_id="CHK-TLS",
                    status="flagged" if tls_res["findings"] else "passed",
                    duration_ms=int((time.time() - t_tls) * 1000),
                    short_note=f"TLS verdict: {tls_report.tls_verdict if tls_report else 'Unavailable'}."
                ))
            else:
                unavailable_groups.append("TLS")
                all_checks.append(CheckRecord(
                    check_id="CHK-TLS",
                    status="unavailable",
                    duration_ms=int((time.time() - t_tls) * 1000),
                    short_note="TLS handshake unavailable or port 443 closed."
                ))

            if tls_res["ct_available"]:
                completed_groups.append("Certificate Transparency")
            else:
                unavailable_groups.append("Certificate Transparency")

            # Header Inspection
            header_results = []
            if final_headers:
                t_hdr = time.time()
                header_results, hdr_findings = header_analyzer.analyze_headers(final_headers)
                all_findings.extend(hdr_findings)
                completed_groups.append("Security headers")
                all_checks.append(CheckRecord(
                    check_id="CHK-HEADERS",
                    status="passed",
                    duration_ms=int((time.time() - t_hdr) * 1000),
                    short_note=f"Security headers inspected; {len(hdr_findings)} finding(s)."
                ))
            else:
                unavailable_groups.append("Security headers")

            # Step 5: Checking threat intelligence
            job_runner.update_step(report_id, SCAN_STEPS[4])
            t_intel = time.time()
            intel_res = threat_intel_client.analyze(
                norm["normalized_url"],
                norm["host"],
                norm["registrable_domain"]
            )
            all_findings.extend(intel_res["findings"])
            threat_intel_summary = intel_res["summary"]

            if threat_intel_summary.feeds_answered:
                completed_groups.append("Threat intelligence")
                all_checks.append(CheckRecord(
                    check_id="CHK-THREAT-INTEL",
                    status="flagged" if intel_res["findings"] else "passed",
                    duration_ms=int((time.time() - t_intel) * 1000),
                    short_note=f"Threat intel completed with {len(intel_res['findings'])} match(es)."
                ))
            else:
                unavailable_groups.append("Threat intelligence")

            # Calculate Coverage & Label
            coverage = scoring_engine.calculate_coverage(completed_groups, unavailable_groups)
            score, label, _ = scoring_engine.calculate_score_and_label(
                findings=all_findings,
                coverage=coverage,
                is_official_brand=lex_res["is_official_match"],
                domain_age_days=dom_res.get("domain_age_days"),
                is_host_unreachable=not dom_res["dns_available"]
            )

            # Step 6: Correlating with earlier reports
            job_runner.update_step(report_id, SCAN_STEPS[5])
            temp_rep = Report(
                report_id=report_id,
                created_at=datetime.now(timezone.utc).isoformat(),
                input_type="url",
                input_display=norm["normalized_url"],
                final_domain=final_domain,
                registrable_domain=norm["registrable_domain"],
                resolved_ips=resolved_ips,
                redirect_chain=redirect_chain,
                tls=tls_report,
                risk_label=label,
                risk_score=score,
                evidence_coverage=coverage,
                ai_explanation=ai_explainer._generate_template_explanation(label, all_findings, coverage),
                analysis_duration_ms=int((time.time() - t0) * 1000)
            )
            current_indicators = campaign_correlator.extract_indicators_from_report(temp_rep)
            campaign = campaign_correlator.correlate(current_indicators, db)

            # Step 7: Writing explanation
            job_runner.update_step(report_id, SCAN_STEPS[6])
            explanation = ai_explainer.generate_explanation(
                risk_label=label,
                findings=all_findings,
                coverage=coverage,
                input_type="url",
                redacted_input=norm["normalized_url"]
            )

            report = scoring_engine.assemble_report(
                report_id=report_id,
                input_type="url",
                input_display=norm["normalized_url"],
                normalized_url=norm["normalized_url"],
                registrable_domain=norm["registrable_domain"],
                final_url=final_url,
                final_domain=final_domain,
                resolved_ips=resolved_ips,
                findings=all_findings,
                checks=all_checks,
                coverage=coverage,
                risk_label=label,
                risk_score=score,
                redirect_chain=redirect_chain,
                tls=tls_report,
                security_headers=header_results,
                threat_intel=threat_intel_summary,
                campaign=campaign,
                message_analysis=None,
                ai_explanation=explanation,
                duration_ms=int((time.time() - t0) * 1000),
                is_cached_sample=bool(request.use_cached)
            )

        # Save to database
        now_str = datetime.now(timezone.utc).isoformat()
        record = ScanRecord(
            report_id=report_id,
            created_at=now_str,
            input_type=request.type,
            risk_label=report.risk_label.value,
            risk_score=report.risk_score,
            full_report_json=json.dumps(report.model_dump(), sort_keys=True),
            is_committed=False,
            is_demo_seed=False
        )
        db.add(record)

        # Save extracted indicators
        for ind_type, ind_val, strength in current_indicators:
            db.add(IndicatorRecord(
                report_id=report_id,
                indicator_type=ind_type,
                indicator_value=ind_val,
                strength_class=strength,
                created_at=now_str
            ))

        db.commit()
        job_runner.mark_complete(report_id, report.model_dump())

    except Exception as e:
        job_runner.mark_failed(report_id, f"Scan failed: {str(e)}")
