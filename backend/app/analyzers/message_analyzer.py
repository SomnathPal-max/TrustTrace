import re
import urllib.parse
from typing import Dict, List, Optional, Set, Tuple, Any

from backend.app.models import (
    Finding, FindingCategory, Severity, RiskLabel, MessageAnalysis
)
from backend.app.core.safe_client import defang_url
from backend.app.analyzers.url_analyzer import url_analyzer

# Redaction patterns (HC-13)
REDACT_PATTERNS = {
    "CARD_OR_AADHAAR": re.compile(r"\b(?:\d[ -]?){12,16}\b"),
    "OTP_OR_PIN": re.compile(r"\b(?<!\w)(?:\d{4}|\d{6})(?!\w)\b"),
    "PRIVATE_KEY": re.compile(r"\b0x[a-fA-F0-9]{64}\b"),
    "SEED_PHRASE": re.compile(r"\b(?:[a-z]{3,8}\s+){11,23}[a-z]{3,8}\b", re.IGNORECASE)
}

# Extraction patterns
URL_REGEX = re.compile(r"(?:https?://|hxxps?://|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[^\s<>\"']+", re.IGNORECASE)
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")
PHONE_REGEX = re.compile(r"(?:\+?91[\-\s]?)?[6-9]\d{9}\b")
UPI_REGEX = re.compile(r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b")
CRYPTO_REGEX = re.compile(r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b")

# Message phrases from Appendix E
PHRASE_LISTS = {
    "MSG-01": [
        "within 2 hours", "within 24 hours", "immediately", "act now",
        "last chance", "expires today", "urgent", "final notice", "action required"
    ],
    "MSG-02": [
        "will be blocked", "will be suspended", "account closed", "legal action",
        "penalty", "deactivated", "service disruption", "account restricted"
    ],
    "MSG-03": [
        "share your otp", "enter your pin", "update your pan", "complete kyc",
        "verify your aadhaar", "card number", "cvv", "login to verify", "update pan", "verify kyc"
    ],
    "MSG-03_NEGATION": [
        "do not share", "never share", "don't share", "we will never ask", "do not disclose"
    ],
    "MSG-04": [
        "pay a processing fee", "send money", "collect request", "transfer",
        "gift card", "bitcoin", "usdt", "registration fee", "processing fee", "advance fee"
    ],
    "MSG-05": [
        "you have won", "claim your prize", "cashback", "refund pending",
        "guaranteed returns", "double your money", "selected for the job", "lottery winner"
    ],
    "MSG-07": [
        "anydesk", "teamviewer", "quicksupport", "install this app", "screen share", "remote support"
    ],
    "MSG-08": [
        "hxxp", "[.]", "tinyurl", "bit.ly"
    ]
}

class MessageAnalyzer:
    def sanitize_and_redact(self, raw_text: str) -> Tuple[str, bool]:
        """Strips control chars, limits to 5000 chars, and redacts sensitive tokens."""
        if not raw_text:
            return "", False

        # Limit to 5000 chars
        truncated = raw_text[:5000]
        # Strip control characters except newline and tab
        cleaned = "".join(c for c in truncated if ord(c) >= 32 or c in "\n\t")

        redacted_text = cleaned
        redaction_applied = False
        for name, pattern in REDACT_PATTERNS.items():
            if pattern.search(redacted_text):
                redacted_text = pattern.sub(f"[{name}_REDACTED]", redacted_text)
                redaction_applied = True

        return redacted_text, redaction_applied

    def extract_entities(self, text: str) -> Dict[str, List[str]]:
        # Normalize obfuscated URLs: hxxp -> http, [.] -> .
        normalized_for_extraction = text.replace("hxxp://", "http://").replace("hxxps://", "https://").replace("[.]", ".")

        raw_urls = URL_REGEX.findall(normalized_for_extraction)
        cleaned_urls = []
        for u in raw_urls:
            # Clean trailing punctuation
            u_clean = u.rstrip(".,;:!?)'\"")
            if "." in u_clean and len(u_clean) > 4:
                cleaned_urls.append(u_clean)

        emails = EMAIL_REGEX.findall(text)
        phones = PHONE_REGEX.findall(text)
        upis = [u for u in UPI_REGEX.findall(text) if not EMAIL_REGEX.match(u)]
        cryptos = CRYPTO_REGEX.findall(text)

        return {
            "urls": list(dict.fromkeys(cleaned_urls)),
            "emails": list(dict.fromkeys(emails)),
            "phone_numbers": list(dict.fromkeys(phones)),
            "upi_ids": list(dict.fromkeys(upis)),
            "crypto_addresses": list(dict.fromkeys(cryptos))
        }

    def analyze(self, raw_message: str) -> Dict[str, Any]:
        redacted_text, redaction_applied = self.sanitize_and_redact(raw_message)
        entities = self.extract_entities(raw_message)
        findings: List[Finding] = []
        signals_triggered: List[str] = []
        what_message_says: List[str] = []
        what_checks_found: List[str] = []

        lower_text = raw_message.lower()

        # Check negation guard for MSG-03
        has_negation = any(neg in lower_text for neg in PHRASE_LISTS["MSG-03_NEGATION"])

        # Signal Matching MSG-01 to MSG-08
        # MSG-01: Urgency
        matched_01 = [p for p in PHRASE_LISTS["MSG-01"] if p in lower_text]
        if matched_01:
            signals_triggered.append("MSG-01")
            what_message_says.append(f"Uses urgent phrasing: '{', '.join(matched_01)}'")
            findings.append(Finding(
                id=f"F-MSG-{len(findings)+1:02d}",
                signal_id="MSG-01",
                category=FindingCategory.CONTENT,
                title="Urgency or time pressure language",
                description=f"Message uses psychological urgency tactics: '{matched_01[0]}'.",
                severity=Severity.LOW,
                points=10,
                technical_evidence={"matched_phrases": matched_01},
                source="message rules",
                potential_impact="Psychological pressure designed to prompt hasty compliance without verification.",
                recommendation="Pause and verify through trusted channels before taking any action.",
                limitation="Legitimate deadline notifications also use urgent phrasing."
            ))

        # MSG-02: Threat
        matched_02 = [p for p in PHRASE_LISTS["MSG-02"] if p in lower_text]
        if matched_02:
            signals_triggered.append("MSG-02")
            what_message_says.append(f"Threatens punitive action: '{', '.join(matched_02)}'")
            findings.append(Finding(
                id=f"F-MSG-{len(findings)+1:02d}",
                signal_id="MSG-02",
                category=FindingCategory.CONTENT,
                title="Threat of account suspension or penalty",
                description=f"Message threatens penalties or service deactivation: '{matched_02[0]}'.",
                severity=Severity.LOW,
                points=10,
                technical_evidence={"matched_phrases": matched_02},
                source="message rules",
                potential_impact="Coercive language used to force user into panicked submission.",
                recommendation="Do not panic. Contact your service provider via their verified hotline.",
                limitation="Automated payment delinquency notices can contain threat warnings."
            ))

        # MSG-03: Sensitive Request (with negation guard)
        matched_03 = [p for p in PHRASE_LISTS["MSG-03"] if p in lower_text]
        if matched_03:
            if has_negation:
                what_checks_found.append("Negation guard active: Message includes explicit warnings against sharing sensitive data.")
            else:
                signals_triggered.append("MSG-03")
                what_message_says.append(f"Requests credentials or KYC update: '{', '.join(matched_03)}'")
                findings.append(Finding(
                    id=f"F-MSG-{len(findings)+1:02d}",
                    signal_id="MSG-03",
                    category=FindingCategory.CONTENT,
                    title="Request for sensitive data or KYC update",
                    description=f"Message requests sensitive verification or credentials: '{matched_03[0]}'.",
                    severity=Severity.HIGH,
                    points=25,
                    technical_evidence={"matched_phrases": matched_03, "negation_guard_passed": True},
                    source="message rules",
                    potential_impact="Direct credential theft, identity fraud, or unauthorized account access.",
                    recommendation="Never share OTPs, PINs, or PAN details via SMS or unverified web links.",
                    limitation="Official account onboarding flows occasionally send KYC reminders."
                ))

        # MSG-04: Payment Request
        matched_04 = [p for p in PHRASE_LISTS["MSG-04"] if p in lower_text]
        if matched_04:
            signals_triggered.append("MSG-04")
            what_message_says.append(f"Demands payment or transfer: '{', '.join(matched_04)}'")
            findings.append(Finding(
                id=f"F-MSG-{len(findings)+1:02d}",
                signal_id="MSG-04",
                category=FindingCategory.CONTENT,
                title="Suspicious payment or fee request",
                description=f"Message solicits financial transfer or processing fee: '{matched_04[0]}'.",
                severity=Severity.MEDIUM,
                points=15,
                technical_evidence={"matched_phrases": matched_04},
                source="message rules",
                potential_impact="Financial loss through irreversible payments, UPI collect scams, or gift cards.",
                recommendation="Do not approve unexpected payment or UPI collect requests.",
                limitation="Legitimate billing notifications also mention payments."
            ))

        # MSG-05: Too Good To Be True
        matched_05 = [p for p in PHRASE_LISTS["MSG-05"] if p in lower_text]
        if matched_05:
            signals_triggered.append("MSG-05")
            what_message_says.append(f"Lures with unrealistic rewards: '{', '.join(matched_05)}'")
            findings.append(Finding(
                id=f"F-MSG-{len(findings)+1:02d}",
                signal_id="MSG-05",
                category=FindingCategory.CONTENT,
                title="Unrealistic reward or lottery lure",
                description=f"Message promises unearned rewards or guaranteed returns: '{matched_05[0]}'.",
                severity=Severity.MEDIUM,
                points=15,
                technical_evidence={"matched_phrases": matched_05},
                source="message rules",
                potential_impact="Advance-fee fraud or lottery scam designed to harvest initial fees.",
                recommendation="Remember that unsolicited prize and lottery notifications are fraudulent.",
                limitation="Promotional marketing campaigns can feature rewards."
            ))

        # MSG-07: Remote Access
        matched_07 = [p for p in PHRASE_LISTS["MSG-07"] if p in lower_text]
        if matched_07:
            signals_triggered.append("MSG-07")
            what_message_says.append(f"Requests installation of remote access software: '{', '.join(matched_07)}'")
            findings.append(Finding(
                id=f"F-MSG-{len(findings)+1:02d}",
                signal_id="MSG-07",
                category=FindingCategory.CONTENT,
                title="Remote-access application lure",
                description=f"Message prompts installation of remote desktop tools: '{matched_07[0]}'.",
                severity=Severity.HIGH,
                points=20,
                technical_evidence={"matched_phrases": matched_07},
                source="message rules",
                potential_impact="Complete compromise of your device and banking apps via remote takeover.",
                recommendation="Never install AnyDesk or TeamViewer at the instruction of an unsolicited caller.",
                limitation="Authorized IT support departments legitimately use remote software."
            ))

        # MSG-08: Obfuscated Link
        if "hxxp" in raw_message.lower() or "[.]" in raw_message:
            signals_triggered.append("MSG-08")
            what_message_says.append("Contains intentionally defanged or obfuscated links.")
            findings.append(Finding(
                id=f"F-MSG-{len(findings)+1:02d}",
                signal_id="MSG-08",
                category=FindingCategory.CONTENT,
                title="Obfuscated link format detected",
                description="The message contains deliberately obfuscated URLs (such as hxxp or bracketed dots).",
                severity=Severity.LOW,
                points=10,
                technical_evidence={"obfuscation_detected": True},
                source="message rules",
                potential_impact="Used by threat actors to evade basic SMS gateway security filters.",
                recommendation="Treat disguised links with extreme suspicion.",
                limitation="Security researchers defang links when sharing samples."
            ))

        # Scan extracted URLs
        per_url_labels: Dict[str, str] = {}
        technical_corroboration = False
        url_points = 0
        has_confirmed_malicious_url = False

        for url_str in entities["urls"][:5]:
            url_res = url_analyzer.analyze(url_str)
            if url_res["findings"]:
                technical_corroboration = True
                has_imp = any(f.signal_id.startswith("IMP") for f in url_res["findings"])
                if has_imp:
                    per_url_labels[url_str] = "High Risk"
                    url_points += 35
                    what_checks_found.append(f"Extracted link '{defang_url(url_str)}' impersonates brand '{url_res.get('matched_brand', 'Target')}'.")
                else:
                    per_url_labels[url_str] = "Suspicious"
                    url_points += 15
                    what_checks_found.append(f"Extracted link '{defang_url(url_str)}' flagged with structural anomalies.")
            else:
                per_url_labels[url_str] = "Low Risk"

        # Check Brand Impersonation in text vs Link (MSG-06 / IMP-05)
        for b in url_analyzer.brands:
            b_name = b.get("brand", "").lower()
            b_kws = [k.lower() for k in b.get("keywords", [])]
            if any(k in lower_text for k in b_kws):
                # Brand is named in text: check if any extracted URL matches official domain
                if entities["urls"]:
                    official_domains = [d.lower() for d in b.get("official_domains", [])]
                    matches_official = False
                    for u in entities["urls"]:
                        norm_u = url_analyzer.normalize_url(u)
                        if norm_u["registrable_domain"] in official_domains:
                            matches_official = True
                            break
                    if not matches_official:
                        technical_corroboration = True
                        signals_triggered.append("MSG-06")
                        what_checks_found.append(f"Impersonation mismatch: Text mentions {b.get('brand')} but link does not point to an official domain.")
                        findings.append(Finding(
                            id=f"F-MSG-{len(findings)+1:02d}",
                            signal_id="MSG-06",
                            category=FindingCategory.IMPERSONATION,
                            title=f"Brand impersonation with domain mismatch ({b.get('brand')})",
                            description=f"Message refers to {b.get('brand')} but directs to an unofficial destination.",
                            severity=Severity.HIGH,
                            points=25,
                            technical_evidence={"brand": b.get("brand"), "extracted_urls": entities["urls"]},
                            source="message rules",
                            potential_impact="Direct brand impersonation phishing lure.",
                            recommendation="Access the organization's services only through official websites.",
                            limitation="Organizations occasionally use external survey or event platforms."
                        ))

        # Apply Section 8.5 Message Label Decision
        score = sum(f.points for f in findings) + url_points
        
        if has_confirmed_malicious_url:
            label = RiskLabel.CONFIRMED_MALICIOUS
        elif len(raw_message.strip()) < 15:
            label = RiskLabel.INCONCLUSIVE
        elif not signals_triggered and not technical_corroboration:
            label = RiskLabel.LOW_RISK
        else:
            # Any signal fired: at least Suspicious
            label = RiskLabel.SUSPICIOUS
            # Check Exception (Section 8.5 step 6): >= 3 different MSG types including MSG-03 or MSG-04
            msg_types = {s for s in signals_triggered if s.startswith("MSG")}
            has_credential_or_pay = ("MSG-03" in msg_types) or ("MSG-04" in msg_types)
            if len(msg_types) >= 3 and has_credential_or_pay:
                label = RiskLabel.HIGH_RISK

            # With technical corroboration and score >= 45 -> High Risk
            if technical_corroboration and score >= 45:
                label = RiskLabel.HIGH_RISK

        message_analysis = MessageAnalysis(
            extracted_urls=entities["urls"],
            emails=entities["emails"],
            phone_numbers=entities["phone_numbers"],
            upi_ids=entities["upi_ids"],
            crypto_addresses=entities["crypto_addresses"],
            signals_triggered=signals_triggered,
            per_url_labels=per_url_labels,
            what_message_says=what_message_says,
            what_checks_found=what_checks_found,
            redaction_applied=redaction_applied
        )

        return {
            "label": label,
            "score": min(100, score),
            "findings": findings,
            "message_analysis": message_analysis,
            "redacted_text": redacted_text,
            "technical_corroboration": technical_corroboration
        }

message_analyzer = MessageAnalyzer()
