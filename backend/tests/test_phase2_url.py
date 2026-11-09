import pytest
from backend.app.analyzers.url_analyzer import url_analyzer, parse_domain_parts, normalize_confusables, levenshtein_distance
from backend.app.analyzers.domain_analyzer import DomainAnalyzer

def test_parse_domain_parts():
    sub, reg, sfx = parse_domain_parts("portal.onlinesbi.sbi.co.in")
    assert reg == "sbi.co.in"
    assert sfx == "co.in"
    assert sub == "portal.onlinesbi"

    sub2, reg2, sfx2 = parse_domain_parts("login.google.com")
    assert reg2 == "google.com"
    assert sfx2 == "com"
    assert sub2 == "login"

def test_official_domain_mitigation():
    # sbi.co.in is official State Bank of India domain
    res = url_analyzer.analyze("https://sbi.co.in/portal/login")
    assert res["is_official_match"] is True
    # Zero IMP findings should be raised for official brand domains (MIT-01)
    imp_signals = [f.signal_id for f in res["findings"] if f.signal_id.startswith("IMP")]
    assert len(imp_signals) == 0

def test_bank_lookalike_imp01_str01():
    # sbi-kyc-update.com has brand 'sbi' and phishing keywords 'kyc', 'update'
    res = url_analyzer.analyze("http://sbi-kyc-update.com/login")
    assert res["is_official_match"] is False
    signals = {f.signal_id for f in res["findings"]}
    assert "IMP-01" in signals
    assert "STR-01" in signals

def test_punycode_imp04():
    # xn--gogl-qqa.com is punycode
    res = url_analyzer.analyze("http://xn--gogl-qqa.com/login")
    signals = {f.signal_id for f in res["findings"]}
    assert "IMP-04" in signals

def test_bare_domain_normalization():
    norm = url_analyzer.normalize_url("sbi.co.in")
    assert norm["scheme"] == "https"
    assert norm["registrable_domain"] == "sbi.co.in"

def test_shortener_str06():
    res = url_analyzer.analyze("https://bit.ly/3xyz45")
    signals = {f.signal_id for f in res["findings"]}
    assert "STR-06" in signals

def test_embedded_redirect_str07():
    res = url_analyzer.analyze("https://example.com/login?redirect=https://evil.com/phish")
    signals = {f.signal_id for f in res["findings"]}
    assert "STR-07" in signals

def test_user_info_trick_str03():
    res = url_analyzer.analyze("https://support.google.com@evil-site.com/login")
    signals = {f.signal_id for f in res["findings"]}
    assert "STR-03" in signals

def test_typosquatting_imp02():
    # micros0ft.com with 0 for o
    res = url_analyzer.analyze("https://micros0ft.com/account")
    signals = {f.signal_id for f in res["findings"]}
    assert "IMP-02" in signals
