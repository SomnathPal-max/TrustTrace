import pytest
from backend.app.analyzers.threat_intel import ThreatIntelClient

def test_bundled_dataset_int03():
    # sbi-kyc-update.com is present in bundled dataset
    client = ThreatIntelClient(auth_key=None)
    res = client.analyze(
        target_url="http://sbi-kyc-update.com/login",
        hostname="sbi-kyc-update.com",
        registrable_domain="sbi-kyc-update.com"
    )
    assert "Bundled Curated Threat Dataset" in res["summary"].feeds_answered
    assert "URLhaus (abuse.ch)" in res["summary"].feeds_unavailable
    
    int03_findings = [f for f in res["findings"] if f.signal_id == "INT-03"]
    assert len(int03_findings) == 1
    assert int03_findings[0].points == 40
    assert "banking phishing" in int03_findings[0].description

def test_urlhaus_online_listing_int01():
    client = ThreatIntelClient(auth_key="test-key")
    # Mock URLhaus response for an online URL
    client.query_urlhaus_url = lambda url: ({
        "query_status": "ok",
        "url_status": "online",
        "date_added": "2026-11-01 12:00:00",
        "threat": "malware_download",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/"
    }, True)
    client.query_urlhaus_host = lambda host: (None, False)

    res = client.analyze(
        target_url="http://malware-drop.xyz/payload.exe",
        hostname="malware-drop.xyz",
        registrable_domain="malware-drop.xyz"
    )
    assert res["short_circuit_fetch"] is True
    int01_findings = [f for f in res["findings"] if f.signal_id == "INT-01"]
    assert len(int01_findings) == 1
    assert int01_findings[0].severity.value == "Critical"
    assert "online" in int01_findings[0].description

def test_urlhaus_offline_listing_int02():
    client = ThreatIntelClient(auth_key="test-key")
    client.query_urlhaus_url = lambda url: ({"query_status": "no_results"}, True)
    client.query_urlhaus_host = lambda host: ({
        "query_status": "ok",
        "host_status": "offline",
        "firstseen": "2026-08-10",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/malware-drop.xyz/"
    }, True)

    res = client.analyze(
        target_url="http://malware-drop.xyz/clean-path",
        hostname="malware-drop.xyz",
        registrable_domain="malware-drop.xyz"
    )
    assert res["short_circuit_fetch"] is False
    int02_findings = [f for f in res["findings"] if f.signal_id == "INT-02"]
    assert len(int02_findings) == 1
    assert int02_findings[0].points == 40
    assert "offline" in int02_findings[0].description
