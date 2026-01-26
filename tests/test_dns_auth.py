from phishing_analyzer.detector import (
    Cache,
    CacheConfig,
    DNSChecker,
    SPFDMARCDKIMAgent,
    HeaderOutput,
)

def test_spf_dmarc_dkim_all_missing(mocker):
    cache = Cache(CacheConfig())
    dns = DNSChecker(cache)

    # Mock DNS results
    mocker.patch.object(dns, "has_spf", return_value=False)
    mocker.patch.object(dns, "has_dmarc", return_value=False)

    header = HeaderOutput(
        from_email="attacker@evil.com",
        from_domain="evil.com",
        spf_result="unknown",
        dkim_result="missing",
        dmarc_result="unknown",
        anomalies=[],
        risk=0,
    )

    agent = SPFDMARCDKIMAgent(dns)
    out = agent.run("evil.com", header)

    assert out.risk > 0
    assert "SPF missing" in out.issues
    assert "DMARC missing" in out.issues
    assert "DKIM missing" in out.issues
