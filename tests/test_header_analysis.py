from phishing_analyzer.detector import HeaderAnalyzerAgent

def test_header_analysis_spf_and_dmarc_fail():
    raw_headers = (
        "From: attacker@evil.com\n"
        "Return-Path: bounce@evil.net\n"
        "Received-SPF: fail\n"
        "Authentication-Results: dmarc=fail\n"
    )

    agent = HeaderAnalyzerAgent()
    out = agent.run(raw_headers)

    assert out.risk > 0
    assert any("SPF" in a for a in out.anomalies)
    assert any("DMARC" in a for a in out.anomalies)
