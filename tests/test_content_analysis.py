from phishing_analyzer.detector import (
    ContentAnalyzerAgent,
    IngestionOutput,
)

def test_content_detects_phishing_language():
    """
    Verifies that the ContentAnalyzerAgent detects
    common phishing language and escalates risk.
    """

    fake_email = IngestionOutput(
        raw_headers="",
        headers={},
        body_text="Urgent! Verify your password immediately.",
        urls=["http://evil.com/login"],
        attachments=[],
        from_email="attacker@evil.com",
        from_domain="evil.com",
    )

    agent = ContentAnalyzerAgent()
    out = agent.run(fake_email)

    # Assertions
    assert out.risk > 0
    assert len(out.indicators) > 0
    assert any(
        "Urgent" in indicator or "credential" in indicator.lower()
        for indicator in out.indicators
    )
