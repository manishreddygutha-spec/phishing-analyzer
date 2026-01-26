from phishing_analyzer.detector import (
    RiskScorerAgent,
    RiskConfig,
    HeaderOutput,
    ContentOutput,
    DomainOutput,
    SPFDMARCDKIMOutput,
)


def test_risk_scoring_escalates_from_info():
    """
    This test verifies that when multiple risk indicators are present,
    the email is NOT classified as Info/Allow, and is at least flagged.
    """

    header = HeaderOutput(
        from_email="attacker@evil.com",
        from_domain="evil.com",
        spf_result="fail",
        dkim_result="missing",
        dmarc_result="fail",
        anomalies=[
            "SPF failed",
            "DMARC failed",
            "Suspicious return-path mismatch",
        ],
        risk=75,
    )

    content = ContentOutput(
        indicators=[
            "credential harvesting",
            "urgent call to action",
            "password reset lure",
        ],
        risk=65,
    )

    domain = DomainOutput(
        domain_age_days=3,
        risk=55,
    )

    auth = SPFDMARCDKIMOutput(
        spf_present=False,
        dmarc_present=False,
        dkim_present=False,
        risk=50,
        issues=[
            "SPF missing",
            "DMARC missing",
            "DKIM missing",
        ],
    )

    agent = RiskScorerAgent()
    cfg = RiskConfig()

    out = agent.run(
        header=header,
        content=content,
        domain=domain,
        auth=auth,
        cfg=cfg,
    )

    # Core guarantees (policy-aligned)
    assert out.score >= 50
    assert out.severity in ("Low", "Medium", "High")
    assert out.action in ("Flag", "Quarantine", "Block")
