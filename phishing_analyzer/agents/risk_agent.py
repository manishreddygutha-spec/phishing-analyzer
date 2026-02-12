"""
Risk Scoring Agent
Calculates final phishing severity.
"""

from phishing_analyzer.detector import RiskScorerAgent
from phishing_analyzer.guardrails import POLICY


class RiskAgent:
    """
    Determines phishing risk and final action.
    """

    def run(self, detection_results):
        risk = RiskScorerAgent().run(
            detection_results["header"],
            detection_results["content"],
            detection_results["domain"],
            detection_results["auth"],
            POLICY
        )
        return risk
