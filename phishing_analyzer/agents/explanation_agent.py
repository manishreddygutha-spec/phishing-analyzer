"""
Explanation Agent (CrewAI)
Generates human-readable phishing analysis explanation.
"""

from phishing_analyzer.crewai_explainer import run_crewai_explainer


class ExplanationAgent:
    """
    LLM-based explanation agent.
    Optional but part of multi-agent architecture.
    """

    def run(self, report_text: str):
        return run_crewai_explainer(report_text)
