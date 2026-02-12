"""
Explanation Agent (CrewAI)
Generates analyst explanation using LLM.
"""

from phishing_analyzer.crewai_explainer import run_crewai_explainer


class ExplanationAgent:
    """
    LLM explanation agent.
    Optional but part of architecture.
    """

    def run(self, report_text: str):
        return run_crewai_explainer(report_text)
