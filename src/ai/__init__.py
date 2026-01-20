"""
AI module for ExposureGraph.

Provides LLM-powered natural language queries over the security knowledge graph.
"""

from .llm_client import LLMClient
from .graph_agent import GraphQueryAgent

__all__ = ["LLMClient", "GraphQueryAgent"]
