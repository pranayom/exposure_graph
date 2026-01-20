"""
Graph Query Agent for ExposureGraph.

Enables natural language queries over the security knowledge graph
by orchestrating LLM-generated Cypher queries and result summarization.
"""

import logging
import re
from dataclasses import dataclass
from typing import Any, Optional

from .llm_client import LLMClient, LLMError
from src.graph.client import Neo4jClient

logger = logging.getLogger(__name__)


# System prompt for Cypher generation with schema and few-shot examples
CYPHER_SYSTEM_PROMPT = """You are a Neo4j Cypher query expert for a security knowledge graph.

Schema:
- (:Domain {name}) -[:HAS_SUBDOMAIN]-> (:Subdomain {fqdn})
- (:Subdomain) -[:HOSTS]-> (:WebService {url, status_code, title, server, technologies, risk_score, risk_factors})

Rules:
1. Output ONLY the Cypher query, no explanation or markdown
2. Use MATCH patterns, never CREATE/DELETE/SET
3. Limit results to 10 unless asked for more
4. Order by risk_score DESC for risk-related questions
5. Use CONTAINS for partial string matching (case-sensitive)
6. Use toLower() for case-insensitive matching

Examples:

Q: "What are the riskiest assets?"
A: MATCH (w:WebService) RETURN w.url AS url, w.risk_score AS risk_score, w.risk_factors AS risk_factors ORDER BY w.risk_score DESC LIMIT 5

Q: "Show staging servers"
A: MATCH (w:WebService) WHERE toLower(w.url) CONTAINS 'staging' RETURN w.url AS url, w.risk_score AS risk_score

Q: "How many subdomains?"
A: MATCH (s:Subdomain) RETURN count(s) AS total

Q: "List all domains"
A: MATCH (d:Domain) RETURN d.name AS domain, d.source AS source ORDER BY d.name

Q: "What services are running nginx?"
A: MATCH (w:WebService) WHERE w.server CONTAINS 'nginx' RETURN w.url AS url, w.server AS server, w.risk_score AS risk_score

Q: "Show high risk services above 70"
A: MATCH (w:WebService) WHERE w.risk_score >= 70 RETURN w.url AS url, w.risk_score AS risk_score, w.title AS title ORDER BY w.risk_score DESC

Q: "What subdomains belong to example.com?"
A: MATCH (d:Domain {name: 'example.com'})-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN s.fqdn AS subdomain ORDER BY s.fqdn

Q: "Show the full path from domain to services"
A: MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:HOSTS]->(w:WebService) RETURN d.name AS domain, s.fqdn AS subdomain, w.url AS service, w.risk_score AS risk_score ORDER BY w.risk_score DESC LIMIT 10"""


SUMMARY_SYSTEM_PROMPT = """You are a security analyst assistant. Summarize these query results in 2-3 concise sentences for a security team. Focus on actionable insights and risk implications. Be direct, not verbose.

If the results are empty, say so clearly and suggest what the user might try instead."""


@dataclass
class QueryResult:
    """Result of a natural language query.

    Attributes:
        question: The original natural language question.
        cypher: The generated Cypher query.
        raw_results: The raw query results from Neo4j.
        summary: LLM-generated summary of the results.
        success: Whether the query executed successfully.
        error: Error message if query failed.
    """

    question: str
    cypher: str
    raw_results: list[dict[str, Any]]
    summary: str
    success: bool = True
    error: Optional[str] = None


class GraphQueryAgent:
    """Agent for natural language queries over the security knowledge graph.

    Orchestrates the flow: question → Cypher → execution → summary.

    Example:
        >>> agent = GraphQueryAgent()
        >>> result = agent.query("What are the riskiest assets?")
        >>> print(result.summary)
        "The top 5 riskiest assets are staging servers with risk scores
        above 70, primarily due to version disclosure and exposed
        non-production environments."
    """

    def __init__(
        self,
        llm_client: Optional[LLMClient] = None,
        neo4j_client: Optional[Neo4jClient] = None,
    ):
        """Initialize the graph query agent.

        Args:
            llm_client: LLM client for completions. Created if not provided.
            neo4j_client: Neo4j client for queries. Created if not provided.
        """
        self._llm = llm_client or LLMClient()
        self._neo4j = neo4j_client
        self._owns_neo4j = neo4j_client is None

        logger.info("GraphQueryAgent initialized")

    def query(self, question: str) -> QueryResult:
        """Execute a natural language query against the graph.

        Args:
            question: Natural language question about the security data.

        Returns:
            QueryResult with cypher, raw results, and summary.

        Example:
            >>> result = agent.query("Show me all staging servers")
            >>> for row in result.raw_results:
            ...     print(row['url'], row['risk_score'])
        """
        logger.info(f"Processing question: {question}")

        # Step 1: Generate Cypher query
        try:
            cypher = self._generate_cypher(question)
            logger.debug(f"Generated Cypher: {cypher}")
        except LLMError as e:
            logger.error(f"Failed to generate Cypher: {e}")
            return QueryResult(
                question=question,
                cypher="",
                raw_results=[],
                summary=f"Failed to generate query: {e}",
                success=False,
                error=str(e),
            )

        # Step 2: Execute against Neo4j
        try:
            raw_results = self._execute_cypher(cypher)
            logger.debug(f"Query returned {len(raw_results)} results")
        except Exception as e:
            logger.error(f"Failed to execute Cypher: {e}")
            return QueryResult(
                question=question,
                cypher=cypher,
                raw_results=[],
                summary=f"Query execution failed: {e}",
                success=False,
                error=str(e),
            )

        # Step 3: Summarize results
        try:
            summary = self._summarize_results(question, raw_results)
        except LLMError as e:
            logger.warning(f"Failed to summarize results: {e}")
            # Fall back to basic summary
            summary = self._basic_summary(raw_results)

        return QueryResult(
            question=question,
            cypher=cypher,
            raw_results=raw_results,
            summary=summary,
            success=True,
        )

    def _generate_cypher(self, question: str) -> str:
        """Generate a Cypher query from natural language.

        Args:
            question: The natural language question.

        Returns:
            A Cypher query string.
        """
        response = self._llm.complete(
            prompt=question,
            system=CYPHER_SYSTEM_PROMPT,
        )

        # Extract Cypher from response (LLM might include extra text)
        cypher = self._extract_cypher(response)
        return cypher

    def _extract_cypher(self, response: str) -> str:
        """Extract Cypher query from LLM response.

        Handles cases where LLM includes markdown code blocks or extra text.

        Args:
            response: Raw LLM response.

        Returns:
            Clean Cypher query string.
        """
        # Remove markdown code blocks if present
        if "```" in response:
            # Extract content between code blocks
            match = re.search(r"```(?:cypher)?\s*(.*?)```", response, re.DOTALL)
            if match:
                return match.group(1).strip()

        # Look for MATCH statement (most Cypher queries start with MATCH)
        lines = response.strip().split("\n")
        cypher_lines = []
        in_query = False

        for line in lines:
            line_stripped = line.strip()
            # Start capturing when we see MATCH
            if line_stripped.upper().startswith("MATCH"):
                in_query = True
            if in_query:
                # Stop if we hit an explanation line
                if line_stripped and not any(
                    line_stripped.upper().startswith(kw)
                    for kw in ["MATCH", "WHERE", "RETURN", "ORDER", "LIMIT", "WITH", "OPTIONAL", "UNWIND", "CALL"]
                ) and not line_stripped.startswith("//"):
                    # Check if it's a continuation (contains Cypher keywords)
                    if not any(kw in line_stripped.upper() for kw in ["AS", "DESC", "ASC", "AND", "OR", "NOT", "IN", "CONTAINS"]):
                        break
                cypher_lines.append(line_stripped)

        if cypher_lines:
            return " ".join(cypher_lines)

        # If no MATCH found, return the whole response (might be valid)
        return response.strip()

    def _execute_cypher(self, cypher: str) -> list[dict[str, Any]]:
        """Execute Cypher query against Neo4j.

        Args:
            cypher: The Cypher query to execute.

        Returns:
            List of result records as dictionaries.
        """
        # Handle Neo4j client lifecycle
        if self._owns_neo4j:
            # Create and manage our own connection
            with Neo4jClient() as client:
                return client.run_query(cypher)
        else:
            # Use provided client (assume it's connected)
            return self._neo4j.run_query(cypher)

    def _summarize_results(
        self,
        question: str,
        results: list[dict[str, Any]],
    ) -> str:
        """Generate a natural language summary of query results.

        Args:
            question: The original question for context.
            results: The query results to summarize.

        Returns:
            Natural language summary string.
        """
        if not results:
            return self._llm.complete(
                prompt=f"Question: {question}\n\nResults: No data found.",
                system=SUMMARY_SYSTEM_PROMPT,
            )

        # Format results for the LLM (limit to avoid token overflow)
        results_text = self._format_results_for_summary(results[:20])

        response = self._llm.complete(
            prompt=f"Question: {question}\n\nResults:\n{results_text}",
            system=SUMMARY_SYSTEM_PROMPT,
        )

        return response.strip()

    def _format_results_for_summary(self, results: list[dict[str, Any]]) -> str:
        """Format query results as text for LLM summarization.

        Args:
            results: Query results to format.

        Returns:
            Formatted text representation.
        """
        lines = []
        for i, row in enumerate(results, 1):
            parts = []
            for key, value in row.items():
                # Handle Neo4j datetime objects
                if hasattr(value, "to_native"):
                    value = value.to_native().isoformat()
                # Truncate long values
                str_value = str(value)
                if len(str_value) > 100:
                    str_value = str_value[:100] + "..."
                parts.append(f"{key}: {str_value}")
            lines.append(f"{i}. {', '.join(parts)}")
        return "\n".join(lines)

    def _basic_summary(self, results: list[dict[str, Any]]) -> str:
        """Generate a basic summary when LLM is unavailable.

        Args:
            results: Query results to summarize.

        Returns:
            Basic text summary.
        """
        if not results:
            return "No results found for this query."

        count = len(results)
        if count == 1:
            return f"Found 1 result."
        return f"Found {count} results."
