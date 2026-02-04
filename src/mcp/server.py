"""
MCP Server for ExposureGraph.

Exposes the security knowledge graph as MCP tools for Claude Code
and other MCP-compatible clients. Wraps existing Neo4jClient,
GraphQueryAgent, and RiskCalculator without duplicating business logic.

Usage:
    # Direct start (for testing)
    python src/mcp/server.py

    # Via MCP Inspector
    mcp dev src/mcp/server.py

    # Via Claude Code (.mcp.json auto-configures this)
    # Just restart Claude Code after adding .mcp.json
"""

import sys
import json
import logging
from datetime import datetime
from pathlib import Path

# CRITICAL: For stdio transport, all logging must go to stderr.
# Any stdout output corrupts the JSON-RPC protocol.
logging.basicConfig(
    level=logging.INFO,
    stream=sys.stderr,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("exposuregraph.mcp")

# Add project root to sys.path so we can import project modules
PROJECT_ROOT = str(Path(__file__).parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from mcp.server.fastmcp import FastMCP

from src.graph.client import Neo4jClient
from src.graph.models import RiskFactor, RiskResult
from src.scoring.calculator import RiskCalculator, WebServiceData
from src.ai.graph_agent import GraphQueryAgent
from src.ai.llm_client import LLMClient

# ---------------------------------------------------------------------------
# FastMCP instance
# ---------------------------------------------------------------------------
mcp = FastMCP("exposuregraph")

# ---------------------------------------------------------------------------
# Singleton holders (lazy-initialized)
# ---------------------------------------------------------------------------
_neo4j_client: Neo4jClient | None = None
_graph_agent: GraphQueryAgent | None = None
_risk_calculator: RiskCalculator | None = None

# ---------------------------------------------------------------------------
# Forbidden Cypher keywords for safety validation
# ---------------------------------------------------------------------------
FORBIDDEN_KEYWORDS = {"CREATE", "DELETE", "SET", "MERGE", "REMOVE", "DROP", "DETACH"}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def get_neo4j_client() -> Neo4jClient:
    """Get or create a connected Neo4j client singleton."""
    global _neo4j_client
    if _neo4j_client is None:
        _neo4j_client = Neo4jClient()
        _neo4j_client.connect()
        logger.info("Neo4j client connected")
    return _neo4j_client


def get_graph_agent() -> GraphQueryAgent:
    """Get or create a GraphQueryAgent singleton."""
    global _graph_agent
    if _graph_agent is None:
        client = get_neo4j_client()
        llm = LLMClient()
        _graph_agent = GraphQueryAgent(llm_client=llm, neo4j_client=client)
        logger.info("GraphQueryAgent initialized")
    return _graph_agent


def get_risk_calculator() -> RiskCalculator:
    """Get or create a RiskCalculator singleton."""
    global _risk_calculator
    if _risk_calculator is None:
        _risk_calculator = RiskCalculator()
    return _risk_calculator


def classify_risk(score: int) -> str:
    """Classify a numeric risk score into a category."""
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"


def serialize_for_json(obj):
    """Convert objects to JSON-safe types."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if hasattr(obj, "__dict__"):
        return obj.__dict__
    return str(obj)


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def get_risk_overview() -> str:
    """Get dashboard-level statistics about the attack surface.

    Returns risk distribution (critical/high/medium/low counts),
    total asset counts, and average risk score. Use this for a
    quick summary of the security posture.
    """
    try:
        client = get_neo4j_client()
        stats = client.get_stats()
        services = client.get_webservices_by_risk(min_score=0, limit=1000)

        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_score = 0
        for svc in services:
            if svc.risk_score is not None:
                distribution[classify_risk(svc.risk_score)] += 1
                total_score += svc.risk_score

        scored_count = len([s for s in services if s.risk_score is not None])
        avg_score = round(total_score / scored_count, 1) if scored_count else 0

        overview = {
            "asset_counts": stats,
            "risk_distribution": distribution,
            "average_risk_score": avg_score,
            "total_scored_services": scored_count,
        }
        return json.dumps(overview, indent=2)
    except Exception as e:
        logger.error(f"get_risk_overview failed: {e}")
        return json.dumps({"error": str(e)})


@mcp.tool()
def get_risky_assets(min_score: int = 0, limit: int = 10) -> str:
    """Get the riskiest web services from the knowledge graph.

    Args:
        min_score: Minimum risk score to include (0-100). Default 0.
        limit: Maximum number of results to return. Default 10.

    Returns a list of web services sorted by risk score descending,
    including URL, score, server header, and risk factors.
    """
    try:
        client = get_neo4j_client()
        services = client.get_webservices_by_risk(min_score=min_score, limit=limit)

        results = []
        for svc in services:
            entry = {
                "url": svc.url,
                "risk_score": svc.risk_score,
                "risk_level": classify_risk(svc.risk_score) if svc.risk_score else "unknown",
                "status_code": svc.status_code,
                "server": svc.server,
                "title": svc.title,
                "technologies": svc.technologies,
            }
            if svc.risk_factors:
                try:
                    entry["risk_factors"] = json.loads(svc.risk_factors)
                except (json.JSONDecodeError, TypeError):
                    entry["risk_factors"] = svc.risk_factors
            results.append(entry)

        return json.dumps(results, indent=2, default=serialize_for_json)
    except Exception as e:
        logger.error(f"get_risky_assets failed: {e}")
        return json.dumps({"error": str(e)})


@mcp.tool()
def get_assets_for_domain(domain_name: str) -> str:
    """Get all subdomains and their web services for a given domain.

    Args:
        domain_name: The domain to look up (e.g., "acme-corp.com").

    Returns subdomains with their hosted web services and risk scores.
    """
    try:
        client = get_neo4j_client()
        subdomains = client.get_subdomains_for_domain(domain_name)

        results = {
            "domain": domain_name,
            "subdomain_count": len(subdomains),
            "subdomains": [
                {
                    "fqdn": s.fqdn,
                    "discovered_at": s.discovered_at.isoformat() if s.discovered_at else None,
                }
                for s in subdomains
            ],
        }
        return json.dumps(results, indent=2)
    except Exception as e:
        logger.error(f"get_assets_for_domain failed: {e}")
        return json.dumps({"error": str(e)})


@mcp.tool()
def calculate_risk_score(
    url: str,
    status_code: int,
    server: str = "",
    title: str = "",
    technologies: str = "",
) -> str:
    """Calculate a what-if risk score for a hypothetical or real web service.

    Args:
        url: The URL of the web service (e.g., "http://staging.example.com").
        status_code: HTTP status code (e.g., 200, 404, 503).
        server: Server header value (e.g., "nginx/1.18.0"). Empty string if unknown.
        title: HTML page title. Empty string if unknown.
        technologies: Comma-separated list of technologies (e.g., "PHP/5.6,jQuery/1.12").

    Returns the risk score (0-100) and a list of contributing factors
    with explanations.
    """
    try:
        calc = get_risk_calculator()
        tech_list = [t.strip() for t in technologies.split(",") if t.strip()] if technologies else []

        data = WebServiceData(
            url=url,
            status_code=status_code,
            server=server or None,
            title=title or None,
            technologies=tech_list or None,
        )
        result = calc.calculate_score(data)

        output = {
            "url": url,
            "risk_score": result.score,
            "risk_level": classify_risk(result.score),
            "factors": [
                {
                    "name": f.name,
                    "contribution": f.contribution,
                    "explanation": f.explanation,
                }
                for f in result.factors
            ],
        }
        return json.dumps(output, indent=2)
    except Exception as e:
        logger.error(f"calculate_risk_score failed: {e}")
        return json.dumps({"error": str(e)})


@mcp.tool()
def run_cypher_query(cypher: str) -> str:
    """Execute a read-only Cypher query against the Neo4j knowledge graph.

    Only MATCH/RETURN queries are allowed. Write operations (CREATE, DELETE,
    SET, MERGE, REMOVE, DROP, DETACH) are blocked for safety.

    Args:
        cypher: The Cypher query string.

    Schema reference:
        (:Domain {name}) -[:HAS_SUBDOMAIN]-> (:Subdomain {fqdn})
        (:Subdomain) -[:HOSTS]-> (:WebService {url, status_code, title,
            server, technologies, risk_score, risk_factors})
    """
    # Safety validation
    upper = cypher.upper()
    for keyword in FORBIDDEN_KEYWORDS:
        if keyword in upper:
            return json.dumps({
                "error": f"Write operations not allowed. Forbidden keyword: {keyword}",
                "hint": "Only MATCH/RETURN queries are permitted.",
            })

    try:
        client = get_neo4j_client()
        results = client.run_query(cypher)

        serialized = []
        for record in results:
            row = {}
            for key, value in record.items():
                row[key] = serialize_for_json(value)
            serialized.append(row)

        return json.dumps({
            "query": cypher,
            "result_count": len(serialized),
            "results": serialized,
        }, indent=2, default=str)
    except Exception as e:
        logger.error(f"run_cypher_query failed: {e}")
        return json.dumps({"error": str(e), "query": cypher})


@mcp.tool()
def query_graph(question: str) -> str:
    """Ask a natural language question about the security knowledge graph.

    The question is converted to a Cypher query by the LLM, executed
    against Neo4j, and the results are summarized in plain English.

    Args:
        question: A natural language question (e.g., "What are our riskiest assets?",
                  "Show staging servers", "How many subdomains does acme-corp.com have?").

    Requires Ollama to be running with the configured model, or MOCK_LLM=true
    for mock responses.
    """
    try:
        agent = get_graph_agent()
        result = agent.query(question)

        output = {
            "question": result.question,
            "cypher": result.cypher,
            "summary": result.summary,
            "success": result.success,
            "result_count": len(result.raw_results),
        }
        if result.error:
            output["error"] = result.error
        if result.raw_results:
            # Include raw results (limited) for transparency
            serialized = []
            for record in result.raw_results[:20]:
                row = {}
                for key, value in record.items():
                    row[key] = serialize_for_json(value)
                serialized.append(row)
            output["raw_results"] = serialized

        return json.dumps(output, indent=2, default=str)
    except Exception as e:
        logger.error(f"query_graph failed: {e}")
        return json.dumps({"error": str(e), "question": question})


@mcp.tool()
def generate_risk_report(
    format: str = "executive",
    framework: str = "general",
) -> str:
    """Generate a compliance-style risk report from the knowledge graph.

    Args:
        format: Report format — "executive" for a high-level summary,
                "technical" for detailed findings. Default "executive".
        framework: Compliance framework context — "general", "nist", or "cis".
                   Default "general".

    Returns a markdown-formatted risk report suitable for stakeholder
    communication.
    """
    try:
        client = get_neo4j_client()
        stats = client.get_stats()
        services = client.get_webservices_by_risk(min_score=0, limit=1000)

        # Classify services
        distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        critical_assets = []
        for svc in services:
            if svc.risk_score is not None:
                level = classify_risk(svc.risk_score)
                distribution[level] += 1
                if level == "critical":
                    critical_assets.append(svc)

        scored = [s for s in services if s.risk_score is not None]
        avg_score = round(sum(s.risk_score for s in scored) / len(scored), 1) if scored else 0
        now = datetime.now().strftime("%Y-%m-%d %H:%M")

        framework_label = {
            "nist": "NIST Cybersecurity Framework",
            "cis": "CIS Controls v8",
            "general": "General Security Assessment",
        }.get(framework, "General Security Assessment")

        # Build report
        lines = [
            f"# ExposureGraph Risk Report",
            f"",
            f"**Generated:** {now}",
            f"**Framework:** {framework_label}",
            f"**Report Type:** {format.title()}",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"The attack surface consists of **{stats.get('domains', 0)} domains**, "
            f"**{stats.get('subdomains', 0)} subdomains**, and "
            f"**{stats.get('webservices', 0)} web services**.",
            f"",
            f"**Average Risk Score:** {avg_score}/100",
            f"",
            f"### Risk Distribution",
            f"",
            f"| Level | Count |",
            f"|-------|-------|",
            f"| Critical (80-100) | {distribution['critical']} |",
            f"| High (60-79) | {distribution['high']} |",
            f"| Medium (40-59) | {distribution['medium']} |",
            f"| Low (0-39) | {distribution['low']} |",
            f"",
        ]

        if critical_assets:
            lines.extend([
                f"## Critical Findings",
                f"",
                f"The following assets require immediate attention:",
                f"",
            ])
            for asset in critical_assets[:5]:
                factors_str = ""
                if asset.risk_factors:
                    try:
                        factors = json.loads(asset.risk_factors)
                        factor_names = [f.get("name", "Unknown") for f in factors]
                        factors_str = f" — Factors: {', '.join(factor_names)}"
                    except (json.JSONDecodeError, TypeError):
                        pass
                lines.append(
                    f"- **{asset.url}** (Score: {asset.risk_score}){factors_str}"
                )
            lines.append("")

        if format == "technical":
            lines.extend([
                f"## Technical Details",
                f"",
                f"### All Scored Services",
                f"",
                f"| URL | Score | Level | Server |",
                f"|-----|-------|-------|--------|",
            ])
            for svc in scored[:25]:
                level = classify_risk(svc.risk_score)
                lines.append(
                    f"| {svc.url} | {svc.risk_score} | {level} | {svc.server or 'N/A'} |"
                )
            lines.append("")

        lines.extend([
            f"## Recommendations",
            f"",
            f"1. **Address Critical Assets First** — {distribution['critical']} services "
            f"scored 80+ and need immediate remediation.",
            f"2. **Reduce Version Disclosure** — Remove version information from server headers.",
            f"3. **Enforce HTTPS** — Migrate all HTTP services to HTTPS.",
            f"4. **Decommission Non-Production** — Remove or restrict access to staging/dev "
            f"environments exposed to the internet.",
            f"",
            f"---",
            f"*Report generated by ExposureGraph*",
        ])

        return "\n".join(lines)
    except Exception as e:
        logger.error(f"generate_risk_report failed: {e}")
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# MCP Resources
# ---------------------------------------------------------------------------

@mcp.resource("exposuregraph://schema")
def get_schema() -> str:
    """Neo4j knowledge graph schema for ExposureGraph.

    Describes the node types, their properties, and relationships.
    Use this to understand the data model when writing Cypher queries.
    """
    return """# ExposureGraph Neo4j Schema

## Nodes

### Domain
Properties:
  - name: String (e.g., "acme-corp.com")
  - discovered_at: DateTime
  - source: String ("manual" | "scan")

### Subdomain
Properties:
  - fqdn: String (e.g., "api.acme-corp.com")
  - discovered_at: DateTime

### WebService
Properties:
  - url: String (e.g., "https://api.acme-corp.com")
  - status_code: Integer (e.g., 200, 404)
  - title: String (HTML page title)
  - server: String (e.g., "nginx/1.18.0")
  - technologies: List<String>
  - risk_score: Integer (0-100)
  - risk_factors: String (JSON array of factor objects)
  - discovered_at: DateTime

## Relationships

(:Domain)-[:HAS_SUBDOMAIN]->(:Subdomain)
(:Subdomain)-[:HOSTS]->(:WebService)

## Indexes

- domain_name: Domain.name
- subdomain_fqdn: Subdomain.fqdn
- webservice_url: WebService.url
- webservice_risk: WebService.risk_score
"""


@mcp.resource("exposuregraph://scoring-model")
def get_scoring_model() -> str:
    """Risk scoring model documentation for ExposureGraph.

    Describes how risk scores are calculated, including base score,
    all risk factors, their point contributions, and conditions.
    """
    return """# ExposureGraph Risk Scoring Model

## Overview

Risk scores range from 0 to 100. Every exposed service starts with a
base score and accumulates points from observable risk indicators.
The model is fully transparent — every score includes the contributing
factors and their explanations.

## Base Score: 20 points

Every internet-facing service has inherent risk from being exposed.

## Risk Factors

| Factor | Points | Condition |
|--------|--------|-----------|
| Live Service | +30 | HTTP status code is 200 |
| Non-Production Exposed | +15 | URL contains staging, dev, test, uat, sandbox, demo, qa, preprod |
| Version Disclosure | +10 | Server header contains version number (e.g., nginx/1.18.0) |
| Outdated Technology | +20 | Server or technologies match known EOL software |
| No HTTPS | +15 | URL starts with http:// |
| Directory Listing | +10 | Page title contains "Index of" |

## Maximum Score: 100

Scores are capped at 100 even if factors sum higher.

## Risk Levels

| Level | Score Range |
|-------|-------------|
| Critical | 80-100 |
| High | 60-79 |
| Medium | 40-59 |
| Low | 0-39 |

## Outdated Technology Database

Includes known EOL versions of: PHP, Apache, Nginx, OpenSSL,
jQuery, AngularJS, Node.js, Python, Tomcat, IIS.

## Example

A service at http://staging.example.com returning 200 with server
header "nginx/1.0.5" would score:
- Base: 20
- Live Service: +30
- Non-Production Exposed: +15
- Version Disclosure: +10
- Outdated Technology: +20 (nginx/1.0)
- No HTTPS: +15
- **Total: 100** (capped from 110)
"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """Run the ExposureGraph MCP server."""
    logger.info("Starting ExposureGraph MCP server...")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
