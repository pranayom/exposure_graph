"""
Neo4j client for ExposureGraph.

Provides a clean interface to Neo4j for all graph operations.
Uses MERGE to handle idempotent inserts (safe for repeated scans).
"""

import json
import logging
from contextlib import contextmanager
from typing import Any

from neo4j import GraphDatabase, Driver, Session

from config import get_settings
from .models import Domain, Subdomain, WebService, RiskResult

logger = logging.getLogger(__name__)


class Neo4jClient:
    """Client for Neo4j graph database operations.

    Handles connection management and provides methods for creating
    and querying security asset nodes.

    Example:
        >>> client = Neo4jClient()
        >>> client.connect()
        >>> client.create_domain("example.com")
        >>> client.close()

        # Or use as context manager:
        >>> with Neo4jClient() as client:
        ...     client.create_domain("example.com")
    """

    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ):
        """Initialize Neo4j client.

        Args:
            uri: Neo4j bolt URI. Defaults to settings.
            user: Neo4j username. Defaults to settings.
            password: Neo4j password. Defaults to settings.
        """
        settings = get_settings()
        self._uri = uri or settings.neo4j_uri
        self._user = user or settings.neo4j_user
        self._password = password or settings.neo4j_password
        self._driver: Driver | None = None

    def connect(self) -> None:
        """Establish connection to Neo4j.

        Raises:
            Exception: If connection fails.
        """
        logger.info(f"Connecting to Neo4j at {self._uri}")
        self._driver = GraphDatabase.driver(
            self._uri,
            auth=(self._user, self._password) if self._password else None,
        )
        # Verify connectivity
        self._driver.verify_connectivity()
        logger.info("Connected to Neo4j successfully")

    def close(self) -> None:
        """Close the Neo4j connection."""
        if self._driver:
            self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed")

    def __enter__(self) -> "Neo4jClient":
        """Context manager entry."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit."""
        self.close()

    @contextmanager
    def _session(self):
        """Get a Neo4j session.

        Yields:
            Neo4j session for running queries.

        Raises:
            RuntimeError: If not connected.
        """
        if not self._driver:
            raise RuntimeError("Not connected to Neo4j. Call connect() first.")
        session = self._driver.session()
        try:
            yield session
        finally:
            session.close()

    def create_indexes(self) -> None:
        """Create indexes for better query performance.

        Should be called once during initial setup.
        """
        indexes = [
            "CREATE INDEX domain_name IF NOT EXISTS FOR (d:Domain) ON (d.name)",
            "CREATE INDEX subdomain_fqdn IF NOT EXISTS FOR (s:Subdomain) ON (s.fqdn)",
            "CREATE INDEX webservice_url IF NOT EXISTS FOR (w:WebService) ON (w.url)",
            "CREATE INDEX webservice_risk IF NOT EXISTS FOR (w:WebService) ON (w.risk_score)",
        ]
        with self._session() as session:
            for index_query in indexes:
                session.run(index_query)
                logger.debug(f"Created index: {index_query}")
        logger.info("All indexes created successfully")

    def create_domain(self, name: str, source: str = "manual") -> Domain:
        """Create or update a Domain node.

        Uses MERGE to avoid duplicates.

        Args:
            name: Domain name (e.g., "example.com").
            source: Discovery source ("manual" or "scan").

        Returns:
            The created/updated Domain.
        """
        query = """
        MERGE (d:Domain {name: $name})
        ON CREATE SET d.discovered_at = datetime(), d.source = $source
        ON MATCH SET d.source = $source
        RETURN d.name as name, d.discovered_at as discovered_at, d.source as source
        """
        with self._session() as session:
            result = session.run(query, name=name.lower(), source=source)
            record = result.single()
            logger.info(f"Created/updated domain: {name}")
            return Domain(
                name=record["name"],
                discovered_at=record["discovered_at"].to_native(),
                source=record["source"],
            )

    def create_subdomain(self, fqdn: str, parent_domain: str) -> Subdomain:
        """Create or update a Subdomain node and link to parent Domain.

        Uses MERGE to avoid duplicates. Creates the relationship
        (:Domain)-[:HAS_SUBDOMAIN]->(:Subdomain).

        Args:
            fqdn: Fully qualified domain name (e.g., "api.example.com").
            parent_domain: Parent domain name (e.g., "example.com").

        Returns:
            The created/updated Subdomain.
        """
        query = """
        MERGE (d:Domain {name: $parent_domain})
        ON CREATE SET d.discovered_at = datetime(), d.source = 'scan'
        MERGE (s:Subdomain {fqdn: $fqdn})
        ON CREATE SET s.discovered_at = datetime()
        MERGE (d)-[:HAS_SUBDOMAIN]->(s)
        RETURN s.fqdn as fqdn, s.discovered_at as discovered_at
        """
        with self._session() as session:
            result = session.run(
                query,
                fqdn=fqdn.lower(),
                parent_domain=parent_domain.lower(),
            )
            record = result.single()
            logger.info(f"Created/updated subdomain: {fqdn}")
            return Subdomain(
                fqdn=record["fqdn"],
                discovered_at=record["discovered_at"].to_native(),
            )

    def create_webservice(
        self,
        url: str,
        subdomain_fqdn: str,
        status_code: int,
        title: str | None = None,
        server: str | None = None,
        technologies: list[str] | None = None,
        risk_score: int | None = None,
        risk_factors: list[dict] | None = None,
    ) -> WebService:
        """Create or update a WebService node and link to parent Subdomain.

        Uses MERGE to avoid duplicates. Creates the relationship
        (:Subdomain)-[:HOSTS]->(:WebService).

        Args:
            url: Full URL (e.g., "https://api.example.com").
            subdomain_fqdn: Parent subdomain FQDN.
            status_code: HTTP response status code.
            title: Page title from HTML.
            server: Server header value.
            technologies: List of detected technologies.
            risk_score: Calculated risk score (0-100).
            risk_factors: List of risk factor dicts.

        Returns:
            The created/updated WebService.
        """
        risk_factors_json = json.dumps(risk_factors) if risk_factors else None

        query = """
        MERGE (s:Subdomain {fqdn: $subdomain_fqdn})
        ON CREATE SET s.discovered_at = datetime()
        MERGE (w:WebService {url: $url})
        ON CREATE SET w.discovered_at = datetime()
        SET w.status_code = $status_code,
            w.title = $title,
            w.server = $server,
            w.technologies = $technologies,
            w.risk_score = $risk_score,
            w.risk_factors = $risk_factors
        MERGE (s)-[:HOSTS]->(w)
        RETURN w.url as url, w.status_code as status_code, w.title as title,
               w.server as server, w.technologies as technologies,
               w.risk_score as risk_score, w.risk_factors as risk_factors,
               w.discovered_at as discovered_at
        """
        with self._session() as session:
            result = session.run(
                query,
                url=url,
                subdomain_fqdn=subdomain_fqdn.lower(),
                status_code=status_code,
                title=title,
                server=server,
                technologies=technologies or [],
                risk_score=risk_score,
                risk_factors=risk_factors_json,
            )
            record = result.single()
            logger.info(f"Created/updated webservice: {url}")
            return WebService(
                url=record["url"],
                status_code=record["status_code"],
                title=record["title"],
                server=record["server"],
                technologies=record["technologies"] or [],
                risk_score=record["risk_score"],
                risk_factors=record["risk_factors"],
                discovered_at=record["discovered_at"].to_native(),
            )

    def get_all_domains(self) -> list[Domain]:
        """Get all Domain nodes.

        Returns:
            List of all domains in the graph.
        """
        query = """
        MATCH (d:Domain)
        RETURN d.name as name, d.discovered_at as discovered_at, d.source as source
        ORDER BY d.name
        """
        with self._session() as session:
            result = session.run(query)
            return [
                Domain(
                    name=record["name"],
                    discovered_at=record["discovered_at"].to_native(),
                    source=record["source"] or "manual",
                )
                for record in result
            ]

    def get_subdomains_for_domain(self, domain_name: str) -> list[Subdomain]:
        """Get all subdomains for a given domain.

        Args:
            domain_name: The parent domain name.

        Returns:
            List of subdomains belonging to the domain.
        """
        query = """
        MATCH (d:Domain {name: $name})-[:HAS_SUBDOMAIN]->(s:Subdomain)
        RETURN s.fqdn as fqdn, s.discovered_at as discovered_at
        ORDER BY s.fqdn
        """
        with self._session() as session:
            result = session.run(query, name=domain_name.lower())
            return [
                Subdomain(
                    fqdn=record["fqdn"],
                    discovered_at=record["discovered_at"].to_native(),
                )
                for record in result
            ]

    def get_webservices_by_risk(self, min_score: int = 0, limit: int = 10) -> list[WebService]:
        """Get web services ordered by risk score.

        Args:
            min_score: Minimum risk score filter.
            limit: Maximum number of results.

        Returns:
            List of web services sorted by risk (highest first).
        """
        query = """
        MATCH (w:WebService)
        WHERE w.risk_score >= $min_score
        RETURN w.url as url, w.status_code as status_code, w.title as title,
               w.server as server, w.technologies as technologies,
               w.risk_score as risk_score, w.risk_factors as risk_factors,
               w.discovered_at as discovered_at
        ORDER BY w.risk_score DESC
        LIMIT $limit
        """
        with self._session() as session:
            result = session.run(query, min_score=min_score, limit=limit)
            return [
                WebService(
                    url=record["url"],
                    status_code=record["status_code"],
                    title=record["title"],
                    server=record["server"],
                    technologies=record["technologies"] or [],
                    risk_score=record["risk_score"],
                    risk_factors=record["risk_factors"],
                    discovered_at=record["discovered_at"].to_native(),
                )
                for record in result
            ]

    def run_query(self, cypher: str, parameters: dict[str, Any] | None = None) -> list[dict]:
        """Run an arbitrary Cypher query.

        Args:
            cypher: The Cypher query string.
            parameters: Optional query parameters.

        Returns:
            List of result records as dictionaries.
        """
        with self._session() as session:
            result = session.run(cypher, parameters or {})
            return [dict(record) for record in result]

    def get_stats(self) -> dict[str, int]:
        """Get graph statistics.

        Returns:
            Dictionary with counts of nodes and relationships.
        """
        query = """
        MATCH (d:Domain) WITH count(d) as domains
        MATCH (s:Subdomain) WITH domains, count(s) as subdomains
        MATCH (w:WebService) WITH domains, subdomains, count(w) as webservices
        RETURN domains, subdomains, webservices
        """
        with self._session() as session:
            result = session.run(query)
            record = result.single()
            return {
                "domains": record["domains"],
                "subdomains": record["subdomains"],
                "webservices": record["webservices"],
            }

    def update_risk_score(
        self,
        url: str,
        risk_score: int,
        risk_factors: list[dict],
    ) -> bool:
        """Update risk score and factors for an existing WebService.

        Args:
            url: The URL of the web service to update.
            risk_score: Calculated risk score (0-100).
            risk_factors: List of risk factor dicts with name, contribution, explanation.

        Returns:
            True if the node was found and updated, False otherwise.

        Example:
            >>> client.update_risk_score(
            ...     "https://api.example.com",
            ...     risk_score=75,
            ...     risk_factors=[{"name": "Live Service", "contribution": 30, "explanation": "..."}]
            ... )
        """
        risk_factors_json = json.dumps(risk_factors)

        query = """
        MATCH (w:WebService {url: $url})
        SET w.risk_score = $risk_score,
            w.risk_factors = $risk_factors
        RETURN w.url as url
        """
        with self._session() as session:
            result = session.run(
                query,
                url=url,
                risk_score=risk_score,
                risk_factors=risk_factors_json,
            )
            record = result.single()
            if record:
                logger.debug(f"Updated risk score for {url}: {risk_score}")
                return True
            else:
                logger.warning(f"WebService not found for risk update: {url}")
                return False

    def get_webservices_without_scores(self) -> list[WebService]:
        """Get all web services that don't have risk scores yet.

        Returns:
            List of web services with null risk_score.
        """
        query = """
        MATCH (w:WebService)
        WHERE w.risk_score IS NULL
        RETURN w.url as url, w.status_code as status_code, w.title as title,
               w.server as server, w.technologies as technologies,
               w.risk_score as risk_score, w.risk_factors as risk_factors,
               w.discovered_at as discovered_at
        """
        with self._session() as session:
            result = session.run(query)
            return [
                WebService(
                    url=record["url"],
                    status_code=record["status_code"],
                    title=record["title"],
                    server=record["server"],
                    technologies=record["technologies"] or [],
                    risk_score=record["risk_score"],
                    risk_factors=record["risk_factors"],
                    discovered_at=record["discovered_at"].to_native(),
                )
                for record in result
            ]
