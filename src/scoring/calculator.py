"""
Risk calculator for ExposureGraph.

Provides transparent, explainable risk scoring for web services based on
observable security indicators. Each score comes with contributing factors
that explain why the score was assigned.
"""

import re
import logging
from dataclasses import dataclass

from src.graph.models import RiskFactor, RiskResult

logger = logging.getLogger(__name__)

# Known outdated technologies and their patterns
OUTDATED_TECHNOLOGIES = {
    "php/5": "PHP 5.x is end-of-life since January 2019",
    "php/7.0": "PHP 7.0 is end-of-life since December 2018",
    "php/7.1": "PHP 7.1 is end-of-life since December 2019",
    "php/7.2": "PHP 7.2 is end-of-life since November 2020",
    "apache/2.2": "Apache 2.2.x is end-of-life since July 2017",
    "nginx/1.1": "Nginx 1.1x is significantly outdated",
    "nginx/1.0": "Nginx 1.0x is significantly outdated",
    "openssl/1.0": "OpenSSL 1.0.x is end-of-life since December 2019",
    "jquery/1.": "jQuery 1.x has known security vulnerabilities",
    "jquery/2.": "jQuery 2.x has known security vulnerabilities",
    "angular/1.": "AngularJS 1.x is end-of-life since December 2021",
    "node/8": "Node.js 8 is end-of-life since December 2019",
    "node/10": "Node.js 10 is end-of-life since April 2021",
    "node/12": "Node.js 12 is end-of-life since April 2022",
    "python/2": "Python 2 is end-of-life since January 2020",
    "tomcat/7": "Apache Tomcat 7 is end-of-life",
    "tomcat/8.0": "Apache Tomcat 8.0 is end-of-life",
    "iis/6": "IIS 6 is end-of-life",
    "iis/7": "IIS 7 is end-of-life",
}

# Non-production environment indicators
NON_PROD_INDICATORS = ["staging", "dev", "test", "uat", "sandbox", "demo", "qa", "preprod"]

# Regex to detect version numbers in server headers
VERSION_PATTERN = re.compile(r"/\d+[\.\d]*")


@dataclass
class WebServiceData:
    """Minimal data structure for risk calculation.

    Can be created from httpx results or Neo4j WebService nodes.
    """

    url: str
    status_code: int
    title: str | None = None
    server: str | None = None
    technologies: list[str] | None = None


class RiskCalculator:
    """Calculate risk scores with explainable factors.

    The scoring model is transparent and deterministic:
    - Base score: 20 points (every exposed service has some risk)
    - Additional points added based on observable risk indicators
    - Maximum score capped at 100

    Example:
        >>> calc = RiskCalculator()
        >>> data = WebServiceData(
        ...     url="http://staging.example.com",
        ...     status_code=200,
        ...     server="nginx/1.18.0"
        ... )
        >>> result = calc.calculate_score(data)
        >>> print(f"Score: {result.score}")
        >>> for factor in result.factors:
        ...     print(f"  {factor.name}: +{factor.contribution}")
    """

    BASE_SCORE = 20

    def __init__(self):
        """Initialize the risk calculator."""
        self._outdated_tech = OUTDATED_TECHNOLOGIES
        self._non_prod_indicators = NON_PROD_INDICATORS

    def calculate_score(self, webservice: WebServiceData) -> RiskResult:
        """Calculate risk score with explainable factors.

        Args:
            webservice: The web service data to analyze.

        Returns:
            RiskResult containing score (0-100) and contributing factors.

        Example:
            >>> calc = RiskCalculator()
            >>> result = calc.calculate_score(service)
            >>> print(f"Score: {result.score}, Factors: {len(result.factors)}")
        """
        factors: list[RiskFactor] = []
        score = self.BASE_SCORE

        # Factor 1: Live service (+30)
        if webservice.status_code == 200:
            factors.append(
                RiskFactor(
                    name="Live Service",
                    contribution=30,
                    explanation="Service responds with HTTP 200, confirming it is live and accessible",
                )
            )
            score += 30

        # Factor 2: Non-production exposed (+15)
        non_prod_match = self._check_non_production(webservice.url)
        if non_prod_match:
            factors.append(
                RiskFactor(
                    name="Non-Production Exposed",
                    contribution=15,
                    explanation=f"URL contains '{non_prod_match}', indicating a non-production "
                    "environment exposed to the internet",
                )
            )
            score += 15

        # Factor 3: Version disclosure (+10)
        if webservice.server and self._has_version(webservice.server):
            factors.append(
                RiskFactor(
                    name="Version Disclosure",
                    contribution=10,
                    explanation=f"Server header '{webservice.server}' reveals version information, "
                    "aiding attackers in finding known vulnerabilities",
                )
            )
            score += 10

        # Factor 4: Outdated technology (+20)
        outdated = self._check_outdated_tech(webservice)
        if outdated:
            tech_name, reason = outdated
            factors.append(
                RiskFactor(
                    name="Outdated Technology",
                    contribution=20,
                    explanation=f"Detected '{tech_name}': {reason}",
                )
            )
            score += 20

        # Factor 5: No HTTPS (+15)
        if webservice.url.startswith("http://"):
            factors.append(
                RiskFactor(
                    name="No HTTPS",
                    contribution=15,
                    explanation="Service uses unencrypted HTTP, exposing data in transit to "
                    "interception and tampering",
                )
            )
            score += 15

        # Factor 6: Directory listing (+10)
        if webservice.title and "index of" in webservice.title.lower():
            factors.append(
                RiskFactor(
                    name="Directory Listing",
                    contribution=10,
                    explanation="Page title suggests directory listing is enabled, potentially "
                    "exposing sensitive files and structure",
                )
            )
            score += 10

        # Cap score at 100
        final_score = min(score, 100)

        logger.debug(
            f"Calculated risk score for {webservice.url}: {final_score} "
            f"({len(factors)} factors)"
        )

        return RiskResult(score=final_score, factors=factors)

    def _check_non_production(self, url: str) -> str | None:
        """Check if URL indicates a non-production environment.

        Args:
            url: The URL to check.

        Returns:
            The matched indicator or None.
        """
        url_lower = url.lower()
        for indicator in self._non_prod_indicators:
            if indicator in url_lower:
                return indicator
        return None

    def _has_version(self, server_header: str) -> bool:
        """Check if server header contains version information.

        Args:
            server_header: The Server header value.

        Returns:
            True if version pattern is found.
        """
        return bool(VERSION_PATTERN.search(server_header))

    def _check_outdated_tech(self, webservice: WebServiceData) -> tuple[str, str] | None:
        """Check for outdated technologies.

        Checks both server header and detected technologies list.

        Args:
            webservice: The web service data.

        Returns:
            Tuple of (tech_name, reason) or None if no outdated tech found.
        """
        # Check server header
        if webservice.server:
            server_lower = webservice.server.lower()
            for pattern, reason in self._outdated_tech.items():
                if pattern in server_lower:
                    return (pattern, reason)

        # Check technologies list
        if webservice.technologies:
            for tech in webservice.technologies:
                tech_lower = tech.lower()
                for pattern, reason in self._outdated_tech.items():
                    if pattern in tech_lower:
                        return (tech, reason)

        return None
