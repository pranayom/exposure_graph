"""
Pydantic models for ExposureGraph knowledge graph nodes.

These models define the structure of security assets stored in Neo4j.
Each model corresponds to a node type in the graph.
"""

from datetime import datetime

from pydantic import BaseModel, Field


class Domain(BaseModel):
    """Root domain entity.

    Represents a top-level domain being monitored (e.g., "acme-corp.com").

    Attributes:
        name: The domain name (e.g., "acme-corp.com").
        discovered_at: When this domain was first added.
        source: How it was discovered ("manual" or "scan").
    """

    name: str = Field(..., description="Domain name (e.g., acme-corp.com)")
    discovered_at: datetime = Field(default_factory=datetime.now)
    source: str = Field(default="manual", description="Discovery source: manual or scan")


class Subdomain(BaseModel):
    """Subdomain entity.

    Represents a subdomain discovered under a root domain.

    Attributes:
        fqdn: Fully qualified domain name (e.g., "api.acme-corp.com").
        discovered_at: When this subdomain was discovered.
    """

    fqdn: str = Field(..., description="Fully qualified domain name")
    discovered_at: datetime = Field(default_factory=datetime.now)


class WebService(BaseModel):
    """Web service entity.

    Represents an HTTP/HTTPS service running on a subdomain.
    Contains fingerprinting data and risk assessment.

    Attributes:
        url: Full URL of the service (e.g., "https://api.acme-corp.com").
        status_code: HTTP response status code.
        title: Page title from HTML.
        server: Server header value (e.g., "nginx/1.18.0").
        technologies: List of detected technologies.
        risk_score: Calculated risk score (0-100).
        risk_factors: JSON string of contributing risk factors.
        discovered_at: When this service was discovered.
    """

    url: str = Field(..., description="Full URL of the web service")
    status_code: int = Field(..., description="HTTP status code")
    title: str | None = Field(default=None, description="HTML page title")
    server: str | None = Field(default=None, description="Server header value")
    technologies: list[str] = Field(default_factory=list, description="Detected technologies")
    risk_score: int | None = Field(default=None, ge=0, le=100, description="Risk score 0-100")
    risk_factors: str | None = Field(default=None, description="JSON string of risk factors")
    discovered_at: datetime = Field(default_factory=datetime.now)


class RiskFactor(BaseModel):
    """Individual risk factor contributing to a score.

    Used to provide explainable risk assessments.

    Attributes:
        name: Factor name (e.g., "Version Disclosure").
        contribution: Points this factor adds to the score.
        explanation: Human-readable explanation of why this is risky.
    """

    name: str = Field(..., description="Risk factor name")
    contribution: int = Field(..., description="Points contributed to risk score")
    explanation: str = Field(..., description="Human-readable explanation")


class RiskResult(BaseModel):
    """Complete risk assessment result.

    Attributes:
        score: Total risk score (0-100).
        factors: List of contributing factors.
    """

    score: int = Field(..., ge=0, le=100, description="Total risk score")
    factors: list[RiskFactor] = Field(default_factory=list, description="Contributing factors")
