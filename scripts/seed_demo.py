#!/usr/bin/env python3
"""
Seed demo data for ExposureGraph.

Populates Neo4j with realistic demo data for demonstrations and testing
without needing to run actual reconnaissance scans.

Usage:
    python scripts/seed_demo.py          # Seed demo data
    python scripts/seed_demo.py --clear  # Clear existing data first
"""

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from random import choice, randint, shuffle

import typer
from rich.console import Console
from rich.table import Table

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.graph.client import Neo4jClient
from src.graph.models import RiskFactor

console = Console()
app = typer.Typer(help="Seed demo data for ExposureGraph")


# =============================================================================
# Demo Data Definitions
# =============================================================================

DEMO_DOMAINS = [
    {"name": "acme-corp.com", "source": "demo"},
    {"name": "example-tech.io", "source": "demo"},
]

# Subdomain templates with their typical characteristics
SUBDOMAIN_TEMPLATES = [
    # High risk - non-production exposed
    {"prefix": "staging-api", "risk_profile": "high", "tech": ["nginx/1.18.0", "Node.js", "Express"]},
    {"prefix": "dev", "risk_profile": "high", "tech": ["Apache/2.4.41", "PHP/7.4"]},
    {"prefix": "staging", "risk_profile": "high", "tech": ["nginx", "React", "Node.js"]},
    {"prefix": "test", "risk_profile": "high", "tech": ["Apache", "Python", "Django"]},
    {"prefix": "uat", "risk_profile": "high", "tech": ["nginx/1.16.1", "Java", "Spring"]},
    {"prefix": "sandbox", "risk_profile": "high", "tech": ["nginx", "Ruby", "Rails"]},

    # Critical risk - admin/legacy systems
    {"prefix": "admin", "risk_profile": "critical", "tech": ["Apache/2.2.34", "PHP/5.6"]},
    {"prefix": "legacy-admin", "risk_profile": "critical", "tech": ["Apache/2.2.22", "PHP/5.4", "MySQL"]},
    {"prefix": "jenkins", "risk_profile": "critical", "tech": ["Jetty", "Jenkins"]},
    {"prefix": "old-portal", "risk_profile": "critical", "tech": ["IIS/7.5", "ASP.NET"]},

    # Medium risk - standard services
    {"prefix": "api", "risk_profile": "medium", "tech": ["nginx/1.20.0", "Node.js", "Express"]},
    {"prefix": "app", "risk_profile": "medium", "tech": ["nginx", "React", "Webpack"]},
    {"prefix": "portal", "risk_profile": "medium", "tech": ["nginx/1.18.0", "Vue.js", "Node.js"]},
    {"prefix": "dashboard", "risk_profile": "medium", "tech": ["Apache/2.4.51", "Angular", "TypeScript"]},

    # Low risk - public/static
    {"prefix": "www", "risk_profile": "low", "tech": ["Cloudflare", "nginx"]},
    {"prefix": "static", "risk_profile": "low", "tech": ["Amazon S3", "CloudFront"]},
    {"prefix": "cdn", "risk_profile": "low", "tech": ["Fastly", "Varnish"]},
    {"prefix": "docs", "risk_profile": "low", "tech": ["GitHub Pages", "Jekyll"]},
    {"prefix": "blog", "risk_profile": "low", "tech": ["WordPress", "nginx", "PHP/8.1"]},
    {"prefix": "status", "risk_profile": "low", "tech": ["Atlassian Statuspage"]},
]

# Risk profiles with score ranges and typical factors
RISK_PROFILES = {
    "critical": {
        "score_range": (75, 95),
        "status_codes": [200, 200, 200, 403],
        "factors": [
            RiskFactor(name="Live Service", contribution=30, explanation="Service responds with HTTP 200, confirming it is live and accessible"),
            RiskFactor(name="Non-Production Exposed", contribution=15, explanation="URL indicates a non-production environment exposed to the internet"),
            RiskFactor(name="Version Disclosure", contribution=10, explanation="Server header reveals version information that could aid attackers"),
            RiskFactor(name="Outdated Technology", contribution=20, explanation="Detected end-of-life software that no longer receives security patches"),
        ],
    },
    "high": {
        "score_range": (55, 74),
        "status_codes": [200, 200, 301, 302],
        "factors": [
            RiskFactor(name="Live Service", contribution=30, explanation="Service responds with HTTP 200, confirming it is live and accessible"),
            RiskFactor(name="Non-Production Exposed", contribution=15, explanation="URL indicates a non-production environment exposed to the internet"),
            RiskFactor(name="Version Disclosure", contribution=10, explanation="Server header reveals version information that could aid attackers"),
        ],
    },
    "medium": {
        "score_range": (35, 54),
        "status_codes": [200, 200, 200, 301],
        "factors": [
            RiskFactor(name="Live Service", contribution=30, explanation="Service responds with HTTP 200, confirming it is live and accessible"),
            RiskFactor(name="Version Disclosure", contribution=10, explanation="Server header reveals version information that could aid attackers"),
        ],
    },
    "low": {
        "score_range": (20, 34),
        "status_codes": [200, 301, 302],
        "factors": [
            RiskFactor(name="Live Service", contribution=30, explanation="Service responds with HTTP 200, confirming it is live and accessible"),
        ],
    },
}

# Page titles for realism
PAGE_TITLES = {
    "api": "API Documentation",
    "staging-api": "Staging API - Internal Use Only",
    "dev": "Development Environment",
    "staging": "Staging Environment",
    "test": "Test Environment",
    "uat": "UAT Environment",
    "sandbox": "Sandbox Environment",
    "admin": "Admin Portal",
    "legacy-admin": "Legacy Admin System",
    "jenkins": "Jenkins CI/CD",
    "old-portal": "Customer Portal (Legacy)",
    "app": "Application",
    "portal": "Customer Portal",
    "dashboard": "Analytics Dashboard",
    "www": "Welcome to Our Company",
    "static": "",
    "cdn": "",
    "docs": "Documentation",
    "blog": "Company Blog",
    "status": "System Status",
}


# =============================================================================
# Helper Functions
# =============================================================================


def generate_risk_factors(profile_name: str) -> list[dict]:
    """Generate risk factors for a given profile."""
    profile = RISK_PROFILES[profile_name]
    factors = profile["factors"]

    # Randomly select some factors (at least 1)
    num_factors = randint(1, len(factors))
    selected = factors[:num_factors]

    return [
        {"name": f.name, "contribution": f.contribution, "explanation": f.explanation}
        for f in selected
    ]


def calculate_score_from_factors(factors: list[dict]) -> int:
    """Calculate risk score from factors."""
    base_score = 20
    total = base_score + sum(f["contribution"] for f in factors)
    return min(total, 100)


def generate_demo_services(domain: str, templates: list[dict]) -> list[dict]:
    """Generate web services for a domain from templates."""
    services = []

    for template in templates:
        profile = RISK_PROFILES[template["risk_profile"]]

        # Generate risk factors
        factors = generate_risk_factors(template["risk_profile"])
        score = calculate_score_from_factors(factors)

        # Ensure score is within profile range
        min_score, max_score = profile["score_range"]
        score = max(min_score, min(max_score, score))

        # Randomly adjust within range for variety
        score = randint(min_score, max_score)

        # Pick status code
        status_code = choice(profile["status_codes"])

        # Build service
        fqdn = f"{template['prefix']}.{domain}"
        protocol = "https" if template["risk_profile"] in ["low", "medium"] else choice(["http", "https"])

        service = {
            "fqdn": fqdn,
            "url": f"{protocol}://{fqdn}",
            "status_code": status_code,
            "title": PAGE_TITLES.get(template["prefix"], ""),
            "server": template["tech"][0] if template["tech"] else None,
            "technologies": template["tech"],
            "risk_score": score,
            "risk_factors": factors,
        }
        services.append(service)

    return services


# =============================================================================
# Main Commands
# =============================================================================


@app.command()
def seed(
    clear: bool = typer.Option(False, "--clear", "-c", help="Clear existing data before seeding"),
) -> None:
    """Seed the database with demo data."""
    console.print("\n[bold blue]ExposureGraph Demo Data Seeder[/bold blue]")
    console.print("=" * 40)

    try:
        with Neo4jClient() as client:
            # Clear existing data if requested
            if clear:
                console.print("\n[yellow]Clearing existing data...[/yellow]")
                client.run_query("MATCH (n) DETACH DELETE n")
                console.print("[green]Data cleared.[/green]")

            # Create indexes
            client.create_indexes()

            total_subdomains = 0
            total_services = 0

            # Process each domain
            for domain_info in DEMO_DOMAINS:
                domain_name = domain_info["name"]
                console.print(f"\n[cyan]Seeding domain: {domain_name}[/cyan]")

                # Create domain
                client.create_domain(domain_name, source="demo")

                # Shuffle templates and select a subset for variety
                templates = SUBDOMAIN_TEMPLATES.copy()
                shuffle(templates)
                selected_templates = templates[:randint(8, 12)]  # 8-12 subdomains per domain

                # Generate services
                services = generate_demo_services(domain_name, selected_templates)

                for service in services:
                    # Create subdomain
                    client.create_subdomain(service["fqdn"], domain_name)
                    total_subdomains += 1

                    # Create webservice
                    client.create_webservice(
                        url=service["url"],
                        subdomain_fqdn=service["fqdn"],
                        status_code=service["status_code"],
                        title=service["title"],
                        server=service["server"],
                        technologies=service["technologies"],
                    )

                    # Update risk score
                    client.update_risk_score(
                        url=service["url"],
                        risk_score=service["risk_score"],
                        risk_factors=service["risk_factors"],
                    )
                    total_services += 1

                console.print(f"  Created {len(services)} services")

            # Print summary
            console.print("\n")
            stats = client.get_stats()

            table = Table(title="Demo Data Summary")
            table.add_column("Metric", style="cyan")
            table.add_column("Count", style="green", justify="right")

            table.add_row("Domains", str(stats["domains"]))
            table.add_row("Subdomains", str(stats["subdomains"]))
            table.add_row("Web Services", str(stats["webservices"]))

            console.print(table)

            # Show risk distribution
            console.print("\n[bold]Risk Distribution:[/bold]")
            services = client.get_webservices_by_risk(min_score=0, limit=100)

            critical = len([s for s in services if s.risk_score and s.risk_score >= 70])
            high = len([s for s in services if s.risk_score and 50 <= s.risk_score < 70])
            medium = len([s for s in services if s.risk_score and 30 <= s.risk_score < 50])
            low = len([s for s in services if s.risk_score and s.risk_score < 30])

            console.print(f"  [red]Critical (70+):[/red] {critical}")
            console.print(f"  [yellow]High (50-69):[/yellow] {high}")
            console.print(f"  [blue]Medium (30-49):[/blue] {medium}")
            console.print(f"  [green]Low (<30):[/green] {low}")

            console.print("\n[bold green]Demo data seeded successfully![/bold green]")
            console.print("\nNext steps:")
            console.print("  1. Start the dashboard: [cyan]streamlit run src/ui/app.py[/cyan]")
            console.print("  2. Try the chat: Ask [cyan]'What are our riskiest assets?'[/cyan]")

    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.command()
def clear() -> None:
    """Clear all data from the database."""
    console.print("\n[bold yellow]Warning:[/bold yellow] This will delete ALL data from Neo4j!")

    if not typer.confirm("Are you sure you want to continue?"):
        console.print("Aborted.")
        raise typer.Exit(0)

    try:
        with Neo4jClient() as client:
            client.run_query("MATCH (n) DETACH DELETE n")
            console.print("[green]All data cleared.[/green]")
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        raise typer.Exit(1)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """Seed demo data for ExposureGraph."""
    if ctx.invoked_subcommand is None:
        seed()


if __name__ == "__main__":
    app()
