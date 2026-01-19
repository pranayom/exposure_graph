#!/usr/bin/env python3
"""
ExposureGraph Scan CLI

Command-line interface for running reconnaissance scans and populating
the knowledge graph with discovered assets.

Usage:
    python scripts/run_scan.py scan scanme.sh
    python scripts/run_scan.py scan example.com --timeout 60
"""

import os
import sys
from pathlib import Path

# Fix Windows console encoding for Rich's Unicode characters
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    # Enable virtual terminal processing for ANSI escape codes
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass  # Non-critical, Rich will fall back gracefully

# Use ASCII spinner for Windows compatibility
SPINNER_NAME = "line" if sys.platform == "win32" else "dots"

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from config import get_settings
from src.collectors import SubfinderCollector, HttpxCollector
from src.collectors.subfinder import SubfinderNotFoundError, SubfinderError
from src.collectors.httpx import HttpxNotFoundError, HttpxError
from src.graph.client import Neo4jClient
from src.scoring import RiskCalculator
from src.scoring.calculator import WebServiceData

app = typer.Typer(
    name="exposuregraph",
    help="ExposureGraph - Security reconnaissance and knowledge graph builder",
    add_completion=False,
)
console = Console()


class ScanError(Exception):
    """Raised when a scan fails."""

    pass


def validate_target(target: str) -> None:
    """Validate that target is in allowed list.

    Args:
        target: Domain to validate.

    Raises:
        typer.BadParameter: If target is not allowed.
    """
    settings = get_settings()
    if not settings.is_target_allowed(target):
        allowed = ", ".join(settings.allowed_targets)
        raise typer.BadParameter(
            f"Target '{target}' is not in allowed list.\n"
            f"Allowed targets: {allowed}\n"
            f"Add targets via ALLOWED_TARGETS environment variable."
        )


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Target domain to scan (must be in ALLOWED_TARGETS)",
    ),
    timeout: int = typer.Option(
        120,
        "--timeout",
        "-t",
        help="Timeout in seconds for each tool",
    ),
    skip_httpx: bool = typer.Option(
        False,
        "--skip-httpx",
        help="Skip HTTP probing (only run subdomain discovery)",
    ),
) -> None:
    """Run a reconnaissance scan against a target domain.

    Discovers subdomains using subfinder, probes them with httpx,
    and stores results in the Neo4j knowledge graph.

    Example:
        python scripts/run_scan.py scan scanme.sh
    """
    console.print()
    console.print("[bold blue]ExposureGraph Scanner[/bold blue]")
    console.print("=" * 40)

    # Validate target
    try:
        validate_target(target)
    except typer.BadParameter as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    console.print(f"[green]Target:[/green] {target}")
    console.print()

    # Track results for summary
    subdomains_found = []
    services_found = []

    # Step 1: Subdomain discovery
    with Progress(
        SpinnerColumn(spinner_name=SPINNER_NAME),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running subfinder...", total=None)

        try:
            subfinder = SubfinderCollector(timeout=timeout)
            result = subfinder.run(target)
            subdomains_found = result.subdomains
            progress.update(task, description=f"[green]Found {len(subdomains_found)} subdomains[/green]")
        except SubfinderNotFoundError as e:
            progress.stop()
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(1)
        except SubfinderError as e:
            progress.stop()
            console.print(f"[red]Subfinder failed:[/red] {e}")
            raise typer.Exit(1)

    if not subdomains_found:
        console.print("[yellow]No subdomains discovered. Nothing to probe.[/yellow]")
        raise typer.Exit(0)

    # Display discovered subdomains
    console.print()
    console.print(f"[bold]Discovered {len(subdomains_found)} subdomains:[/bold]")
    for sub in subdomains_found[:10]:
        console.print(f"  [dim]•[/dim] {sub}")
    if len(subdomains_found) > 10:
        console.print(f"  [dim]... and {len(subdomains_found) - 10} more[/dim]")
    console.print()

    # Step 2: HTTP probing (optional)
    if not skip_httpx:
        with Progress(
            SpinnerColumn(spinner_name=SPINNER_NAME),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Running httpx...", total=None)

            try:
                httpx = HttpxCollector(timeout=timeout * 2)  # More time for probing
                services_found = httpx.run(subdomains_found)
                progress.update(
                    task,
                    description=f"[green]Found {len(services_found)} live services[/green]",
                )
            except HttpxNotFoundError as e:
                progress.stop()
                console.print(f"[red]Error:[/red] {e}")
                raise typer.Exit(1)
            except HttpxError as e:
                progress.stop()
                console.print(f"[red]Httpx failed:[/red] {e}")
                raise typer.Exit(1)

    # Step 3: Push to Neo4j
    console.print()
    with Progress(
        SpinnerColumn(spinner_name=SPINNER_NAME),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Connecting to Neo4j...", total=None)

        try:
            with Neo4jClient() as client:
                progress.update(task, description="Creating indexes...")
                client.create_indexes()

                progress.update(task, description="Creating domain node...")
                client.create_domain(target, source="scan")

                progress.update(task, description="Creating subdomain nodes...")
                for subdomain in subdomains_found:
                    client.create_subdomain(subdomain, target)

                if services_found:
                    progress.update(task, description="Creating webservice nodes...")
                    for service in services_found:
                        client.create_webservice(
                            url=service.url,
                            subdomain_fqdn=service.host,
                            status_code=service.status_code,
                            title=service.title,
                            server=service.server,
                            technologies=service.technologies,
                        )

                    # Calculate and store risk scores
                    progress.update(task, description="Calculating risk scores...")
                    calculator = RiskCalculator()
                    for service in services_found:
                        ws_data = WebServiceData(
                            url=service.url,
                            status_code=service.status_code,
                            title=service.title,
                            server=service.server,
                            technologies=service.technologies,
                        )
                        result = calculator.calculate_score(ws_data)
                        factors_dict = [
                            {
                                "name": f.name,
                                "contribution": f.contribution,
                                "explanation": f.explanation,
                            }
                            for f in result.factors
                        ]
                        client.update_risk_score(
                            url=service.url,
                            risk_score=result.score,
                            risk_factors=factors_dict,
                        )
                        # Store score for summary display
                        service.risk_score = result.score

                progress.update(task, description="[green]Data saved to Neo4j[/green]")

        except Exception as e:
            progress.stop()
            console.print(f"[red]Neo4j error:[/red] {e}")
            console.print("[dim]Is Neo4j running? Try: docker-compose up -d[/dim]")
            raise typer.Exit(1)

    # Summary
    console.print()
    console.print("[bold green]Scan Complete![/bold green]")
    console.print()

    # Summary table
    summary = Table(title="Scan Summary", show_header=True, header_style="bold")
    summary.add_column("Metric", style="cyan")
    summary.add_column("Count", justify="right")

    summary.add_row("Target Domain", target)
    summary.add_row("Subdomains Found", str(len(subdomains_found)))
    summary.add_row("Live Services", str(len(services_found)))

    console.print(summary)
    console.print()

    # Services table (if any found)
    if services_found:
        # Sort by risk score descending
        services_sorted = sorted(
            services_found,
            key=lambda s: getattr(s, "risk_score", 0) or 0,
            reverse=True,
        )

        services_table = Table(title="Live Services (by Risk)", show_header=True, header_style="bold")
        services_table.add_column("Risk", justify="center", width=6)
        services_table.add_column("URL", style="cyan", no_wrap=True, max_width=45)
        services_table.add_column("Status", justify="center")
        services_table.add_column("Title", max_width=25)
        services_table.add_column("Server", max_width=15)

        for svc in services_sorted[:15]:
            status_style = "green" if svc.status_code == 200 else "yellow"
            risk_score = getattr(svc, "risk_score", None) or 0
            # Color risk score based on severity
            if risk_score >= 70:
                risk_style = "red bold"
            elif risk_score >= 50:
                risk_style = "yellow"
            else:
                risk_style = "green"

            services_table.add_row(
                f"[{risk_style}]{risk_score}[/{risk_style}]",
                svc.url[:45],
                f"[{status_style}]{svc.status_code}[/{status_style}]",
                (svc.title or "")[:25],
                (svc.server or "")[:15],
            )

        if len(services_found) > 15:
            services_table.add_row(
                "",
                f"[dim]... and {len(services_found) - 15} more[/dim]",
                "",
                "",
                "",
            )

        console.print(services_table)
        console.print()

    console.print("[dim]View results: http://localhost:7474 (Neo4j Browser)[/dim]")
    console.print()


@app.command()
def status() -> None:
    """Check Neo4j connection and show graph statistics."""
    console.print()
    console.print("[bold blue]ExposureGraph Status[/bold blue]")
    console.print("=" * 40)

    try:
        with Neo4jClient() as client:
            stats = client.get_stats()
            console.print("[green]Neo4j:[/green] Connected")
            console.print()

            table = Table(title="Graph Statistics", show_header=True, header_style="bold")
            table.add_column("Node Type", style="cyan")
            table.add_column("Count", justify="right")

            table.add_row("Domains", str(stats["domains"]))
            table.add_row("Subdomains", str(stats["subdomains"]))
            table.add_row("Web Services", str(stats["webservices"]))

            console.print(table)

    except Exception as e:
        console.print(f"[red]Neo4j:[/red] Not connected")
        console.print(f"[dim]Error: {e}[/dim]")
        console.print()
        console.print("[dim]Start Neo4j with: docker-compose up -d[/dim]")
        raise typer.Exit(1)

    console.print()


if __name__ == "__main__":
    app()
