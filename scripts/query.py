#!/usr/bin/env python3
"""
ExposureGraph Query CLI

Natural language interface for querying the security knowledge graph.

Usage:
    python scripts/query.py "What are the riskiest assets?"
    python scripts/query.py "Show staging servers" --verbose
    python scripts/query.py "How many subdomains?" --mock
    python scripts/query.py examples
"""

import os
import sys
from pathlib import Path
from typing import Optional

# Fix Windows console encoding for Rich's Unicode characters
if sys.platform == "win32":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass

# Add project root to path for imports
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax

from src.ai import GraphQueryAgent, LLMClient
from src.ai.llm_client import LLMConnectionError, LLMError

app = typer.Typer(
    name="query",
    help="Natural language queries over the ExposureGraph knowledge graph",
    add_completion=False,
    invoke_without_command=True,
)
console = Console()


@app.callback()
def main(
    ctx: typer.Context,
    question: Optional[str] = typer.Argument(
        None,
        help="Natural language question about your security data",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Show raw query results in addition to summary",
    ),
    mock: bool = typer.Option(
        False,
        "--mock",
        "-m",
        help="Use mock LLM responses (for testing without Ollama)",
    ),
    show_cypher: bool = typer.Option(
        True,
        "--cypher/--no-cypher",
        help="Show the generated Cypher query",
    ),
) -> None:
    """Ask a question about your security data in natural language.

    The agent will:
    1. Generate a Cypher query from your question
    2. Execute it against the Neo4j knowledge graph
    3. Summarize the results in plain English

    Examples:
        python scripts/query.py "What are the riskiest assets?"
        python scripts/query.py "Show me staging servers"
        python scripts/query.py "How many subdomains do we have?"
        python scripts/query.py "What services run nginx?"
    """
    # If a subcommand is being invoked, don't run the main logic
    if ctx.invoked_subcommand is not None:
        return

    # Check if question is actually a subcommand name
    if question == "examples":
        ctx.invoke(examples)
        return

    # If no question provided, show help
    if question is None:
        console.print()
        console.print("[bold blue]ExposureGraph Query[/bold blue]")
        console.print("=" * 40)
        console.print()
        console.print("Usage: python scripts/query.py \"<question>\"")
        console.print()
        console.print("Examples:")
        console.print("  python scripts/query.py \"What are the riskiest assets?\"")
        console.print("  python scripts/query.py \"Show staging servers\" --verbose")
        console.print("  python scripts/query.py \"How many subdomains?\" --mock")
        console.print()
        console.print("Run [bold]python scripts/query.py examples[/bold] for more example queries.")
        console.print()
        return

    console.print()
    console.print("[bold blue]ExposureGraph Query[/bold blue]")
    console.print("=" * 40)
    console.print()

    # Show the question
    console.print(f"[bold]Question:[/bold] {question}")
    console.print()

    # Initialize the agent
    try:
        llm_client = LLMClient(mock=mock)

        # Check connection if not in mock mode
        if not mock:
            console.print("[dim]Checking Ollama connection...[/dim]")
            try:
                llm_client.check_connection()
                console.print("[dim]Ollama connected.[/dim]")
            except LLMConnectionError as e:
                console.print(f"[yellow]Warning:[/yellow] {e}")
                console.print("[yellow]Falling back to mock mode.[/yellow]")
                console.print()
                llm_client = LLMClient(mock=True)
            except LLMError as e:
                console.print(f"[yellow]Warning:[/yellow] {e}")
                console.print("[yellow]Falling back to mock mode.[/yellow]")
                console.print()
                llm_client = LLMClient(mock=True)

        agent = GraphQueryAgent(llm_client=llm_client)

    except Exception as e:
        console.print(f"[red]Failed to initialize agent:[/red] {e}")
        raise typer.Exit(1)

    # Run the query
    console.print("[dim]Generating query...[/dim]")
    result = agent.query(question)

    if not result.success:
        console.print()
        console.print(f"[red]Query failed:[/red] {result.error}")

        if "connect" in result.error.lower():
            console.print()
            console.print("[dim]Is Neo4j running? Try: docker-compose up -d[/dim]")

        raise typer.Exit(1)

    # Show generated Cypher
    if show_cypher and result.cypher:
        console.print()
        console.print("[bold]Generated Cypher:[/bold]")
        syntax = Syntax(result.cypher, "cypher", theme="monokai", word_wrap=True)
        console.print(syntax)

    # Show summary in a panel
    console.print()
    console.print(
        Panel(
            result.summary,
            title="[bold green]Answer[/bold green]",
            border_style="green",
            padding=(1, 2),
        )
    )

    # Show raw results if verbose
    if verbose and result.raw_results:
        console.print()
        console.print(f"[bold]Raw Results ({len(result.raw_results)} rows):[/bold]")

        # Build a table from results
        if result.raw_results:
            table = Table(show_header=True, header_style="bold cyan")

            # Get columns from first result
            columns = list(result.raw_results[0].keys())
            for col in columns:
                table.add_column(col)

            # Add rows (limit to 20 for display)
            for row in result.raw_results[:20]:
                values = []
                for col in columns:
                    val = row.get(col, "")
                    # Handle Neo4j datetime
                    if hasattr(val, "to_native"):
                        val = val.to_native().strftime("%Y-%m-%d %H:%M")
                    # Truncate long values
                    str_val = str(val) if val is not None else ""
                    if len(str_val) > 50:
                        str_val = str_val[:47] + "..."
                    values.append(str_val)
                table.add_row(*values)

            if len(result.raw_results) > 20:
                table.add_row(*["..." for _ in columns])

            console.print(table)

    elif verbose and not result.raw_results:
        console.print()
        console.print("[dim]No raw results to display.[/dim]")

    # Footer
    console.print()
    if llm_client.is_mock:
        console.print("[dim]Note: Using mock LLM responses[/dim]")
    console.print()


@app.command()
def examples() -> None:
    """Show example queries you can ask."""
    console.print()
    console.print("[bold blue]Example Queries[/bold blue]")
    console.print("=" * 40)
    console.print()

    examples_list = [
        ("Risk Analysis", [
            "What are the riskiest assets?",
            "Show high risk services above 70",
            "Which services have the most risk factors?",
        ]),
        ("Asset Discovery", [
            "How many subdomains do we have?",
            "List all domains",
            "What services are running?",
        ]),
        ("Technology Stack", [
            "What services run nginx?",
            "Show services with Apache",
            "Find services exposing version info",
        ]),
        ("Environment", [
            "Show staging servers",
            "Find development environments",
            "Are there any test servers exposed?",
        ]),
        ("Relationships", [
            "What subdomains belong to scanme.sh?",
            "Show the full path from domain to services",
        ]),
    ]

    for category, queries in examples_list:
        console.print(f"[bold cyan]{category}:[/bold cyan]")
        for q in queries:
            console.print(f"  [dim]-[/dim] \"{q}\"")
        console.print()

    console.print("[dim]Usage: python scripts/query.py \"<question>\"[/dim]")
    console.print()


if __name__ == "__main__":
    app()
