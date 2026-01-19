"""
Subfinder collector for subdomain discovery.

Wraps the subfinder tool to discover subdomains for a given domain.
Subfinder is a subdomain discovery tool from ProjectDiscovery.
"""

import logging
import shutil
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class SubfinderNotFoundError(Exception):
    """Raised when subfinder is not installed or not in PATH."""

    pass


class SubfinderError(Exception):
    """Raised when subfinder execution fails."""

    pass


@dataclass
class SubfinderResult:
    """Result from a subfinder scan.

    Attributes:
        domain: The target domain that was scanned.
        subdomains: List of discovered subdomains.
    """

    domain: str
    subdomains: list[str]


class SubfinderCollector:
    """Collector that wraps the subfinder subdomain discovery tool.

    Subfinder passively discovers subdomains using various sources like
    certificate transparency logs, search engines, and DNS datasets.

    Example:
        >>> collector = SubfinderCollector()
        >>> result = collector.run("example.com")
        >>> print(f"Found {len(result.subdomains)} subdomains")
    """

    def __init__(self, timeout: int = 120):
        """Initialize the SubfinderCollector.

        Args:
            timeout: Maximum time in seconds to wait for subfinder.
                     Defaults to 120 seconds.
        """
        self.timeout = timeout
        self._verify_installation()

    def _verify_installation(self) -> None:
        """Verify that subfinder is installed and accessible.

        Raises:
            SubfinderNotFoundError: If subfinder is not found in PATH.
        """
        if not shutil.which("subfinder"):
            raise SubfinderNotFoundError(
                "subfinder not found in PATH. Install it with:\n"
                "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
                "Ensure ~/go/bin is in your PATH."
            )

    def run(self, domain: str) -> SubfinderResult:
        """Run subfinder against a domain to discover subdomains.

        Args:
            domain: The target domain to scan (e.g., "example.com").

        Returns:
            SubfinderResult containing the domain and discovered subdomains.

        Raises:
            SubfinderError: If subfinder execution fails.
            subprocess.TimeoutExpired: If scan exceeds timeout.

        Example:
            >>> collector = SubfinderCollector(timeout=60)
            >>> result = collector.run("scanme.sh")
            >>> for sub in result.subdomains:
            ...     print(sub)
        """
        logger.info(f"Running subfinder for domain: {domain}")

        cmd = ["subfinder", "-d", domain, "-silent"]

        try:
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )

            if process.returncode != 0:
                error_msg = process.stderr.strip() or "Unknown error"
                raise SubfinderError(f"subfinder failed: {error_msg}")

            # Parse output - one subdomain per line
            subdomains = [
                line.strip()
                for line in process.stdout.strip().split("\n")
                if line.strip()
            ]

            # Remove duplicates while preserving order
            seen = set()
            unique_subdomains = []
            for sub in subdomains:
                if sub.lower() not in seen:
                    seen.add(sub.lower())
                    unique_subdomains.append(sub.lower())

            logger.info(f"Discovered {len(unique_subdomains)} subdomains for {domain}")

            return SubfinderResult(domain=domain, subdomains=unique_subdomains)

        except subprocess.TimeoutExpired:
            logger.error(f"subfinder timed out after {self.timeout}s for {domain}")
            raise
        except SubfinderError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error running subfinder: {e}")
            raise SubfinderError(f"Failed to run subfinder: {e}") from e
