"""
Httpx collector for HTTP probing and fingerprinting.

Wraps the httpx tool to probe subdomains and extract service information.
Httpx is an HTTP toolkit from ProjectDiscovery.

Note: This collector specifically requires ProjectDiscovery's httpx (Go),
not the Python httpx library. The _find_projectdiscovery_httpx method
detects the correct binary by checking version output.
"""

import json
import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


class HttpxNotFoundError(Exception):
    """Raised when httpx is not installed or not in PATH."""

    pass


class HttpxError(Exception):
    """Raised when httpx execution fails."""

    pass


@dataclass
class HttpxResult:
    """Result for a single probed service.

    Attributes:
        url: Full URL of the service (e.g., "https://api.example.com").
        status_code: HTTP response status code.
        title: Page title from HTML, if available.
        server: Server header value, if available.
        technologies: List of detected technologies.
        host: The original host/subdomain that was probed.
    """

    url: str
    status_code: int
    title: str | None = None
    server: str | None = None
    technologies: list[str] = field(default_factory=list)
    host: str = ""


class HttpxCollector:
    """Collector that wraps the httpx HTTP probing tool.

    Httpx probes hosts for live HTTP/HTTPS services and fingerprints
    them to identify technologies, server versions, and page titles.

    This collector specifically requires ProjectDiscovery's httpx (Go binary),
    not the Python httpx library. It automatically detects and uses the correct
    binary even when both are installed.

    Example:
        >>> collector = HttpxCollector()
        >>> results = collector.run(["api.example.com", "www.example.com"])
        >>> for r in results:
        ...     print(f"{r.url} - {r.status_code} - {r.technologies}")
    """

    def __init__(self, timeout: int = 180):
        """Initialize the HttpxCollector.

        Args:
            timeout: Maximum time in seconds to wait for httpx.
                     Defaults to 180 seconds (probing can be slow).
        """
        self.timeout = timeout
        self.httpx_path = self._find_projectdiscovery_httpx()

    def _find_projectdiscovery_httpx(self) -> str:
        """Find the ProjectDiscovery httpx binary.

        Searches for httpx executables and identifies the ProjectDiscovery
        version by checking the version output for "projectdiscovery".

        Returns:
            Path to the ProjectDiscovery httpx binary.

        Raises:
            HttpxNotFoundError: If ProjectDiscovery httpx is not found.
        """
        candidates = self._get_httpx_candidates()

        if not candidates:
            raise HttpxNotFoundError(
                "httpx not found in PATH. Install it with:\n"
                "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
                "Ensure ~/go/bin is in your PATH."
            )

        # Check each candidate to find ProjectDiscovery httpx
        for candidate in candidates:
            if self._is_projectdiscovery_httpx(candidate):
                logger.info(f"Found ProjectDiscovery httpx at: {candidate}")
                return candidate

        # None of the candidates are ProjectDiscovery httpx
        raise HttpxNotFoundError(
            "Found httpx but it's not the ProjectDiscovery version.\n"
            "The Python httpx library may be shadowing the Go binary.\n"
            "Install ProjectDiscovery httpx with:\n"
            "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
            "Ensure ~/go/bin is before Python's Scripts in your PATH,\n"
            f"or found candidates: {candidates}"
        )

    def _get_httpx_candidates(self) -> list[str]:
        """Get all httpx executables in PATH.

        Returns:
            List of paths to httpx executables.
        """
        candidates = []

        # First, check shutil.which for the default
        default = shutil.which("httpx")
        if default:
            candidates.append(default)

        # Search PATH for additional httpx executables
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
        exe_names = ["httpx", "httpx.exe"] if os.name == "nt" else ["httpx"]

        for path_dir in path_dirs:
            for exe_name in exe_names:
                candidate = Path(path_dir) / exe_name
                if candidate.is_file():
                    candidate_str = str(candidate)
                    if candidate_str not in candidates:
                        candidates.append(candidate_str)

        # Also check common Go bin locations
        home = Path.home()
        go_paths = [
            home / "go" / "bin" / ("httpx.exe" if os.name == "nt" else "httpx"),
            home / ".go" / "bin" / ("httpx.exe" if os.name == "nt" else "httpx"),
        ]
        for go_path in go_paths:
            if go_path.is_file():
                go_path_str = str(go_path)
                if go_path_str not in candidates:
                    candidates.append(go_path_str)

        return candidates

    def _is_projectdiscovery_httpx(self, path: str) -> bool:
        """Check if an httpx binary is the ProjectDiscovery version.

        Args:
            path: Path to the httpx binary.

        Returns:
            True if it's ProjectDiscovery httpx, False otherwise.
        """
        try:
            result = subprocess.run(
                [path, "-version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout + result.stderr
            # ProjectDiscovery httpx shows "projectdiscovery" in version output
            return "projectdiscovery" in output.lower()
        except Exception as e:
            logger.debug(f"Failed to check httpx at {path}: {e}")
            return False

    def run(self, subdomains: list[str]) -> list[HttpxResult]:
        """Run httpx against a list of subdomains to probe for web services.

        Args:
            subdomains: List of subdomains to probe (e.g., ["api.example.com"]).

        Returns:
            List of HttpxResult objects for each discovered service.

        Raises:
            HttpxError: If httpx execution fails.
            subprocess.TimeoutExpired: If scan exceeds timeout.

        Example:
            >>> collector = HttpxCollector(timeout=120)
            >>> results = collector.run(["scanme.sh", "www.scanme.sh"])
            >>> for result in results:
            ...     print(f"{result.url}: {result.status_code}")
        """
        if not subdomains:
            logger.warning("No subdomains provided to httpx")
            return []

        logger.info(f"Running httpx against {len(subdomains)} subdomains")

        # httpx flags:
        # -json: Output in JSON format
        # -silent: Suppress banner and other output
        # -sc: Show status code
        # -title: Extract page title
        # -server: Show server header
        # -td: Detect technologies (tech detect)
        cmd = [self.httpx_path, "-json", "-silent", "-sc", "-title", "-server", "-td"]

        # Prepare input - one subdomain per line
        input_data = "\n".join(subdomains)

        try:
            process = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )

            # httpx may return non-zero for partial failures, but still produce output
            if process.returncode != 0 and not process.stdout:
                error_msg = process.stderr.strip() or "Unknown error"
                raise HttpxError(f"httpx failed: {error_msg}")

            # Parse JSON lines output
            results = []
            for line in process.stdout.strip().split("\n"):
                if not line.strip():
                    continue

                try:
                    data = json.loads(line)
                    result = self._parse_httpx_json(data)
                    if result:
                        results.append(result)
                except json.JSONDecodeError as e:
                    logger.warning(f"Failed to parse httpx JSON line: {e}")
                    continue

            logger.info(f"Httpx found {len(results)} live services")
            return results

        except subprocess.TimeoutExpired:
            logger.error(f"httpx timed out after {self.timeout}s")
            raise
        except HttpxError:
            raise
        except Exception as e:
            logger.error(f"Unexpected error running httpx: {e}")
            raise HttpxError(f"Failed to run httpx: {e}") from e

    def _parse_httpx_json(self, data: dict) -> HttpxResult | None:
        """Parse a single httpx JSON result.

        Args:
            data: Parsed JSON dict from httpx output.

        Returns:
            HttpxResult if valid data, None otherwise.
        """
        # Required fields
        url = data.get("url")
        status_code = data.get("status_code") or data.get("status-code")

        if not url or status_code is None:
            logger.debug(f"Skipping incomplete httpx result: {data}")
            return None

        # Optional fields
        title = data.get("title", "").strip() or None
        server = data.get("webserver") or data.get("server")

        # Technologies can be in different fields depending on httpx version
        technologies = []
        if "tech" in data and data["tech"]:
            technologies = data["tech"] if isinstance(data["tech"], list) else [data["tech"]]
        elif "technologies" in data and data["technologies"]:
            technologies = (
                data["technologies"]
                if isinstance(data["technologies"], list)
                else [data["technologies"]]
            )

        # Extract host from input field or URL
        host = data.get("input", "")
        if not host and url:
            # Parse host from URL
            from urllib.parse import urlparse

            parsed = urlparse(url)
            host = parsed.netloc or parsed.path.split("/")[0]

        return HttpxResult(
            url=url,
            status_code=int(status_code),
            title=title,
            server=server,
            technologies=technologies,
            host=host.lower() if host else "",
        )
