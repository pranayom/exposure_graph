"""
LLM Client for ExposureGraph.

Wraps the Ollama Python library to provide a clean interface for
LLM completions used by the graph query agent.
"""

import logging
from typing import Optional

import ollama
from ollama import Client, ResponseError

from config import get_settings

logger = logging.getLogger(__name__)


class LLMError(Exception):
    """Raised when LLM operations fail."""

    pass


class LLMConnectionError(LLMError):
    """Raised when unable to connect to Ollama."""

    pass


class LLMClient:
    """Client for interacting with Ollama LLM.

    Provides a simple interface for text completions using local LLMs.
    Supports mock mode for testing without a running Ollama instance.

    Example:
        >>> client = LLMClient()
        >>> response = client.complete(
        ...     prompt="What is 2+2?",
        ...     system="You are a helpful assistant."
        ... )
        >>> print(response)
        "2+2 equals 4."
    """

    def __init__(
        self,
        host: Optional[str] = None,
        model: Optional[str] = None,
        mock: Optional[bool] = None,
    ):
        """Initialize the LLM client.

        Args:
            host: Ollama server URL. Defaults to settings.ollama_host.
            model: Model name to use. Defaults to settings.ollama_model.
            mock: If True, return mock responses. Defaults to settings.mock_llm.
        """
        settings = get_settings()
        self._host = host or settings.ollama_host
        self._model = model or settings.ollama_model
        self._mock = mock if mock is not None else settings.mock_llm
        self._client: Optional[Client] = None

        if not self._mock:
            self._client = Client(host=self._host)

        logger.info(
            f"LLMClient initialized (model={self._model}, mock={self._mock})"
        )

    @property
    def model(self) -> str:
        """Get the model name being used."""
        return self._model

    @property
    def is_mock(self) -> bool:
        """Check if client is in mock mode."""
        return self._mock

    def complete(
        self,
        prompt: str,
        system: Optional[str] = None,
    ) -> str:
        """Generate a completion for the given prompt.

        Args:
            prompt: The user prompt to complete.
            system: Optional system prompt to set context.

        Returns:
            The generated text response.

        Raises:
            LLMConnectionError: If unable to connect to Ollama.
            LLMError: If the completion fails for other reasons.

        Example:
            >>> client = LLMClient()
            >>> cypher = client.complete(
            ...     prompt="Generate a Cypher query to find all domains",
            ...     system="You are a Neo4j Cypher expert."
            ... )
        """
        if self._mock:
            return self._mock_response(prompt, system)

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        try:
            logger.debug(f"Sending completion request to {self._model}")
            response = self._client.chat(
                model=self._model,
                messages=messages,
            )
            content = response["message"]["content"]
            logger.debug(f"Received response: {content[:100]}...")
            return content

        except ResponseError as e:
            logger.error(f"Ollama response error: {e}")
            if "model" in str(e).lower() and "not found" in str(e).lower():
                raise LLMError(
                    f"Model '{self._model}' not found. "
                    f"Run: ollama pull {self._model}"
                ) from e
            raise LLMError(f"LLM request failed: {e}") from e

        except Exception as e:
            error_msg = str(e).lower()
            if "connection" in error_msg or "refused" in error_msg:
                logger.error(f"Failed to connect to Ollama at {self._host}")
                raise LLMConnectionError(
                    f"Cannot connect to Ollama at {self._host}. "
                    "Is Ollama running? Start it with: ollama serve"
                ) from e
            logger.error(f"LLM error: {e}")
            raise LLMError(f"LLM request failed: {e}") from e

    def _mock_response(self, prompt: str, system: Optional[str]) -> str:
        """Generate a mock response for testing.

        Args:
            prompt: The user prompt.
            system: The system prompt (used to determine response type).

        Returns:
            A mock response appropriate for the context.
        """
        prompt_lower = prompt.lower()

        # Mock Cypher generation
        if system and "cypher" in system.lower():
            if "riskiest" in prompt_lower or "risk" in prompt_lower:
                return "MATCH (w:WebService) RETURN w.url, w.risk_score ORDER BY w.risk_score DESC LIMIT 5"
            if "subdomain" in prompt_lower:
                return "MATCH (s:Subdomain) RETURN s.fqdn LIMIT 10"
            if "count" in prompt_lower or "how many" in prompt_lower:
                return "MATCH (n) RETURN labels(n)[0] as type, count(n) as count"
            return "MATCH (w:WebService) RETURN w.url, w.risk_score LIMIT 5"

        # Mock summary generation
        if system and "summarize" in system.lower():
            return (
                "Based on the query results, there are several web services "
                "in the graph with varying risk scores. The highest risk "
                "services should be prioritized for security review."
            )

        # Generic mock response
        return f"[Mock response for: {prompt[:50]}...]"

    def check_connection(self) -> bool:
        """Check if Ollama is reachable and model is available.

        Returns:
            True if connection is successful and model exists.

        Raises:
            LLMConnectionError: If unable to connect.
            LLMError: If model is not available.
        """
        if self._mock:
            logger.info("Mock mode enabled, skipping connection check")
            return True

        try:
            # List models to verify connection
            models = self._client.list()
            model_names = [m["name"] for m in models.get("models", [])]

            # Check if our model is available (handle tag variations)
            model_base = self._model.split(":")[0]
            available = any(model_base in name for name in model_names)

            if not available:
                logger.warning(
                    f"Model '{self._model}' not found. "
                    f"Available: {model_names}"
                )
                raise LLMError(
                    f"Model '{self._model}' not found. "
                    f"Run: ollama pull {self._model}"
                )

            logger.info(f"Ollama connection verified, model '{self._model}' available")
            return True

        except LLMError:
            raise
        except Exception as e:
            raise LLMConnectionError(
                f"Cannot connect to Ollama at {self._host}: {e}"
            ) from e
