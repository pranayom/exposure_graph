"""
ExposureGraph Configuration

Centralized settings using Pydantic BaseSettings.
Values can be overridden via environment variables.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with environment variable support."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # Neo4j Configuration
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = ""  # Empty for local dev with NEO4J_AUTH=none

    # Ollama Configuration
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"

    # Application Settings
    allowed_targets: list[str] = ["scanme.sh", "example.com"]
    log_level: str = "INFO"

    # Feature Flags
    mock_llm: bool = False  # Set True to mock LLM responses for testing

    def is_target_allowed(self, target: str) -> bool:
        """Check if a target domain is in the allowed list.

        Args:
            target: The domain to check.

        Returns:
            True if the target is allowed, False otherwise.
        """
        return target.lower() in [t.lower() for t in self.allowed_targets]


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.

    Returns:
        Settings instance (cached for performance).
    """
    return Settings()
