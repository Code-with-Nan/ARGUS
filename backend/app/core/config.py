
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ARGUS API"
    database_url: str = "postgresql+psycopg:///argus_db"
    workspace_dir: str = ".argus/workspaces"
    cors_origins: str = "http://localhost:3000"
    api_token: str | None = None
    max_upload_size: int = 10 * 1024 * 1024
    max_extracted_size: int = 50 * 1024 * 1024
    max_archive_files: int = 500
    max_compression_ratio: int = 100
    max_source_file_size: int = 2 * 1024 * 1024
    scanner_timeout_seconds: int = 120
    include_dependency_audits: bool = True
    semgrep_bin: str | None = None
    ai_provider: str = "fallback"
    ai_api_url: str | None = None
    ai_api_key: str | None = None
    ai_model: str = "gpt-4o-mini"
    ai_timeout_seconds: int = 15
    ai_include_code: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


settings = Settings()
