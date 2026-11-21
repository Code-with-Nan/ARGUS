from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "ARGUS API"
    app_env: str = "development"
    database_url: str = "postgresql+psycopg:///argus_db"
    workspace_dir: str = ".argus/workspaces"
    cors_origins: str = "http://localhost:3000"
    trusted_frontend_origins: str = ""
    api_token: str | None = None
    auth_cookie_name: str = "argus_session"
    auth_session_ttl_seconds: int = 60 * 60 * 12
    auth_cookie_secure: bool = False
    login_rate_limit_attempts: int = 5
    login_rate_limit_window_seconds: int = 15 * 60
    max_upload_size: int = 10 * 1024 * 1024
    max_extracted_size: int = 50 * 1024 * 1024
    max_archive_files: int = 500
    max_compression_ratio: int = 100
    max_source_file_size: int = 2 * 1024 * 1024
    max_zip_entry_size: int = 20 * 1024 * 1024
    scanner_timeout_seconds: int = 120
    include_dependency_audits: bool = True
    semgrep_bin: str | None = None
    ai_provider: str = "fallback"
    ai_api_url: str | None = None
    ai_api_key: str | None = None
    ai_model: str = "gpt-4o-mini"
    ai_timeout_seconds: int = 15
    ai_include_code: bool = False

    @model_validator(mode="after")
    def require_secure_cookies_in_production(self):
        if self.app_env.strip().lower() == "production" and not self.auth_cookie_secure:
            raise ValueError("AUTH_COOKIE_SECURE=true is required when APP_ENV=production")
        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


settings = Settings()
