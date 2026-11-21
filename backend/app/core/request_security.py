from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings


def trusted_origins() -> set[str]:
    sources = (
        settings.trusted_frontend_origins
        if settings.trusted_frontend_origins.strip()
        else settings.cors_origins
    )
    origins: set[str] = set()
    for source in sources.split(","):
        origin = source.strip().rstrip("/")
        if origin:
            origins.add(origin)
    return origins


def validate_origin(origin: str | None = Header(default=None, alias="Origin")) -> None:
    if origin is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Origin header is required.")
    normalized = origin.strip().rstrip("/")
    if normalized not in trusted_origins():
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Untrusted origin.")

    parsed = urlsplit(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Untrusted origin.")


def login_limit_key(request: Request, email: str) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    address = forwarded.split(",", 1)[0].strip() if forwarded else (request.client.host if request.client else "unknown")
    return f"login:{address}:{email.strip().lower()}"


def check_login_rate_limit(db: Session, key: str) -> datetime:
    from app.models.auth import LoginAttempt

    now = datetime.now(timezone.utc)
    attempt = db.query(LoginAttempt).filter(LoginAttempt.key == key).first()
    if attempt:
        if attempt.blocked_until and attempt.blocked_until.tzinfo is None:
            attempt.blocked_until = attempt.blocked_until.replace(tzinfo=timezone.utc)
        if attempt.blocked_until and attempt.blocked_until > now:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many login attempts. Try again later.",
                headers={"Retry-After": str(max(1, int((attempt.blocked_until - now).total_seconds())))},
            )
        window_start = attempt.updated_at
        if window_start.tzinfo is None:
            window_start = window_start.replace(tzinfo=timezone.utc)
        if now - window_start >= timedelta(seconds=settings.login_rate_limit_window_seconds):
            attempt.failed_attempts = 0
            attempt.blocked_until = None
    else:
        attempt = LoginAttempt(key=key, failed_attempts=0)
        db.add(attempt)
        db.flush()
    db.commit()
    return now


def record_failed_login(db: Session, key: str) -> None:
    from app.models.auth import LoginAttempt

    now = datetime.now(timezone.utc)
    attempt = db.query(LoginAttempt).filter(LoginAttempt.key == key).first()
    if not attempt:
        attempt = LoginAttempt(key=key, failed_attempts=0)
        db.add(attempt)
    attempt.failed_attempts += 1
    if attempt.failed_attempts >= settings.login_rate_limit_attempts:
        attempt.blocked_until = now + timedelta(seconds=settings.login_rate_limit_window_seconds)
    db.commit()


def clear_failed_login(db: Session, key: str) -> None:
    from app.models.auth import LoginAttempt

    attempt = db.query(LoginAttempt).filter(LoginAttempt.key == key).first()
    if attempt:
        db.delete(attempt)
        db.commit()
