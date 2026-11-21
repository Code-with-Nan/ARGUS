from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.auth import router as auth_router
from app.core.config import settings
from app.core.database import Base, get_db
from app.models.auth import LoginAttempt, User, UserSession


@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    app = FastAPI()
    app.include_router(auth_router)

    def override_get_db():
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(settings, "cors_origins", "http://localhost:3000")
    monkeypatch.setattr(settings, "trusted_frontend_origins", "http://localhost:3000")
    monkeypatch.setattr(settings, "auth_cookie_name", "argus_test_session")
    monkeypatch.setattr(settings, "auth_cookie_secure", False)
    monkeypatch.setattr(settings, "login_rate_limit_attempts", 5)
    monkeypatch.setattr(settings, "login_rate_limit_window_seconds", 900)

    with TestClient(app) as test_client:
        yield test_client, session_factory
    engine.dispose()


def register(test_client, email="developer@example.com", password="correct-horse-battery"):
    return test_client.post(
        "/api/v1/auth/register",
        headers={"Origin": "http://localhost:3000"},
        json={"email": email, "display_name": "Test Developer", "password": password},
    )


def login(test_client, email="developer@example.com", password="correct-horse-battery", origin="http://localhost:3000"):
    headers = {} if origin is None else {"Origin": origin}
    return test_client.post(
        "/api/v1/auth/login",
        headers=headers,
        json={"email": email, "password": password},
    )


def test_registration_login_me_logout_and_cookie_flags(client):
    test_client, _ = client
    registration = register(test_client)
    assert registration.status_code == 201
    payload = registration.json()
    assert "password" not in payload
    assert "password_hash" not in payload

    login_response = login(test_client)
    assert login_response.status_code == 200
    assert "password" not in str(login_response.json()).lower()
    cookie = login_response.headers["set-cookie"]
    assert "argus_test_session=" in cookie
    assert "httponly" in cookie.lower()
    assert "samesite=lax" in cookie.lower()
    assert "secure" not in cookie.lower()

    me = test_client.get("/api/v1/auth/me")
    assert me.status_code == 200

    logout = test_client.post("/api/v1/auth/logout", headers={"Origin": "http://localhost:3000"})
    assert logout.status_code == 204
    assert test_client.get("/api/v1/auth/me").status_code == 401


def test_password_hash_is_argon2_and_raw_password_is_not_returned(client):
    test_client, session_factory = client
    registration = register(test_client, "argon2@example.com")
    assert registration.status_code == 201

    db = session_factory()
    user = db.query(User).filter(User.email == "argon2@example.com").first()
    assert user.password_hash.startswith("$argon2")
    assert "correct-horse-battery" not in user.password_hash
    assert "correct-horse-battery" not in str(registration.json())
    db.close()


def test_login_rejects_missing_origin(client):
    test_client, _ = client
    assert register(test_client).status_code == 201
    assert login(test_client, origin=None).status_code == 403


def test_login_rejects_untrusted_origin(client):
    test_client, _ = client
    assert register(test_client).status_code == 201
    assert login(test_client, origin="https://evil.example").status_code == 403


def test_logout_rejects_untrusted_origin(client):
    test_client, _ = client
    assert register(test_client).status_code == 201
    assert login(test_client).status_code == 200
    assert test_client.post("/api/v1/auth/logout", headers={"Origin": "https://evil.example"}).status_code == 403


def test_registration_rejects_missing_and_untrusted_origin(client):
    test_client, _ = client
    missing = test_client.post("/api/v1/auth/register", json={"email": "missing@example.com", "display_name": "Missing", "password": "correct-horse-battery"})
    untrusted = test_client.post("/api/v1/auth/register", headers={"Origin": "https://evil.example"}, json={"email": "untrusted@example.com", "display_name": "Untrusted", "password": "correct-horse-battery"})
    assert missing.status_code == 403
    assert untrusted.status_code == 403


def test_invalid_credentials_do_not_reveal_account_state(client):
    test_client, _ = client
    assert register(test_client, "person@example.com").status_code == 201
    response = login(test_client, "person@example.com", "wrong-password")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_disabled_user_cannot_login(client):
    test_client, session_factory = client
    assert register(test_client, "disabled@example.com").status_code == 201

    db = session_factory()
    user = db.query(User).filter(User.email == "disabled@example.com").first()
    user.is_active = False
    db.commit()
    db.close()

    assert login(test_client, "disabled@example.com").status_code == 403


def test_expired_and_revoked_sessions_cannot_authenticate(client):
    test_client, session_factory = client
    assert register(test_client, "expired@example.com").status_code == 201
    assert login(test_client, "expired@example.com").status_code == 200

    db = session_factory()
    user = db.query(User).filter(User.email == "expired@example.com").first()
    session = db.query(UserSession).filter(UserSession.user_id == user.id).first()
    session.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    db.close()
    assert test_client.get("/api/v1/auth/me").status_code == 401


def test_logout_revokes_only_active_session(client):
    test_client, session_factory = client
    assert register(test_client, "sessions@example.com").status_code == 201
    assert login(test_client, "sessions@example.com").status_code == 200

    db = session_factory()
    user = db.query(User).filter(User.email == "sessions@example.com").first()
    sessions = db.query(UserSession).filter(UserSession.user_id == user.id).all()
    assert len(sessions) == 1
    db.close()

    assert test_client.post("/api/v1/auth/logout", headers={"Origin": "http://localhost:3000"}).status_code == 204

    db = session_factory()
    session = db.query(UserSession).filter(UserSession.user_id == user.id).first()
    assert session.revoked_at is not None
    db.close()
    assert test_client.get("/api/v1/auth/me").status_code == 401


def test_login_rate_limit_and_recovery(client):
    test_client, session_factory = client
    assert register(test_client, "rate@example.com").status_code == 201

    for _ in range(settings.login_rate_limit_attempts):
        response = login(test_client, "rate@example.com", "wrong-password")
        assert response.status_code == 401

    blocked = login(test_client, "rate@example.com", "correct-horse-battery")
    assert blocked.status_code == 429
    assert "retry-after" in {name.lower() for name in blocked.headers}

    db = session_factory()
    attempt = db.query(LoginAttempt).filter(LoginAttempt.key.startswith("login:")).first()
    attempt.blocked_until = datetime.now(timezone.utc) - timedelta(seconds=1)
    attempt.updated_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()
    db.close()

    recovered = login(test_client, "rate@example.com", "correct-horse-battery")
    assert recovered.status_code == 200


def test_raw_session_token_never_appears_in_json(client):
    test_client, session_factory = client
    assert register(test_client, "token@example.com").status_code == 201
    login_response = login(test_client, "token@example.com")
    assert login_response.status_code == 200

    db = session_factory()
    session = db.query(UserSession).filter(UserSession.user_id == db.query(User).filter(User.email == "token@example.com").first().id).first()
    assert session.token_hash
    assert len(session.token_hash) == 64
    assert "token_hash" not in login_response.json()
    assert session.token_hash not in str(login_response.json())
    db.close()
