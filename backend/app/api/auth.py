from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.auth import (
    create_session_token,
    hash_password,
    hash_session_token,
    needs_password_rehash,
    normalize_email,
    session_expiry,
    verify_password,
)
from app.core.config import settings
from app.core.database import get_db
from app.core.request_security import (
    check_login_rate_limit,
    clear_failed_login,
    login_limit_key,
    record_failed_login,
    validate_origin,
)
from app.dependencies.auth import get_current_session, get_current_user
from app.models.auth import User, UserSession
from app.schemas.auth import AuthCredentials, RegistrationRequest, UserResponse


router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=settings.auth_cookie_name,
        value=token,
        max_age=settings.auth_session_ttl_seconds,
        expires=settings.auth_session_ttl_seconds,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="lax",
        path="/",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=settings.auth_cookie_name,
        httponly=True,
        secure=settings.auth_cookie_secure,
        samesite="lax",
        path="/",
    )


@router.post("/register", response_model=UserResponse, status_code=201, dependencies=[Depends(validate_origin)])
def register(request: RegistrationRequest, db: Session = Depends(get_db)):
    email = normalize_email(request.email)
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=409, detail="An account with this email already exists.")

    user = User(
        email=email,
        display_name=request.display_name,
        password_hash=hash_password(request.password),
        is_active=True,
    )
    db.add(user)
    try:
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    return user


@router.post("/login", response_model=UserResponse, dependencies=[Depends(validate_origin)])
def login(request: AuthCredentials, http_request: Request, response: Response, db: Session = Depends(get_db)):
    email = normalize_email(request.email)
    limit_key = login_limit_key(http_request, email)
    check_login_rate_limit(db, limit_key)

    user = db.query(User).filter(User.email == email).first()
    valid_password = bool(user and verify_password(user.password_hash, request.password))
    if not user or not valid_password:
        record_failed_login(db, limit_key)
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        record_failed_login(db, limit_key)
        raise HTTPException(status_code=403, detail="User account is disabled.")

    clear_failed_login(db, limit_key)

    if needs_password_rehash(user.password_hash):
        user.password_hash = hash_password(request.password)

    token = create_session_token()
    session = UserSession(
        user_id=user.id,
        token_hash=hash_session_token(token),
        expires_at=session_expiry(settings.auth_session_ttl_seconds),
    )
    db.add(session)
    db.commit()
    db.refresh(user)

    _set_session_cookie(response, token)
    return user


@router.post("/logout", status_code=204, dependencies=[Depends(validate_origin)])
def logout(
    response: Response,
    db: Session = Depends(get_db),
    current: tuple[User, UserSession] = Depends(get_current_session),
):
    _clear_session_cookie(response)
    _, session = current
    session.revoked_at = datetime.now(timezone.utc)
    db.commit()
    return Response(status_code=204)


@router.get("/me", response_model=UserResponse)
def current_user(user: User = Depends(get_current_user)):
    return user
