from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.core.config import settings
from app.core.database import engine
from app.models import Finding, FindingDetails, Remediation, Scan, ScanMetadata, VerificationResult
from app.api.auth import router as auth_router
from app.api.scans import router as scans_router
from app.api.projects import router as projects_router
from app.schemas.scans import HealthResponse

app = FastAPI(
    title=settings.app_name,
    description="AI-powered code security and verified remediation platform.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)

app.include_router(auth_router)
app.include_router(scans_router)
app.include_router(projects_router)


@app.get("/")
def root():
    return {
        "project": "ARGUS",
        "message": "Welcome to ARGUS API",
        "status": "running",
    }


@app.get("/health")
@app.get("/api/v1/health", response_model=HealthResponse)
def health():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return {
            "status": "healthy",
            "database": "connected",
        }

    except Exception:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "database": "disconnected",
            },
        )
