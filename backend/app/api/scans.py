import hashlib
import hmac
import os
import shutil
import stat
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.dependencies.auth import get_current_user
from app.models import Finding, FindingDetails, Remediation, Scan, ScanMetadata, VerificationResult, User
from app.schemas.scans import (
    DecisionRequest,
    FindingsPageResponse,
    RemediationCreate,
    ScannerCatalogResponse,
    ScanDetailResponse,
    ScanHistoryResponse,
    SecurityReportResponse,
)
from app.services.ai_explainer import explain_finding
from app.services.remediation import apply_unified_diff, preview_unified_diff, suggest_fix
from app.services.security_scanner import scan_project, scanner_catalog


router = APIRouter(prefix="/api/v1/scans", tags=["Security Scans"])

_ACCURACY_STATUS = (
    "Measured accuracy is not available: no labelled evaluation dataset is configured. "
    "Fix verification rate is an operational outcome, not model accuracy."
)
_COMPLETED_VERIFICATION_STATUSES = frozenset(
    {"VERIFIED_FIXED", "STILL_PRESENT", "REGRESSION_DETECTED"}
)


def _owned_scan(db: Session, scan_id: str, user: User) -> Scan:
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.initiated_by_user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


def _workspace_root() -> Path:
    root = Path(settings.workspace_dir).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def _require_api_token(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if settings.api_token and not hmac.compare_digest(
        (x_api_key or "").encode("utf-8"), settings.api_token.encode("utf-8")
    ):
        raise HTTPException(status_code=401, detail="A valid API key is required.")


def validate_archive(archive: zipfile.ZipFile) -> list[zipfile.ZipInfo]:
    entries = archive.infolist()
    if len(entries) > settings.max_archive_files:
        raise ValueError("Archive contains too many files")
    total_size = 0
    seen_paths: set[str] = set()
    files: list[zipfile.ZipInfo] = []
    for entry in entries:
        name = entry.filename
        if not name or "\x00" in name or "\\" in name:
            raise ValueError("Invalid archive filename")
        if entry.flag_bits & 0x1:
            raise ValueError("Encrypted ZIP files are not supported")
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in (".", "..") for part in path.parts) or (path.parts and ":" in path.parts[0]):
            raise ValueError("Unsafe archive path detected")
        normalized_name = path.as_posix().rstrip("/")
        if normalized_name in seen_paths:
            raise ValueError("Duplicate archive entry detected")
        seen_paths.add(normalized_name)
        unix_mode = (entry.external_attr >> 16) & 0xFFFF
        file_type = stat.S_IFMT(unix_mode)
        if stat.S_ISLNK(unix_mode):
            raise ValueError("Symbolic links are not allowed")
        if file_type and file_type not in (stat.S_IFREG, stat.S_IFDIR):
            raise ValueError("Special archive files are not allowed")
        if entry.is_dir():
            continue
        if entry.file_size < 0 or entry.compress_size < 0:
            raise ValueError("Invalid archive entry size")
        if entry.file_size > settings.max_zip_entry_size:
            continue
        if entry.file_size > 0:
            if entry.compress_size == 0:
                raise ValueError("Suspicious archive compression")
            if entry.file_size / entry.compress_size > settings.max_compression_ratio:
                raise ValueError("Suspicious compression ratio")
        if _is_supported_file(path.name, path.suffix.lower()):
            total_size += entry.file_size
            if total_size > settings.max_extracted_size:
                raise ValueError("Extracted archive exceeds the configured size limit")
            files.append(entry)
    if not files:
        raise ValueError("No supported source or dependency manifest files found in the ZIP archive")
    return files


_SUPPORTED_SOURCE_SUFFIXES = {
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".java",
    ".go", ".rb", ".php", ".c", ".h", ".cpp", ".hpp", ".cs", ".rs", ".swift",
    ".kt", ".kts", ".scala", ".sh", ".bash", ".yaml", ".yml", ".toml", ".ini",
    ".cfg", ".conf", ".properties", ".xml", ".html", ".css", ".sql", ".tf",
    ".bicep", ".dockerfile", ".md", ".txt", ".json", ".lock",
}
_SUPPORTED_MANIFESTS = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "poetry.lock",
    "pipfile", "pipfile.lock", "setup.py", "setup.cfg", "package.json",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    ".semgrepignore", ".gitleaks.toml",
}


def _is_supported_file(filename: str, suffix: str) -> bool:
    normalized_name = filename.lower()
    return normalized_name in _SUPPORTED_MANIFESTS or suffix in _SUPPORTED_SOURCE_SUFFIXES


def _extract_archive(archive_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive_path, "r") as archive:
        entries = validate_archive(archive)
        root = destination.resolve()
        total_written = 0
        extracted_count = 0
        for entry in entries:
            relative = PurePosixPath(entry.filename)
            if entry.is_dir() or entry.file_size > settings.max_zip_entry_size or not _is_supported_file(relative.name, relative.suffix.lower()):
                continue
            output_path = (root / Path(*relative.parts)).resolve()
            if not output_path.is_relative_to(root):
                raise ValueError("Unsafe archive path detected")
            output_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            written = 0
            with archive.open(entry, "r") as source, output_path.open("xb") as output:
                while chunk := source.read(64 * 1024):
                    written += len(chunk)
                    total_written += len(chunk)
                    if written > entry.file_size or total_written > settings.max_extracted_size:
                        raise ValueError("Extracted archive exceeds the configured size limit")
                    output.write(chunk)
            if written != entry.file_size:
                raise ValueError("Archive entry size does not match its contents")
            output_path.chmod(0o600)
            extracted_count += 1
        if extracted_count == 0:
            raise ValueError("No supported source or dependency manifest files found in the ZIP archive")


def _directory_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        with path.open("rb") as source:
            while chunk := source.read(64 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def _copy_managed_workspace(source: Path, destination: Path) -> None:
    root = _workspace_root()
    source = source.resolve()
    if not source.is_relative_to(root) or not source.is_dir() or source.is_symlink():
        raise ValueError("Managed project copy is unavailable")
    total_size = 0
    file_count = 0
    for path in source.rglob("*"):
        if path.is_symlink():
            raise ValueError("Working copy contains an unsupported symbolic link")
        if path.is_file():
            file_count += 1
            total_size += path.stat().st_size
            if file_count > settings.max_archive_files or total_size > settings.max_extracted_size:
                raise ValueError("Working copy exceeds configured size limits")
    if destination.exists():
        raise ValueError("A remediation working copy already exists")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copytree(source, destination, symlinks=False, copy_function=shutil.copy2)
    for path in destination.rglob("*"):
        if path.is_file():
            path.chmod(0o600)


def _finding_payload(db: Session, finding: Finding) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "file": finding.file,
        "line": finding.line,
        "test_id": finding.test_id,
        "code": finding.code,
    }
    details = db.get(FindingDetails, finding.id)
    if details:
        payload.update(
            scanner=details.scanner,
            rule_id=details.rule_id,
            package=details.package,
            installed_version=details.installed_version,
            fixed_version=details.fixed_version,
            references=details.references or [],
            metadata=details.metadata_json or {},
            description=details.description,
            explanation=details.explanation,
            explanation_source=details.explanation_source,
        )
    return payload


def _remediation_payload(db: Session, item: Remediation) -> dict[str, Any]:
    verifications = (
        db.query(VerificationResult)
        .filter(VerificationResult.remediation_id == item.id)
        .order_by(VerificationResult.created_at.desc())
        .all()
    )
    return {
        "id": item.id,
        "finding_id": item.finding_id,
        "source_scan_id": item.source_scan_id,
        "rationale": item.rationale,
        "suggested_fix": item.suggested_fix,
        "original_code": item.original_code,
        "proposed_code": item.proposed_code,
        "affected_file": item.affected_file,
        "affected_line": item.affected_line,
        "patch_available": bool(item.patch),
        "status": item.status,
        "approved_by": item.approved_by,
        "approved_at": item.approved_at,
        "applied_scan_id": item.applied_scan_id,
        "working_copy_created": item.working_copy_path is not None,
        "created_at": item.created_at,
        "verifications": [
            {
                "id": result.id,
                "followup_scan_id": result.followup_scan_id,
                "status": result.status,
                "target_finding_present": result.target_finding_present,
                "message": result.message,
                "evidence": result.evidence or {},
                "created_at": result.created_at,
            }
            for result in verifications
        ],
    }


def _created_at_sort_key(record: Any) -> datetime:
    value = record.created_at
    if value is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def calculate_security_metrics(
    remediations: list[Remediation],
    verifications: list[VerificationResult],
) -> dict[str, Any]:
    remediation_by_id = {item.id: item for item in remediations}
    latest_completed: dict[str, VerificationResult] = {}
    regression_count = 0

    for result in sorted(verifications, key=_created_at_sort_key):
        if result.remediation_id not in remediation_by_id:
            continue
        if result.status == "REGRESSION_DETECTED":
            regression_count += 1
        if result.status in _COMPLETED_VERIFICATION_STATUSES:
            latest_completed[result.remediation_id] = result

    durations: list[float] = []
    for remediation_id, result in latest_completed.items():
        remediation = remediation_by_id[remediation_id]
        if remediation.created_at is None or result.created_at is None:
            continue
        try:
            duration = (_created_at_sort_key(result) - _created_at_sort_key(remediation)).total_seconds()
        except TypeError:
            continue
        if duration >= 0:
            durations.append(duration)

    verified_resolutions = sum(
        1
        for result in latest_completed.values()
        if result.status == "VERIFIED_FIXED" and result.target_finding_present is False
    )
    completed_verifications = len(latest_completed)
    return {
        "fix_verification_rate": (
            verified_resolutions / completed_verifications if completed_verifications else None
        ),
        "verified_resolutions": verified_resolutions,
        "completed_verifications": completed_verifications,
        "regression_count": regression_count,
        "average_remediation_seconds": (
            sum(durations) / len(durations) if durations else None
        ),
        "remediation_time_samples": len(durations),
        "accuracy_status": _ACCURACY_STATUS,
    }


def _scan_payload(db: Session, scan: Scan, include_findings: bool) -> dict[str, Any]:
    metadata = db.get(ScanMetadata, scan.id)
    payload: dict[str, Any] = {
        "scan_id": scan.id,
        "project_name": scan.project_name,
        "status": scan.status,
        "scanner": scan.scanner,
        "total_findings": scan.total_findings,
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
        "scanner_results": metadata.scanner_results if metadata else {},
    }
    if include_findings:
        findings = db.query(Finding).filter(Finding.scan_id == scan.id).order_by(Finding.id).all()
        payload["findings"] = [_finding_payload(db, finding) for finding in findings]
        remediations = (
            db.query(Remediation)
            .filter(Remediation.source_scan_id == scan.id)
            .order_by(Remediation.created_at.desc())
            .all()
        )
        payload["remediations"] = [_remediation_payload(db, item) for item in remediations]
    return payload


def _security_report(db: Session, scan: Scan) -> dict[str, Any]:
    payload = _scan_payload(db, scan, include_findings=True)
    severity_breakdown: dict[str, int] = {}
    for finding in payload["findings"]:
        severity = str(finding.get("severity") or "UNKNOWN").upper()
        severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
    remediations = (
        db.query(Remediation)
        .filter(Remediation.source_scan_id == scan.id)
        .order_by(Remediation.created_at)
        .all()
    )
    remediation_status: dict[str, int] = {}
    verification_results = []
    for item in remediations:
        remediation_status[item.status] = remediation_status.get(item.status, 0) + 1
        verification_results.extend(_remediation_payload(db, item)["verifications"])
    remediation_ids = [item.id for item in remediations]
    verification_rows = (
        db.query(VerificationResult)
        .filter(VerificationResult.remediation_id.in_(remediation_ids))
        .all()
        if remediation_ids
        else []
    )
    metrics = calculate_security_metrics(remediations, verification_rows)
    scanner_results = payload.get("scanner_results", {})
    limitations = [
        f"{name} scanner status: {result.get('status', 'unknown')}"
        for name, result in scanner_results.items()
        if result.get("status") != "completed"
    ]
    limitations.append("A completed scan is point-in-time evidence and does not prove the project is secure.")
    limitations.append(_ACCURACY_STATUS)
    return {
        "project_name": scan.project_name,
        "scan_id": scan.id,
        "scan_timestamp": scan.created_at,
        "scan_status": scan.status,
        "scanner_execution": scanner_results,
        "total_findings": scan.total_findings,
        "severity_breakdown": severity_breakdown,
        "findings": payload["findings"],
        "remediation_status": remediation_status,
        "verification_results": verification_results,
        "metrics": metrics,
        "limitations": limitations,
    }


def _run_scan(
    db: Session,
    *,
    scan_id: str,
    project_name: str,
    project_path: Path,
    source_filename: str | None,
    source_sha256: str | None = None,
    project_id: str | None = None,
    initiated_by_user_id: str | None = None,
) -> Scan:
    scan = Scan(
        id=scan_id,
        project_name=project_name[:255],
        status="running",
        scanner="pending",
        total_findings=0,
        project_id=project_id,
        initiated_by_user_id=initiated_by_user_id,
    )
    metadata = ScanMetadata(
        scan_id=scan_id,
        source_path=str(project_path.resolve()),
        source_filename=source_filename,
        source_sha256=source_sha256 or _directory_digest(project_path),
        scanner_results={},
    )
    db.add_all((scan, metadata))
    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise

    try:
        report = scan_project(
            project_path,
            timeout=settings.scanner_timeout_seconds,
            include_dependency_audits=settings.include_dependency_audits,
        )
    except Exception:
        scan.status = "failed"
        scan.scanner = "execution error"
        metadata.scanner_results = {"execution": {"status": "failed", "error": "Scanner execution failed"}}
        db.commit()
        return scan
    scan.status = report["status"]
    scan.scanner = report["scanner"][:100]
    scan.total_findings = report["total_findings"]
    metadata.scanner_results = report["scanner_results"]
    for item in report["findings"]:
        finding = Finding(
            scan_id=scan_id,
            title=str(item.get("title") or "Unknown finding")[:8000],
            severity=str(item.get("severity") or "UNKNOWN")[:20],
            confidence=str(item.get("confidence") or "UNKNOWN")[:20],
            file=str(item.get("file") or "unknown")[:8000],
            line=max(1, int(item.get("line") or 1)),
            test_id=str(item.get("test_id") or "UNKNOWN")[:20],
            code=str(item.get("code") or "")[:8000],
        )
        db.add(finding)
        db.flush()
        db.add(
            FindingDetails(
                finding_id=finding.id,
                scanner=str(item.get("scanner") or "Unknown")[:100],
                rule_id=str(item["rule_id"])[:255] if item.get("rule_id") else None,
                package=str(item["package"])[:255] if item.get("package") else None,
                installed_version=str(item["installed_version"])[:100] if item.get("installed_version") else None,
                fixed_version=str(item["fixed_version"])[:100] if item.get("fixed_version") else None,
                references=item.get("references") or [],
                metadata_json=item.get("metadata") or {},
                description=item.get("description"),
            )
        )
    try:
        db.commit()
        db.refresh(scan)
    except SQLAlchemyError:
        db.rollback()
        failed_scan = db.get(Scan, scan_id)
        if failed_scan:
            failed_scan.status = "failed"
            failed_scan.scanner = "persistence error"
            db.commit()
        raise
    return scan


@router.post("", response_model=ScanDetailResponse, status_code=201)
@router.post("/", response_model=ScanDetailResponse, status_code=201, include_in_schema=False)
@router.post("/upload", response_model=ScanDetailResponse, status_code=201)
def upload_and_scan(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
    _authorized: None = Depends(_require_api_token),
):
    if not file.filename or Path(file.filename.replace("\\", "/")).suffix.lower() != ".zip":
        raise HTTPException(status_code=400, detail="Please upload a ZIP file.")
    scan_id = str(uuid4())
    project_path = _workspace_root() / scan_id
    project_path.mkdir(mode=0o700)
    digest = hashlib.sha256()
    project_name = Path(file.filename.replace("\\", "/")).stem[:255] or "uploaded-project"
    archive_path: Path | None = None
    uploaded_size = 0
    try:
        with tempfile.NamedTemporaryFile(prefix="argus-upload-", suffix=".zip", delete=False) as archive_file:
            archive_path = Path(archive_file.name)
            while chunk := file.file.read(64 * 1024):
                uploaded_size += len(chunk)
                if uploaded_size > settings.max_upload_size:
                    raise HTTPException(status_code=413, detail="ZIP upload exceeds the configured size limit.")
                digest.update(chunk)
                archive_file.write(chunk)
        if uploaded_size == 0:
            raise HTTPException(status_code=400, detail="Uploaded ZIP file is empty.")
        if not zipfile.is_zipfile(archive_path):
            raise HTTPException(status_code=400, detail="Invalid ZIP archive.")
        _extract_archive(archive_path, project_path)
        scan = _run_scan(
            db,
            scan_id=scan_id,
            project_name=project_name,
            project_path=project_path,
            source_filename=Path(file.filename.replace("\\", "/")).name,
            source_sha256=digest.hexdigest(),
            initiated_by_user_id=user.id,
        )
        return _scan_payload(db, scan, include_findings=True)
    except HTTPException:
        shutil.rmtree(project_path, ignore_errors=True)
        raise
    except ValueError as exc:
        shutil.rmtree(project_path, ignore_errors=True)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except (zipfile.BadZipFile, OSError) as exc:
        shutil.rmtree(project_path, ignore_errors=True)
        raise HTTPException(status_code=400, detail="Unable to process the uploaded ZIP archive.") from exc
    except SQLAlchemyError as exc:
        shutil.rmtree(project_path, ignore_errors=True)
        raise HTTPException(status_code=500, detail="Failed to save scan results.") from exc
    except (RuntimeError, TimeoutError) as exc:
        raise HTTPException(status_code=500, detail="Security scan failed.") from exc
    finally:
        if archive_path:
            archive_path.unlink(missing_ok=True)
        file.file.close()


@router.get("/scanners", response_model=ScannerCatalogResponse)
def get_scanners():
    return {"items": scanner_catalog()}


@router.get("", response_model=ScanHistoryResponse)
@router.get("/", response_model=ScanHistoryResponse, include_in_schema=False)
def scan_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Scan).filter(Scan.initiated_by_user_id == user.id)
    total = query.count()
    scans = query.order_by(Scan.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return {"items": [_scan_payload(db, scan, False) for scan in scans], "page": page, "page_size": page_size, "total": total}


@router.get("/{scan_id}/findings", response_model=FindingsPageResponse)
def scan_findings(
    scan_id: str,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    severity: str | None = Query(default=None, max_length=20),
    scanner: str | None = Query(default=None, max_length=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.initiated_by_user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    query = (
        db.query(Finding)
        .outerjoin(FindingDetails, FindingDetails.finding_id == Finding.id)
        .filter(Finding.scan_id == scan_id)
    )
    if severity:
        query = query.filter(Finding.severity.ilike(severity.strip()))
    if scanner:
        query = query.filter(FindingDetails.scanner.ilike(scanner.strip()))
    total = query.distinct(Finding.id).count()
    records = query.order_by(Finding.id).offset((page - 1) * page_size).limit(page_size).all()
    return {
        "items": [_finding_payload(db, finding) for finding in records],
        "page": page,
        "page_size": page_size,
        "total": total,
    }


@router.get("/{scan_id}", response_model=ScanDetailResponse)
def scan_details(scan_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scan = _owned_scan(db, scan_id, user)
    return _scan_payload(db, scan, True)


@router.post("/{scan_id}/rescan")
def rescan_project(scan_id: str, db: Session = Depends(get_db), _authorized: None = Depends(_require_api_token)):
    source_scan = db.get(Scan, scan_id)
    metadata = db.get(ScanMetadata, scan_id)
    if not source_scan or not metadata:
        raise HTTPException(status_code=404, detail="A stored project working copy was not found for this scan.")
    root = _workspace_root()
    project_path = Path(metadata.source_path or "").resolve()
    if not project_path.is_relative_to(root) or not project_path.is_dir():
        raise HTTPException(status_code=410, detail="The stored project working copy is unavailable.")
    followup = _run_scan(
        db,
        scan_id=str(uuid4()),
        project_name=source_scan.project_name,
        project_path=project_path,
        source_filename=metadata.source_filename,
    )
    return _scan_payload(db, followup, True)


@router.post("/{scan_id}/findings/{finding_id}/explanation")
def explain_scan_finding(scan_id: str, finding_id: int, db: Session = Depends(get_db)):
    finding = db.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="Finding not found in this scan.")
    details = db.get(FindingDetails, finding_id)
    if not details:
        raise HTTPException(status_code=404, detail="Finding details are unavailable.")
    result = explain_finding(_finding_payload(db, finding))
    details.explanation = result["explanation"]
    details.explanation_source = result["source"]
    db.commit()
    return {"finding_id": finding_id, **result}


@router.post("/{scan_id}/findings/{finding_id}/remediations")
def create_remediation(
    scan_id: str,
    finding_id: int,
    request: RemediationCreate,
    db: Session = Depends(get_db),
    _authorized: None = Depends(_require_api_token),
):
    finding = db.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="Finding not found in this scan.")
    suggestion, default_rationale = suggest_fix(_finding_payload(db, finding))
    metadata = db.get(ScanMetadata, scan_id)
    if request.patch:
        if not metadata or not metadata.source_path:
            raise HTTPException(status_code=409, detail="No managed working copy is available for this scan.")
        try:
            previews = preview_unified_diff(metadata.source_path, request.patch)
        except (OSError, UnicodeError, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"Unsafe remediation patch: {exc}") from exc
    remediation = Remediation(
        id=str(uuid4()),
        finding_id=finding_id,
        source_scan_id=scan_id,
        rationale=request.rationale or default_rationale,
        suggested_fix=request.suggested_fix or suggestion,
        patch=request.patch,
        original_code=previews[0][1] if request.patch else finding.code,
        proposed_code=previews[0][2] if request.patch else None,
        affected_file=previews[0][0] if request.patch else finding.file,
        affected_line=finding.line,
        status="pending",
    )
    db.add(remediation)
    db.commit()
    db.refresh(remediation)
    return _remediation_payload(db, remediation)


def _decide_remediation(remediation_id: str, request: DecisionRequest, db: Session, status: str) -> dict[str, Any]:
    remediation = db.get(Remediation, remediation_id)
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found.")
    if remediation.status != "pending":
        raise HTTPException(status_code=409, detail="Only pending remediations can be approved or rejected.")
    remediation.status = status
    remediation.approved_by = request.approved_by.strip()[:255]
    remediation.approved_at = datetime.now(timezone.utc)
    db.commit()
    return _remediation_payload(db, remediation)


@router.post("/remediations/{remediation_id}/approve")
def approve_remediation(
    remediation_id: str,
    request: DecisionRequest,
    db: Session = Depends(get_db),
    _authorized: None = Depends(_require_api_token),
):
    return _decide_remediation(remediation_id, request, db, "approved")


@router.post("/remediations/{remediation_id}/reject")
def reject_remediation(
    remediation_id: str,
    request: DecisionRequest,
    db: Session = Depends(get_db),
    _authorized: None = Depends(_require_api_token),
):
    return _decide_remediation(remediation_id, request, db, "rejected")


@router.post("/remediations/{remediation_id}/apply")
def apply_remediation(
    remediation_id: str,
    db: Session = Depends(get_db),
    _authorized: None = Depends(_require_api_token),
):
    remediation = db.get(Remediation, remediation_id)
    if not remediation:
        raise HTTPException(status_code=404, detail="Remediation not found.")
    if remediation.status != "approved":
        raise HTTPException(status_code=409, detail="Remediation must be approved before application.")
    if not remediation.patch:
        raise HTTPException(status_code=400, detail="This remediation has no developer-supplied patch to apply.")
    source_metadata = db.get(ScanMetadata, remediation.source_scan_id)
    source_scan = db.get(Scan, remediation.source_scan_id)
    original_finding = db.get(Finding, remediation.finding_id)
    original_details = db.get(FindingDetails, remediation.finding_id)
    if not source_metadata or not source_scan or not original_finding or not original_details:
        raise HTTPException(status_code=409, detail="The original finding or working copy is unavailable.")
    root = _workspace_root()
    source_path = Path(source_metadata.source_path or "").resolve()
    if not source_path.is_relative_to(root) or not source_path.is_dir():
        raise HTTPException(status_code=410, detail="The stored project working copy is unavailable.")
    project_path = root / f"remediation-{remediation.id}"
    try:
        _copy_managed_workspace(source_path, project_path)
        changed_files = apply_unified_diff(project_path, remediation.patch)
    except (OSError, UnicodeError, ValueError) as exc:
        shutil.rmtree(project_path, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Remediation patch was not applied: {exc}") from exc

    remediation.working_copy_path = str(project_path.resolve())
    followup = _run_scan(
        db,
        scan_id=str(uuid4()),
        project_name=source_scan.project_name,
        project_path=project_path,
        source_filename=source_metadata.source_filename,
    )
    followup_metadata = db.get(ScanMetadata, followup.id)
    scanner_status = (followup_metadata.scanner_results or {}).get(original_details.scanner, {})
    original_metadata = db.get(ScanMetadata, remediation.source_scan_id)
    original_status = (original_metadata.scanner_results or {}).get(original_details.scanner, {})
    if scanner_status.get("status") != "completed" or original_status.get("status") != "completed":
        verification_status = "VERIFICATION_FAILED"
        target_present = None
        new_signatures: list[list[str]] = []
        message = f"Original and follow-up {original_details.scanner} scans must both complete; the remediation is not verified."
    else:
        baseline_findings = db.query(Finding).filter(Finding.scan_id == remediation.source_scan_id).all()
        followup_findings = db.query(Finding).filter(Finding.scan_id == followup.id).all()
        def signature(item: Finding) -> tuple[str, str, str]:
            details = db.get(FindingDetails, item.id)
            return (
                details.scanner if details else "legacy",
                item.file,
                details.rule_id if details and details.rule_id else item.test_id,
            )

        baseline_signatures = {signature(item) for item in baseline_findings}
        target_signature = signature(original_finding)
        current_signatures = {signature(item) for item in followup_findings}
        target_present = target_signature in current_signatures
        new_signatures = [list(item) for item in sorted(current_signatures - baseline_signatures)]
        if target_present:
            verification_status = "STILL_PRESENT"
            message = f"Follow-up {original_details.scanner} scan detected the target finding after the patch."
        elif new_signatures:
            verification_status = "REGRESSION_DETECTED"
            message = "Follow-up scan cleared the target finding but detected new findings not present in the baseline scan."
        else:
            verification_status = "VERIFIED_FIXED"
            message = f"Follow-up {original_details.scanner} scan completed and did not detect the target finding or new signatures."
    remediation.status = "applied"
    remediation.applied_scan_id = followup.id
    verification = VerificationResult(
        remediation_id=remediation.id,
        followup_scan_id=followup.id,
        status=verification_status,
        target_finding_present=target_present,
        message=message,
        evidence={
            "baseline_scan_id": remediation.source_scan_id,
            "followup_scan_id": followup.id,
            "scanner": original_details.scanner,
            "scanner_status": scanner_status.get("status"),
            "new_finding_signatures": new_signatures,
            "changed_files": changed_files,
        },
    )
    db.add(verification)
    db.commit()
    return {
        "remediation": _remediation_payload(db, remediation),
        "changed_files": changed_files,
        "followup_scan": _scan_payload(db, followup, True),
        "verification": {
            "status": verification_status,
            "target_finding_present": target_present,
            "message": message,
        },
    }


@router.get("/{scan_id}/report.json", response_model=SecurityReportResponse)
def scan_report_json(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return _security_report(db, scan)


@router.get("/{scan_id}/report.pdf")
def scan_report_pdf(scan_id: str, db: Session = Depends(get_db)):
    scan = db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found.")
    from app.services.pdf_report import build_scan_pdf

    content = build_scan_pdf(_security_report(db, scan))
    return Response(
        content=content,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="argus-scan-{scan_id}.pdf"'},
    )
