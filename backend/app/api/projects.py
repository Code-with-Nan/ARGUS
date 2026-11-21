from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.dependencies.auth import get_current_user
from app.models import Finding, Project, Scan, User
from app.schemas.projects import ProjectCreate, ProjectResponse, ProjectUpdate


router = APIRouter(prefix="/api/v1/projects", tags=["Projects"])


def _owned_project(db: Session, project_id: str, user: User) -> Project:
    project = db.query(Project).filter(Project.id == project_id, Project.owner_user_id == user.id).first()
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found.")
    return project


@router.post("", response_model=ProjectResponse, status_code=201)
def create_project(
    request: ProjectCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = Project(owner_user_id=user.id, name=request.name, description=request.description)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@router.get("", response_model=dict)
def list_projects(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = db.query(Project).filter(Project.owner_user_id == user.id)
    total = query.count()
    projects = query.order_by(Project.updated_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    items = []
    for project in projects:
        scan_count = db.query(func.count(Scan.id)).filter(Scan.project_id == project.id).scalar() or 0
        finding_count = (
            db.query(func.count(Finding.id))
            .join(Scan, Finding.scan_id == Scan.id)
            .filter(Scan.project_id == project.id)
            .scalar()
            or 0
        )
        items.append({**ProjectResponse.model_validate(project).model_dump(), "scan_count": scan_count, "finding_count": finding_count})
    return {"items": items, "page": page, "page_size": page_size, "total": total}


@router.get("/{project_id}", response_model=dict)
def get_project(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = _owned_project(db, project_id, user)
    scans = db.query(Scan).filter(Scan.project_id == project.id).order_by(Scan.created_at.desc()).all()
    return {
        **ProjectResponse.model_validate(project).model_dump(),
        "scans": [
            {
                "scan_id": scan.id,
                "status": scan.status,
                "total_findings": scan.total_findings,
                "created_at": scan.created_at,
                "updated_at": scan.updated_at,
            }
            for scan in scans
        ],
    }


@router.patch("/{project_id}", response_model=ProjectResponse)
def update_project(
    project_id: str,
    request: ProjectUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = _owned_project(db, project_id, user)
    if request.name is not None:
        project.name = request.name
    if request.description is not None:
        project.description = request.description
    db.commit()
    db.refresh(project)
    return project


@router.delete("/{project_id}", status_code=204)
def delete_project(
    project_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    project = _owned_project(db, project_id, user)
    if db.query(Scan).filter(Scan.project_id == project.id).first():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Delete or detach project scans before deleting the project.")
    db.delete(project)
    db.commit()
    return None
