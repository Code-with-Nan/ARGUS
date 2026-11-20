
from datetime import datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    project_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), nullable=False)
    scanner: Mapped[str] = mapped_column(String(100), nullable=False)
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    findings = relationship(
        "Finding",
        back_populates="scan",
        cascade="all, delete-orphan",
    )
