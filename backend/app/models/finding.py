
from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )

    title: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    file: Mapped[str] = mapped_column(Text, nullable=False)
    line: Mapped[int] = mapped_column(Integer, nullable=False)
    test_id: Mapped[str] = mapped_column(String(20), nullable=False)
    code: Mapped[str] = mapped_column(Text, nullable=False)

    scan = relationship("Scan", back_populates="findings")
