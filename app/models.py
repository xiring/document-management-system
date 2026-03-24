from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    documents: Mapped[list["Document"]] = relationship("Document", back_populates="owner")


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    upload_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    file_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    blockchain_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    previous_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("documents.id"), nullable=True, index=True
    )

    owner: Mapped["User"] = relationship("User", back_populates="documents")
    previous_version: Mapped["Document | None"] = relationship(
        "Document", remote_side="Document.id", foreign_keys=[previous_version_id]
    )
