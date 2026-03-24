from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

document_tags = Table(
    "document_tags",
    Base.metadata,
    Column("document_id", ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)

collection_documents = Table(
    "collection_documents",
    Base.metadata,
    Column("collection_id", ForeignKey("collections.id", ondelete="CASCADE"), primary_key=True),
    Column("document_id", ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True),
)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        server_default=text("'user'"),
        default="user",
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    documents: Mapped[list["Document"]] = relationship("Document", back_populates="owner")
    folders: Mapped[list["Folder"]] = relationship("Folder", back_populates="owner")
    tags: Mapped[list["Tag"]] = relationship("Tag", back_populates="owner")
    collections: Mapped[list["Collection"]] = relationship("Collection", back_populates="owner")
    chain_configs: Mapped[list["ChainConfig"]] = relationship("ChainConfig", back_populates="owner")


class Folder(Base):
    __tablename__ = "folders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("folders.id"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner: Mapped["User"] = relationship("User", back_populates="folders")
    parent: Mapped["Folder | None"] = relationship(
        "Folder",
        remote_side="Folder.id",
        foreign_keys=[parent_id],
        back_populates="children",
    )
    children: Mapped[list["Folder"]] = relationship(
        "Folder",
        back_populates="parent",
        foreign_keys=[parent_id],
    )
    documents: Mapped[list["Document"]] = relationship("Document", back_populates="folder")


class Tag(Base):
    __tablename__ = "tags"
    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_tags_owner_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner: Mapped["User"] = relationship("User", back_populates="tags")
    documents: Mapped[list["Document"]] = relationship(
        "Document", secondary=document_tags, back_populates="tags"
    )


class Collection(Base):
    __tablename__ = "collections"
    __table_args__ = (UniqueConstraint("owner_id", "name", name="uq_collections_owner_name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner: Mapped["User"] = relationship("User", back_populates="collections")
    documents: Mapped[list["Document"]] = relationship(
        "Document", secondary=collection_documents, back_populates="collections"
    )


class ChainConfig(Base):
    """Per-tenant (owner) chain endpoints: RPC + contracts for document and batch notarization."""

    __tablename__ = "chain_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    rpc_url: Mapped[str] = mapped_column(Text, nullable=False)
    chain_id: Mapped[int] = mapped_column(Integer, nullable=False)
    document_contract_address: Mapped[str] = mapped_column(String(42), nullable=False)
    batch_contract_address: Mapped[str | None] = mapped_column(String(42), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    owner: Mapped["User"] = relationship("User", back_populates="chain_configs")
    batches: Mapped[list["MerkleBatch"]] = relationship("MerkleBatch", back_populates="chain_config")


class MerkleBatch(Base):
    """Committed Merkle root (many document hashes in one tx)."""

    __tablename__ = "merkle_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    chain_config_id: Mapped[int] = mapped_column(ForeignKey("chain_configs.id"), nullable=False, index=True)
    merkle_root: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    tx_hash: Mapped[str] = mapped_column(String(66), nullable=False)
    leaf_count: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    chain_config: Mapped["ChainConfig"] = relationship("ChainConfig", back_populates="batches")
    documents: Mapped[list["Document"]] = relationship("Document", back_populates="merkle_batch")


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)
    folder_id: Mapped[int | None] = mapped_column(ForeignKey("folders.id"), nullable=True, index=True)
    chain_config_id: Mapped[int | None] = mapped_column(ForeignKey("chain_configs.id"), nullable=True, index=True)
    merkle_batch_id: Mapped[int | None] = mapped_column(ForeignKey("merkle_batches.id"), nullable=True, index=True)
    pending_merkle: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("false"),
        default=False,
    )
    upload_date: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    storage_uri: Mapped[str] = mapped_column(Text, nullable=False)
    file_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    blockchain_tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    previous_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("documents.id"), nullable=True, index=True
    )
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    legal_hold: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("false"),
        default=False,
    )
    retention_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )

    owner: Mapped["User"] = relationship("User", back_populates="documents")
    chain_config: Mapped["ChainConfig | None"] = relationship("ChainConfig")
    merkle_batch: Mapped["MerkleBatch | None"] = relationship("MerkleBatch")
    folder: Mapped["Folder | None"] = relationship("Folder", back_populates="documents")
    tags: Mapped[list["Tag"]] = relationship("Tag", secondary=document_tags, back_populates="documents")
    collections: Mapped[list["Collection"]] = relationship(
        "Collection", secondary=collection_documents, back_populates="documents"
    )
    previous_version: Mapped["Document | None"] = relationship(
        "Document", remote_side="Document.id", foreign_keys=[previous_version_id]
    )


class ActivityEvent(Base):
    """Append-only audit / activity feed (uploads, verify, role changes, retention, etc.)."""

    __tablename__ = "activity_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    actor_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    document_id: Mapped[int | None] = mapped_column(
        ForeignKey("documents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    target_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    payload: Mapped[dict | None] = mapped_column(JSON, nullable=True)
