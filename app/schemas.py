from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator, model_validator

from app.roles import normalize_role


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class UserOut(BaseModel):
    id: int
    email: str
    role: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserRoleUpdate(BaseModel):
    role: str = Field(description="One of: admin, manager, user, viewer")

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        return normalize_role(v).value


class AdminUserCreate(BaseModel):
    """Create a user (admin-only)."""

    email: EmailStr
    password: str = Field(min_length=8)
    role: str = Field(default="user", description="One of: admin, manager, user, viewer")

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        return normalize_role(v).value


class AdminUserUpdate(BaseModel):
    """Partial update: provide at least one field."""

    email: EmailStr | None = None
    role: str | None = None
    password: str | None = Field(default=None, min_length=8)

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return normalize_role(v).value

    @model_validator(mode="after")
    def at_least_one_field(self) -> "AdminUserUpdate":
        if self.email is None and self.role is None and self.password is None:
            raise ValueError("Provide at least one of: email, role, password")
        return self


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    sub: str | None = None


class FolderOut(BaseModel):
    id: int
    owner_id: int
    parent_id: int | None = None
    name: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FolderCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    parent_id: int | None = Field(
        default=None,
        description="Parent folder id; omit or null for a top-level folder.",
    )


class DocumentTreeSummary(BaseModel):
    id: int
    filename: str
    version: int
    upload_date: datetime


class FolderTreeNode(BaseModel):
    id: int
    owner_id: int
    parent_id: int | None
    name: str
    children: list["FolderTreeNode"]
    documents: list[DocumentTreeSummary]


class DocumentTreeResponse(BaseModel):
    owner_id: int
    roots: list[FolderTreeNode]
    orphan_documents: list[DocumentTreeSummary]




class TagOut(BaseModel):
    id: int
    owner_id: int
    name: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TagCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class CollectionOut(BaseModel):
    id: int
    owner_id: int
    name: str
    description: str | None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class CollectionCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None


class CollectionUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = None


class DocumentOut(BaseModel):
    id: int
    filename: str
    owner_id: int
    folder_id: int | None = None
    chain_config_id: int | None = None
    merkle_batch_id: int | None = None
    pending_merkle: bool = False
    tag_ids: list[int] = Field(default_factory=list)
    collection_ids: list[int] = Field(default_factory=list)
    upload_date: datetime
    storage_uri: str
    content_sha256_hex: str = Field(
        description="SHA-256 digest of the file **contents** (raw bytes). Unrelated to the filename.",
    )
    blockchain_tx_hash: str | None
    version: int
    previous_version_id: int | None
    deleted_at: datetime | None = None
    legal_hold: bool = False
    retention_expires_at: datetime | None = None
    lifecycle_state: str = Field(
        default="published",
        description="draft → review → published (workflow); legacy rows default published.",
    )

    model_config = ConfigDict(from_attributes=True)


class DocumentPermissionCreate(BaseModel):
    user_id: int
    permission: Literal["read", "write", "verify", "approve"]


class DocumentPermissionOut(BaseModel):
    id: int
    document_id: int
    user_id: int
    user_email: str | None = None
    permission: str

    model_config = ConfigDict(from_attributes=True)


class DocumentShareLinkCreate(BaseModel):
    expires_in_hours: int = Field(default=168, ge=1, le=8760)
    permission: Literal["read", "verify"]


class DocumentShareLinkOut(BaseModel):
    id: int
    document_id: int
    permission: str
    expires_at: datetime
    token: str
    share_path: str


class LifecycleTransitionBody(BaseModel):
    transition: Literal["submit_review", "approve", "reject", "unpublish"]


class DocumentSharedOut(BaseModel):
    """Public share response (no storage path)."""

    id: int
    filename: str
    owner_id: int
    version: int
    upload_date: datetime
    content_sha256_hex: str
    lifecycle_state: str


class DocumentMetadataUpdate(BaseModel):
    folder_id: int | None = None
    tag_ids: list[int] | None = Field(
        default=None,
        description="Replace all tags for this document; omit to leave unchanged.",
    )
    collection_ids: list[int] | None = Field(
        default=None,
        description="Replace all collection memberships for this document; omit to leave unchanged.",
    )
    legal_hold: bool | None = Field(
        default=None,
        description="When true, document cannot be soft-deleted until cleared.",
    )
    retention_expires_at: datetime | None = Field(
        default=None,
        description="UTC instant after which auto-retention may soft-delete (unless legal hold).",
    )


class RetentionApplyOut(BaseModel):
    soft_deleted_count: int


class DocumentListResponse(BaseModel):
    items: list[DocumentOut]
    total: int
    skip: int
    limit: int | None = Field(
        default=None,
        description="Applied page size; null means no LIMIT (all matching rows after skip).",
    )


class ActivityEventOut(BaseModel):
    """Single row for audit / activity UI (who did what, when)."""

    id: int
    created_at: datetime
    action: str
    actor_user_id: int | None = None
    actor_email: str | None = None
    document_id: int | None = None
    target_user_id: int | None = None
    target_email: str | None = None
    payload: dict | None = None


class ActivityListResponse(BaseModel):
    items: list[ActivityEventOut]
    total: int
    skip: int
    limit: int


class DocumentVerifyResult(BaseModel):
    document_id: int
    content_matches_stored_hash: bool = Field(
        description="True if SHA-256 of bytes on disk equals the hash stored for this document (content integrity).",
    )
    content_hash_matches_blockchain: bool | None = Field(
        default=None,
        description="True if on-chain proof matches the stored content hash; False if mismatch; None if chain proof unavailable.",
    )
    stored_content_sha256_hex: str | None = Field(
        default=None,
        description="SHA-256 of the content recorded at upload (from the database).",
    )
    computed_content_sha256_hex: str | None = Field(
        default=None,
        description="SHA-256 recomputed from the file bytes on disk right now (same algorithm as upload).",
    )
    notarization_configured: bool
    is_latest_version: bool
    newer_version_document_id: int | None
    message: str
    chain_id: int | None = Field(
        default=None,
        description="Resolved chain id from global settings or ChainConfig.",
    )
    merkle_batch_id: int | None = None
    merkle_root_hex: str | None = None
    merkle_root_on_chain: bool | None = None
    merkle_proof_valid: bool | None = None


class ChainConfigOut(BaseModel):
    id: int
    owner_id: int
    name: str
    rpc_url: str
    chain_id: int
    document_contract_address: str
    batch_contract_address: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ChainConfigCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    rpc_url: str = Field(min_length=1)
    chain_id: int
    document_contract_address: str = Field(min_length=42, max_length=42)
    batch_contract_address: str | None = Field(default=None, max_length=42)


class ChainConfigUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    rpc_url: str | None = None
    chain_id: int | None = None
    document_contract_address: str | None = Field(default=None, min_length=42, max_length=42)
    batch_contract_address: str | None = Field(default=None, max_length=42)


class MerkleCommitOut(BaseModel):
    batch_id: int
    merkle_root_hex: str
    tx_hash: str
    leaf_count: int


class PublicVerifyLinkOut(BaseModel):
    token: str
    expires_in_hours: int
    verify_path: str = Field(description="Relative path, e.g. /public/verify?t=...")


class PublicVerifyLinkCreate(BaseModel):
    expires_in_hours: int | None = Field(default=None, ge=1, le=8760)
