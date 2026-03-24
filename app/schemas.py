from __future__ import annotations

from datetime import datetime

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

    model_config = ConfigDict(from_attributes=True)


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


class DocumentListResponse(BaseModel):
    items: list[DocumentOut]
    total: int
    skip: int
    limit: int | None = Field(
        default=None,
        description="Applied page size; null means no LIMIT (all matching rows after skip).",
    )


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
