from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)


class UserOut(BaseModel):
    id: int
    email: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    sub: str | None = None


class DocumentOut(BaseModel):
    id: int
    filename: str
    owner_id: int
    upload_date: datetime
    storage_uri: str
    content_sha256_hex: str = Field(
        description="SHA-256 digest of the file **contents** (raw bytes). Unrelated to the filename.",
    )
    blockchain_tx_hash: str | None
    version: int
    previous_version_id: int | None

    model_config = ConfigDict(from_attributes=True)


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
