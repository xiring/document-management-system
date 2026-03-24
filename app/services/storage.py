import hashlib
import uuid
from pathlib import Path

from app.config import settings


def sha256_bytes(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def save_upload(content: bytes, original_filename: str) -> tuple[str, bytes]:
    """
    Persist file locally and return (storage_uri, SHA-256 digest of **content bytes**).
    The filename is only used for the on-disk name; the hash is always computed from `content`.
    """
    upload_root = Path(settings.upload_dir).resolve()
    upload_root.mkdir(parents=True, exist_ok=True)
    safe_name = f"{uuid.uuid4().hex}_{Path(original_filename).name}"
    dest = upload_root / safe_name
    dest.write_bytes(content)
    digest = sha256_bytes(content)
    rel = str(dest.relative_to(upload_root))
    return rel, digest


def read_stored_file(storage_uri: str) -> bytes:
    """Load bytes from a path stored in storage_uri (relative to upload_dir)."""
    path = Path(settings.upload_dir).resolve() / storage_uri
    if not path.is_file():
        raise FileNotFoundError(f"Stored file not found: {path}")
    return path.read_bytes()


def absolute_path(storage_uri: str) -> Path:
    return Path(settings.upload_dir).resolve() / storage_uri
