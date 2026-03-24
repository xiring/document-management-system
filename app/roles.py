from enum import Enum


class Role(str, Enum):
    """Stored in `users.role` as lowercase strings."""

    admin = "admin"
    manager = "manager"
    user = "user"
    viewer = "viewer"


# Role -> permission keys (see `app/permissions.py`).
ROLE_PERMISSIONS: dict[Role, frozenset[str]] = {
    Role.admin: frozenset(
        {
            "documents:read",
            "documents:read_all",
            "documents:write",
            "documents:verify",
            "users:manage",
        }
    ),
    Role.manager: frozenset(
        {
            "documents:read",
            "documents:read_all",
            "documents:write",
            "documents:verify",
        }
    ),
    Role.user: frozenset(
        {
            "documents:read",
            "documents:write",
            "documents:verify",
        }
    ),
    Role.viewer: frozenset(
        {
            "documents:read",
            "documents:verify",
        }
    ),
}


def normalize_role(value: str) -> Role:
    try:
        return Role(value.lower())
    except ValueError:
        return Role.user
