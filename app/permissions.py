from typing import Annotated

from fastapi import Depends, HTTPException, status

from app.models import User
from app.roles import ROLE_PERMISSIONS, Role, normalize_role
from app.auth import get_current_user


def permissions_for(user: User) -> frozenset[str]:
    role = normalize_role(user.role)
    return ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS[Role.user])


def has_permission(user: User, permission: str) -> bool:
    return permission in permissions_for(user)


class RequirePermission:
    """FastAPI dependency: current user must have the given permission."""

    def __init__(self, permission: str) -> None:
        self.permission = permission

    def __call__(self, user: Annotated[User, Depends(get_current_user)]) -> User:
        if not has_permission(user, self.permission):
            hint = (
                " Your account needs the admin role (set BOOTSTRAP_ADMIN_EMAIL to your email and restart, or update users.role in the database)."
                if self.permission == "users:manage"
                else ""
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing permission: {self.permission}.{hint}",
            )
        return user
