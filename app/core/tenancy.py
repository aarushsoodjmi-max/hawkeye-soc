"""Canonical tenant context resolution for HawkEye.

Every authenticated request carries exactly one tenant context
(``user_id``, ``workspace_id``, ``role``) derived from the verified token in
``app.core.auth``. Tenant identity is NEVER taken from client-supplied
workspace path/query/body values — those are only ever *compared* against the
canonical context (see ``require_workspace`` in ``app.core.auth`` and
``require_workspace_access`` below).
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException

from app.core.auth import Principal, current_principal


@dataclass(frozen=True)
class TenantContext:
    """The canonical tenant identity of an authenticated request."""

    user_id: str
    workspace_id: str
    role: str

    @classmethod
    def from_principal(cls, principal: Principal) -> "TenantContext":
        return cls(
            user_id=principal.sub,
            workspace_id=principal.workspace,
            role=principal.role,
        )


def tenant_context(
    principal: Principal = Depends(current_principal),
) -> TenantContext:
    """Dependency exposing the canonical tenant context of a request."""
    return TenantContext.from_principal(principal)


def require_workspace_access(principal: Principal, workspace_id: str) -> str:
    """Raise 403 unless the caller's canonical workspace matches ``workspace_id``."""
    if principal.workspace != workspace_id:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    return workspace_id
