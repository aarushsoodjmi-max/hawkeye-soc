from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel

from app.config import settings

bearer = HTTPBearer(auto_error=False)

_WWW_AUTH = {"WWW-Authenticate": "Bearer"}
_MAX_WORKSPACE_LEN = 128


class Principal(BaseModel):
    """Canonical authenticated identity.

    sub        — user id (canonical ``user_id``).
    role       — RBAC role (viewer | analyst | operator | admin).
    workspace  — canonical workspace id (canonical ``workspace_id``).
                 NEVER taken from client-supplied path/query/body values;
                 it is always derived from the verified token.
    """

    sub: str
    role: str
    workspace: str = "default"
    connection_id: str | None = None

    @property
    def user_id(self) -> str:
        return self.sub

    @property
    def workspace_id(self) -> str:
        return self.workspace


def create_access_token(
    subject: str,
    role: str = "analyst",
    workspace: str = "default",
    expires_minutes: int | None = None,
) -> str:
    if role not in settings.AUTH_ROLES:
        raise ValueError(f"Unsupported role: {role}")
    if not workspace or not workspace.strip():
        raise ValueError("workspace claim must not be empty")
    now = datetime.now(timezone.utc)
    exp = now + timedelta(minutes=expires_minutes or settings.JWT_EXPIRE_MINUTES)
    claims = {
        "sub": subject,
        "role": role,
        "workspace": workspace,
        "iat": now,
        "jti": uuid.uuid4().hex,
        "exp": exp,
    }
    if settings.JWT_ISSUER:
        claims["iss"] = settings.JWT_ISSUER
    if settings.JWT_AUDIENCE:
        claims["aud"] = settings.JWT_AUDIENCE
    return jwt.encode(
        claims,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def decode_token(token: str) -> Principal:
    """Validate and decode a bearer token.

    Rejects invalid, malformed, expired tokens and tokens carrying forged or
    missing identity claims (``sub``, ``exp``, ``role``, ``workspace`` all
    required; ``role`` must be a known RBAC role; ``workspace`` must be a
    non-empty, sane string).
    """
    try:
        decode_kwargs = {
            "algorithms": [settings.JWT_ALGORITHM],
            "options": {"require": ["sub", "exp", "role", "workspace", "iat", "jti"]},
        }
        if settings.JWT_ISSUER:
            decode_kwargs["issuer"] = settings.JWT_ISSUER
        if settings.JWT_AUDIENCE:
            decode_kwargs["audience"] = settings.JWT_AUDIENCE
        payload = jwt.decode(token, settings.JWT_SECRET, **decode_kwargs)
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers=_WWW_AUTH,
        ) from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed token",
            headers=_WWW_AUTH,
        ) from exc

    sub = payload.get("sub")
    role = payload.get("role")
    workspace = payload.get("workspace")

    if not isinstance(sub, str) or not sub.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing subject claim",
            headers=_WWW_AUTH,
        )
    if role not in settings.AUTH_ROLES:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid role claim",
            headers=_WWW_AUTH,
        )
    if (
        not isinstance(workspace, str)
        or not workspace.strip()
        or len(workspace) > _MAX_WORKSPACE_LEN
        or "\x00" in workspace
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid workspace claim",
            headers=_WWW_AUTH,
        )
    if not isinstance(payload.get("iat"), (int, float)) or payload["iat"] > datetime.now(timezone.utc).timestamp() + 30:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid iat claim", headers=_WWW_AUTH)
    if not isinstance(payload.get("jti"), str) or not payload["jti"].strip():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid jti claim", headers=_WWW_AUTH)

    principal = Principal(sub=sub, role=role, workspace=workspace)
    # Bind canonical identity to request context; downstream services/repositories
    # use this for observability and audit correlation, never for authorization.
    try:
        from app.core.request_context import workspace_id_var
        workspace_id_var.set(workspace)
    except Exception:
        pass
    return principal


def current_principal(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> Principal:
    if credentials is None:
        if settings.AUTH_REQUIRED or settings.ENV == "production":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bearer token required",
                headers=_WWW_AUTH,
            )
        # Development-only compatibility. Production cannot reach this branch:
        # AUTH_REQUIRED defaults to true (and cannot be disabled) there.
        return Principal(sub="dev-user", role="admin", workspace="default")
    return decode_token(credentials.credentials)


def require_roles(*roles: str) -> Callable:
    allowed = set(roles)

    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if principal.role not in allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{principal.role}' is not permitted",
            )
        return principal

    return dependency


def require_workspace(
    ws: str,
    principal: Principal = Depends(current_principal),
) -> Principal:
    """Defense in depth: the workspace in the URL path must equal the
    canonical workspace derived from the verified token. Client-supplied
    workspace ids are never trusted on their own."""
    if ws != principal.workspace:
        raise HTTPException(status_code=403, detail="Workspace access denied")
    return principal
