from __future__ import annotations

import hashlib
import hmac
import json
import os

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.config import settings
from app.core.auth import create_access_token

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=256)
    password: str = Field(..., min_length=1, max_length=1024)
    workspace: str = Field("default", min_length=1, max_length=128)


def _verify_password(password: str, stored: str) -> bool:
    # Supports pbkdf2_sha256$iterations$salt$hex_digest.
    try:
        scheme, iterations, salt, digest = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        calculated = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), int(iterations)
        ).hex()
        return hmac.compare_digest(calculated, digest)
    except (ValueError, TypeError):
        return False


def _users() -> dict:
    if not settings.AUTH_USERS_JSON:
        return {}
    try:
        users = json.loads(settings.AUTH_USERS_JSON)
        return users if isinstance(users, dict) else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError("AUTH_USERS_JSON is not valid JSON") from exc


@router.post("/token")
def token(body: LoginRequest):
    users = _users()
    # Deterministic local demo accounts are available only when DEMO_MODE is
    # explicitly enabled and no server-side user registry was supplied.
    # A configured AUTH_USERS_JSON always takes precedence; production never
    # reaches this fallback.
    dev_demo = (not settings.AUTH_USERS_JSON) and settings.DEMO_MODE and settings.ENV != "production"
    demo_users = {
        "admin": ("admin123", "admin"),
        "analyst": ("analyst123", "analyst"),
        "operator": ("operator123", "operator"),
    }
    record = users.get(body.username)
    if dev_demo and body.username in demo_users:
        record = {"password_hash": "", "role": demo_users[body.username][1], "workspace_id": "default"}
    if not isinstance(record, dict):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    password_hash = str(record.get("password_hash", ""))
    if dev_demo and body.username in demo_users:
        valid_password = hmac.compare_digest(body.password, demo_users[body.username][0])
    else:
        valid_password = _verify_password(body.password, password_hash)
    if not valid_password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    role = str(record.get("role", ""))
    workspace = str(record.get("workspace_id", record.get("workspace", "")))
    if body.workspace != workspace:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not authorized for the requested workspace")
    if role not in settings.AUTH_ROLES or not workspace:
        raise HTTPException(status_code=500, detail="Invalid server-side user configuration")

    return {
        "access_token": create_access_token(body.username, role, workspace),
        "token_type": "bearer",
        "expires_in": settings.JWT_EXPIRE_MINUTES * 60,
    }
