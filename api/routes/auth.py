import asyncio

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, Field

from api.middleware.auth import (
    authenticate_user,
    clear_login_failures,
    create_access_token,
    login_locked,
    record_login_failure,
    role_for,
    verify_token,
)
from core.config import settings

router = APIRouter()


class LoginRequest(BaseModel):
    username: str = Field(max_length=128)
    password: str = Field(max_length=256)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, body: LoginRequest):
    client_ip = _client_ip(request)
    if await login_locked(body.username, client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed sign-in attempts — try again later",
            headers={"Retry-After": str(settings.login_lockout_seconds)},
        )
    # bcrypt is CPU-bound; keep it off the event loop.
    ok = await asyncio.to_thread(authenticate_user, body.username, body.password)
    if not ok:
        await record_login_failure(body.username, client_ip)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    await clear_login_failures(body.username, client_ip)
    role = role_for(body.username)
    return TokenResponse(
        access_token=create_access_token(subject=body.username, role=role),
        expires_in=settings.api_access_token_expire_minutes * 60,
        role=role,
    )


@router.get("/me")
async def me(request: Request):
    """Echo the identity carried by the bearer token."""
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    from fastapi.security import HTTPAuthorizationCredentials
    claims = verify_token(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token))
    return {"username": claims.get("sub"), "role": claims.get("role", "analyst")}
