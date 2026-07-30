from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel

from api.middleware.auth import authenticate_user, create_access_token, role_for, verify_token
from core.config import settings

router = APIRouter()


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    role: str


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest):
    if not authenticate_user(body.username, body.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    role = role_for(body.username)
    return TokenResponse(
        access_token=create_access_token(subject=body.username, role=role),
        expires_in=settings.api_access_token_expire_minutes * 60,
        role=role,
    )


@router.get("/me")
async def me(request: Request):
    """Echo the identity carried by the bearer token (populated by AuthMiddleware)."""
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    from fastapi.security import HTTPAuthorizationCredentials
    claims = verify_token(HTTPAuthorizationCredentials(scheme="Bearer", credentials=token))
    return {"username": claims.get("sub"), "role": claims.get("role", "analyst")}
