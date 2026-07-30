from datetime import datetime, timedelta, timezone

from fastapi import Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

from core.config import settings

security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Demo credentials, sourced from settings so they can be overridden in .env.
# Replace `_demo_users()` with a real user table for anything beyond a demo.
_ROLES = {"admin": "admin", "analyst": "analyst"}


def _demo_users() -> dict[str, str]:
    return {
        settings.admin_username: pwd_context.hash(settings.admin_password),
        settings.analyst_username: pwd_context.hash(settings.analyst_password),
    }


_USER_CACHE: dict[str, str] | None = None


def _users() -> dict[str, str]:
    """Hashing with bcrypt is deliberately slow, so hash each demo user only once."""
    global _USER_CACHE
    if _USER_CACHE is None:
        _USER_CACHE = _demo_users()
    return _USER_CACHE


def reset_user_cache() -> None:
    """Drop the cached password hashes (used after changing credentials in tests)."""
    global _USER_CACHE
    _USER_CACHE = None


def _unauthorized(detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_401_UNAUTHORIZED,
        content={"detail": detail},
        headers={"WWW-Authenticate": "Bearer"},
    )


class AuthMiddleware:
    """JWT bearer middleware — enforces auth on all /api/v1/* routes."""

    _SKIP_PREFIXES = (
        "/health", "/metrics", "/ws", "/docs", "/openapi.json", "/redoc", "/api/v1/auth",
    )

    async def __call__(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in self._SKIP_PREFIXES):
            return await call_next(request)

        if path.startswith("/api/v1/"):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return _unauthorized("Missing or invalid Authorization header")
            token = auth_header.removeprefix("Bearer ").strip()
            try:
                claims = jwt.decode(
                    token, settings.api_secret_key, algorithms=[settings.api_algorithm]
                )
            except JWTError:
                return _unauthorized("Invalid or expired token")
            # Expose the caller to downstream handlers.
            request.state.user = claims.get("sub")
            request.state.role = claims.get("role", "analyst")

        return await call_next(request)


def create_access_token(subject: str, role: str = "analyst") -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.api_access_token_expire_minutes)
    return jwt.encode(
        {"sub": subject, "role": role, "exp": expire},
        settings.api_secret_key,
        algorithm=settings.api_algorithm,
    )


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        return jwt.decode(
            credentials.credentials, settings.api_secret_key, algorithms=[settings.api_algorithm]
        )
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def authenticate_user(username: str, password: str) -> bool:
    hashed = _users().get(username)
    if not hashed:
        return False
    try:
        return bool(pwd_context.verify(password, hashed))
    except ValueError:
        return False


def role_for(username: str) -> str:
    if username == settings.admin_username:
        return _ROLES["admin"]
    return _ROLES["analyst"]
