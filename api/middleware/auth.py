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

    @classmethod
    def _is_public(cls, path: str) -> bool:
        """
        Match a public prefix only on a path-segment boundary.

        A bare ``startswith`` would exempt any future route whose path merely begins
        with one of these strings — ``/api/v1/authorisation`` would ship unauthenticated
        because it happens to start with ``/api/v1/auth``.
        """
        return any(path == p or path.startswith(p + "/") for p in cls._SKIP_PREFIXES)

    async def __call__(self, request: Request, call_next):
        path = request.url.path
        if self._is_public(path):
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


def require_admin(request: Request) -> str:
    """
    Route dependency: reject non-admin callers.

    The WebSocket already refuses `pause_agent` / `resume_agent` / `run_agent` from a
    non-admin role, but the equivalent REST routes accepted any authenticated token —
    so an analyst locked out of the dashboard buttons could pause the whole mesh with
    one `curl`. Reads the role AuthMiddleware put on the request.
    """
    role = getattr(request.state, "role", None)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if role != _ROLES["admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Role '{role}' may not perform this action",
        )
    return role


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
