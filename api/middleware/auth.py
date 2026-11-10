import time
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import Request, HTTPException, status, Depends
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

from core.config import settings
from core.database import redis_client

log = structlog.get_logger()

security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

_ROLES = {"admin": "admin", "analyst": "analyst"}

# Methods that cannot change state. Everything else under /api/v1 is admin-only.
SAFE_METHODS = ("GET", "HEAD", "OPTIONS")

# Demo passwords that ALLOW_INSECURE_DEFAULTS=true restores when none is configured.
_DEMO_FALLBACK = {"admin": "admin123", "analyst": "analyst123"}


def _demo_users() -> dict[str, str]:
    """
    Hash the configured accounts.

    An account whose password is unset, shorter than 8 characters or one of the
    values shipped in this repo is *disabled* rather than served: anyone who has
    read the README could otherwise sign in as admin. ALLOW_INSECURE_DEFAULTS=true
    restores the old demo credentials for a local, single-user setup.
    """
    users: dict[str, str] = {}
    accounts = (
        ("admin", settings.admin_username, settings.admin_password),
        ("analyst", settings.analyst_username, settings.analyst_password),
    )
    for role, username, password in accounts:
        if settings.allow_insecure_defaults:
            password = password or _DEMO_FALLBACK[role]
        elif settings.insecure_password(password):
            log.error(
                "auth.account_disabled", username=username, role=role,
                reason=f"{role.upper()}_PASSWORD is unset, shorter than 8 characters or a "
                       "known default — set it in .env (or ALLOW_INSECURE_DEFAULTS=true for "
                       "a local demo)",
            )
            continue
        users[username] = pwd_context.hash(password)
    return users


_USER_CACHE: dict[str, str] | None = None
# Verified against when the username is unknown, so a miss costs the same bcrypt
# work as a hit and response timing does not reveal which usernames exist.
_DUMMY_HASH: str | None = None


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


async def _over_write_limit(user: str) -> bool:
    """Fixed one-minute window per user. Fails open if Redis is unreachable."""
    limit = int(settings.api_write_rate_limit_per_minute or 0)
    if limit <= 0:
        return False
    window = int(time.time() // 60)
    try:
        count = await redis_client.cache.incr_window(f"ratelimit:write:{user}:{window}", ttl=120)
    except Exception as exc:
        log.warning("ratelimit.unavailable", error=str(exc))
        return False
    return count > limit


class AuthMiddleware:
    """
    JWT bearer middleware for /api/v1/*.

    * every route needs a valid token;
    * the analyst role is read-only — any state-changing method needs admin;
    * state-changing calls are rate limited per user (they mostly fan out to LLM work).
    """

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
            user = claims.get("sub")
            role = claims.get("role", "analyst")
            if not user:
                return _unauthorized("Token has no subject")
            # Expose the caller to downstream handlers.
            request.state.user = user
            request.state.role = role

            if request.method.upper() not in SAFE_METHODS:
                if role != _ROLES["admin"]:
                    return JSONResponse(
                        status_code=status.HTTP_403_FORBIDDEN,
                        content={"detail": f"Role '{role}' is read-only and may not perform this action"},
                    )
                if await _over_write_limit(user):
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "Rate limit exceeded for state-changing requests"},
                        headers={"Retry-After": "60"},
                    )

        return await call_next(request)


def require_admin(request: Request) -> str:
    """
    Route dependency: reject non-admin callers.

    AuthMiddleware already refuses non-admin writes; this stays on the override routes
    as a second, route-local guard. Reads the role AuthMiddleware put on the request.
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
    global _DUMMY_HASH
    hashed = _users().get(username)
    if not hashed:
        if _DUMMY_HASH is None:
            _DUMMY_HASH = pwd_context.hash("timing-equaliser")
        try:
            pwd_context.verify(password, _DUMMY_HASH)
        except ValueError:
            pass
        return False
    try:
        return bool(pwd_context.verify(password, hashed))
    except ValueError:
        return False


def role_for(username: str) -> str:
    if username == settings.admin_username:
        return _ROLES["admin"]
    return _ROLES["analyst"]


# ── Login throttling ─────────────────────────────────────────────────────────

def _login_key(username: str, client_ip: str) -> str:
    # Keyed on the pair so one attacker cannot lock the real admin out from elsewhere.
    return f"login_fail:{username}:{client_ip}"


async def login_locked(username: str, client_ip: str) -> bool:
    try:
        count = await redis_client.cache.get(_login_key(username, client_ip))
    except Exception:
        return False
    try:
        return int(count or 0) >= settings.login_max_failures
    except (TypeError, ValueError):
        return False


async def record_login_failure(username: str, client_ip: str) -> None:
    try:
        await redis_client.cache.incr_window(_login_key(username, client_ip), ttl=settings.login_lockout_seconds)
    except Exception as exc:
        log.warning("auth.lockout_unavailable", error=str(exc))


async def clear_login_failures(username: str, client_ip: str) -> None:
    try:
        await redis_client.cache.delete(_login_key(username, client_ip))
    except Exception:
        pass
