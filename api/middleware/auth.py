from datetime import datetime, timedelta, timezone
from fastapi import Request, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext
from core.config import settings

security = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Demo credentials — replace with DB lookup in production
_DEMO_USERS = {
    "admin": pwd_context.hash("admin123"),
    "analyst": pwd_context.hash("analyst123"),
}


class AuthMiddleware:
    """JWT bearer middleware — enforces auth on all /api/v1/* routes."""

    _SKIP_PREFIXES = ("/health", "/metrics", "/ws", "/docs", "/openapi.json", "/redoc", "/api/v1/auth")

    async def __call__(self, request: Request, call_next):
        path = request.url.path
        if any(path.startswith(p) for p in self._SKIP_PREFIXES):
            return await call_next(request)

        if path.startswith("/api/v1/"):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Missing or invalid Authorization header"},
                    headers={"WWW-Authenticate": "Bearer"},
                )
            token = auth_header.removeprefix("Bearer ").strip()
            try:
                jwt.decode(token, settings.api_secret_key, algorithms=[settings.api_algorithm])
            except JWTError:
                from fastapi.responses import JSONResponse
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"detail": "Invalid or expired token"},
                    headers={"WWW-Authenticate": "Bearer"},
                )

        return await call_next(request)


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.api_access_token_expire_minutes)
    return jwt.encode({"sub": subject, "exp": expire}, settings.api_secret_key, algorithm=settings.api_algorithm)


def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        return jwt.decode(credentials.credentials, settings.api_secret_key, algorithms=[settings.api_algorithm])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")


def authenticate_user(username: str, password: str) -> bool:
    hashed = _DEMO_USERS.get(username)
    return bool(hashed and pwd_context.verify(password, hashed))
