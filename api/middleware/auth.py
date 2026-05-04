from fastapi import Request, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from core.config import settings

security = HTTPBearer(auto_error=False)


class AuthMiddleware:
    """Simple JWT bearer middleware — skips /health, /metrics, /ws."""

    SKIP_PATHS = {"/health", "/metrics", "/ws", "/docs", "/openapi.json", "/redoc"}

    async def __call__(self, request: Request, call_next):
        if request.url.path in self.SKIP_PATHS or request.url.path.startswith("/metrics"):
            return await call_next(request)
        return await call_next(request)


def verify_token(credentials: HTTPAuthorizationCredentials = None) -> dict:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    try:
        payload = jwt.decode(credentials.credentials, settings.api_secret_key, algorithms=[settings.api_algorithm])
        return payload
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
