"""
app/middlewares/auth.py — JWT authentication.

We use python-jose for JWT handling.
Tokens are signed with HS256 (HMAC-SHA256).
For microservice-to-microservice auth, RS256 (asymmetric) is better —
noted as a prod improvement in the README.
"""
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from loguru import logger
from passlib.context import CryptContext

from app.config import Settings, get_settings

# ── Password Hashing ──────────────────────────────────────────────────────────
# bcrypt with cost factor 12 — OWASP recommended minimum.
# Higher cost = slower hash = harder brute force.
# Cost 12 takes ~300ms on a modern CPU — acceptable for login, brutal for attackers.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__rounds=12)


def hash_password(password: str) -> str:
    """Hash a password with bcrypt. Returns the hash string."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    Uses constant-time comparison internally — prevents timing attacks.
    Timing attack: if comparison short-circuits on first wrong char,
    an attacker can measure response time to guess chars one by one.
    """
    return pwd_context.verify(plain_password, hashed_password)


# ── JWT ───────────────────────────────────────────────────────────────────────

def create_access_token(
    user_id: int,
    username: str,
    settings: Settings,
) -> str:
    """
    Create a signed JWT access token.

    Payload contains minimal data — JWTs are signed but NOT encrypted.
    Anyone can base64-decode the payload. Never put sensitive data in JWT.
    """
    expire = datetime.now(timezone.utc) + timedelta(hours=settings.JWT_EXPIRE_HOURS)

    payload = {
        "sub": str(user_id),        # Subject — standard JWT claim
        "username": username,
        "exp": expire,              # Expiry — standard JWT claim
        "iat": datetime.now(timezone.utc),  # Issued at
        "iss": "finsecure-api",     # Issuer
    }

    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_access_token(token: str, settings: Settings) -> dict:
    """
    Decode and validate a JWT token.
    Raises HTTPException if token is invalid or expired.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_exp": True},  # Always verify expiry
        )
        return payload
    except JWTError as e:
        logger.warning(f"JWT validation failed: {type(e).__name__}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI Dependency ────────────────────────────────────────────────────────
# HTTPBearer extracts the token from: Authorization: Bearer <token>
bearer_scheme = HTTPBearer()


class CurrentUser:
    """Data about the authenticated user, available in route handlers."""
    def __init__(self, user_id: int, username: str) -> None:
        self.user_id = user_id
        self.username = username


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    settings: Settings = Depends(get_settings),
) -> CurrentUser:
    """
    FastAPI dependency — extracts and validates JWT from Authorization header.

    Usage in a route:
        @router.get("/balance")
        async def get_balance(current_user: CurrentUser = Depends(get_current_user)):
            user_id = current_user.user_id
    """
    payload = decode_access_token(credentials.credentials, settings)

    user_id = payload.get("sub")
    username = payload.get("username")

    if not user_id or not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    return CurrentUser(user_id=int(user_id), username=username)
