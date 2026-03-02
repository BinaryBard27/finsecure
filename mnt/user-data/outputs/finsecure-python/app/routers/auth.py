"""
app/routers/auth.py — Authentication endpoints.

POST /api/v1/register
POST /api/v1/login
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from loguru import logger
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.database import get_db
from app.middlewares.auth import create_access_token, hash_password, verify_password
from app.models.db_models import User
from app.models.schemas import (
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
    UserPublic,
)
from app.utils.audit import write_audit_log

router = APIRouter(prefix="/api/v1", tags=["Authentication"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user",
)
async def register(
    request: Request,
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> RegisterResponse:
    """
    Register a new user account.
    - Username and email must be unique
    - Password is hashed with bcrypt (cost 12) before storage
    - Plain password is NEVER stored or logged
    """
    # Check for existing username or email
    result = await db.execute(
        select(User).where(
            (User.username == body.username) | (User.email == body.email)
        )
    )
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )

    # Hash password — never store plaintext
    hashed = hash_password(body.password)

    user = User(
        username=body.username,
        email=body.email,
        password_hash=hashed,
        balance_paise=1_000_000,  # ₹10,000 demo balance
    )

    try:
        db.add(user)
        await db.flush()  # Get the auto-generated ID without committing yet
        await db.refresh(user)
    except IntegrityError:
        # Race condition: two requests tried to create same user simultaneously
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )

    # Audit log (writes to DB in same transaction)
    await write_audit_log(
        db=db,
        action="register",
        outcome="success",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={"username": user.username, "email": user.email},
    )

    logger.info(f"New user registered: {user.username} (id={user.id})")

    return RegisterResponse(message="Registration successful", user_id=user.id)


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login and receive JWT token",
)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    """
    Authenticate user and return a JWT access token.

    Security notes:
    - Same error message for "user not found" and "wrong password"
      (prevents username enumeration attacks)
    - Failed attempts are audit-logged with IP for brute force detection
    """
    ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")

    # Look up user
    result = await db.execute(select(User).where(User.username == body.username))
    user = result.scalar_one_or_none()

    # SECURITY: Return identical error for "user not found" and "wrong password"
    # Never reveal which one failed — that leaks valid usernames
    if not user or not verify_password(body.password, user.password_hash):
        await write_audit_log(
            db=db,
            action="login_failed",
            outcome="failure",
            user_id=user.id if user else None,
            ip_address=ip,
            user_agent=ua,
            details={"username": body.username, "reason": "invalid_credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled. Please contact support.",
        )

    # Generate JWT
    token = create_access_token(
        user_id=user.id,
        username=user.username,
        settings=settings,
    )

    await write_audit_log(
        db=db,
        action="login",
        outcome="success",
        user_id=user.id,
        ip_address=ip,
        user_agent=ua,
        details={},
    )

    logger.info(f"User logged in: {user.username} (id={user.id}) from {ip}")

    return LoginResponse(
        token=token,
        user=UserPublic(
            id=user.id,
            username=user.username,
            kyc_verified=user.kyc_verified,
        ),
    )
