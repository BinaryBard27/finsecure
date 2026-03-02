"""
app/routers/auth.py — Authentication endpoints.

POST /api/v1/register  — Create a new user account
POST /api/v1/login     — Authenticate and get JWT token
"""
from fastapi import APIRouter, Depends, HTTPException, Request, status
from loguru import logger
from sqlalchemy import select
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
    Create a new user account.

    - Checks for duplicate username/email
    - Hashes password with bcrypt (cost 12)
    - Creates user with demo balance of ₹10,000
    """
    # Check if username already exists
    existing_user = await db.execute(
        select(User).where(User.username == body.username)
    )
    if existing_user.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken",
        )

    # Check if email already exists
    existing_email = await db.execute(
        select(User).where(User.email == body.email)
    )
    if existing_email.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Create user with hashed password
    new_user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
    )

    db.add(new_user)
    await db.flush()
    await db.refresh(new_user)

    # Audit log
    await write_audit_log(
        db=db,
        action="register",
        outcome="success",
        user_id=new_user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        details={"username": body.username},
    )

    logger.info(f"New user registered: {body.username} (id={new_user.id})")

    return RegisterResponse(
        message="Registration successful",
        user_id=new_user.id,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Login and get JWT token",
)
async def login(
    request: Request,
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> LoginResponse:
    """
    Authenticate user and return JWT access token.

    - Verifies username exists
    - Checks password against bcrypt hash
    - Returns signed JWT with user info
    """
    # Find user by username
    result = await db.execute(
        select(User).where(User.username == body.username)
    )
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        # Audit failed login attempt
        await write_audit_log(
            db=db,
            action="login",
            outcome="failure",
            user_id=user.id if user else None,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            details={"username": body.username, "reason": "invalid_credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    # Generate JWT token
    token = create_access_token(
        user_id=user.id,
        username=user.username,
        settings=settings,
    )

    # Audit successful login
    await write_audit_log(
        db=db,
        action="login",
        outcome="success",
        user_id=user.id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    logger.info(f"User logged in: {user.username}")

    return LoginResponse(
        token=token,
        user=UserPublic.model_validate(user),
    )
