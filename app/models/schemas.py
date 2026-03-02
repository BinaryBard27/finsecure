"""
app/models/schemas.py — Pydantic request/response schemas.

These are SEPARATE from the DB models intentionally.
Rule: Never expose SQLAlchemy models directly in API responses.
Why: DB models may have sensitive fields (password_hash, ip_address, encrypted data).
Pydantic schemas let you control exactly what goes in and out.
"""
import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


# ── Auth Schemas ──────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)
    # 72 char max because bcrypt silently truncates at 72 bytes

    @field_validator("password")
    @classmethod
    def password_must_be_strong(cls, v: str) -> str:
        """
        Basic password strength check.
        Production systems use zxcvbn for proper entropy scoring.
        """
        if v.isdigit():
            raise ValueError("Password cannot be all digits")
        if v.islower():
            raise ValueError("Password must contain at least one uppercase letter")
        return v


class RegisterResponse(BaseModel):
    message: str
    user_id: int


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    token: str
    token_type: str = "Bearer"
    expires_in: int = 86400  # seconds
    user: "UserPublic"


class UserPublic(BaseModel):
    """Safe user data — no password hash, no internal fields."""
    id: int
    username: str
    kyc_verified: bool

    model_config = {"from_attributes": True}  # Allows creating from SQLAlchemy model


# ── Transaction Schemas ───────────────────────────────────────────────────────

class TransferRequest(BaseModel):
    # Amount in paise — no floats in the API layer
    amount_paise: int = Field(gt=0, description="Amount in paise (₹1 = 100 paise)")
    to_account: str = Field(min_length=8, max_length=20)
    reference_note: str | None = Field(default=None, max_length=200)
    # UUID the client generates per unique request — prevents double-spend on retry
    idempotency_key: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    )

    @field_validator("to_account")
    @classmethod
    def account_must_be_alphanumeric(cls, v: str) -> str:
        if not v.replace("-", "").replace(" ", "").isalnum():
            raise ValueError("Account number must be alphanumeric")
        return v.strip()

    @model_validator(mode="after")
    def amount_must_be_reasonable(self) -> "TransferRequest":
        # Prevent ₹0.01 transactions that are just spam
        if self.amount_paise < 100:  # Less than ₹1
            raise ValueError("Minimum transfer amount is ₹1 (100 paise)")
        return self


class TransactionResponse(BaseModel):
    id: int
    amount_paise: int
    amount_rupees: float  # Derived for display
    to_account: str       # Masked
    type: str
    status: str
    fraud_score: float
    fraud_signals: list[str] = []
    reference_note: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class TransferResponse(BaseModel):
    transaction_id: int
    status: str
    fraud_score: float
    fraud_signals: list[str]
    to_account: str        # Masked
    amount_paise: int
    amount_rupees: float
    created_at: datetime


# ── Balance Schema ────────────────────────────────────────────────────────────

class BalanceResponse(BaseModel):
    balance_paise: int
    balance_rupees: float
    currency: str = "INR"


# ── History Schema ────────────────────────────────────────────────────────────

class PaginationMeta(BaseModel):
    page: int
    limit: int
    total: int
    total_pages: int


class HistoryResponse(BaseModel):
    transactions: list[TransactionResponse]
    pagination: PaginationMeta


# ── Error Schema ──────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    """Consistent error format across all endpoints."""
    error: str
    details: str | None = None
    status: int
