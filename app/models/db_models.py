"""
app/models/db_models.py — Database table definitions (SQLAlchemy ORM).

FINANCE RULE: Money is stored as Integer (paise), NEVER Float.
Float: 0.1 + 0.2 = 0.30000000000000004 → catastrophic in payments.
Integer: 10 + 20 = 30 → always exact.
₹100.50 = 10050 paise in the DB. The API layer divides by 100 for display.
"""
from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Money stored as Integer (paise). NEVER Float.
    # New users get ₹10,000 demo balance = 1,000,000 paise
    balance_paise: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1_000_000)

    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    kyc_verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Relationships
    transactions: Mapped[list["Transaction"]] = relationship(
        "Transaction", back_populates="user", lazy="select"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        "AuditLog", back_populates="user", lazy="select"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username}>"


class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now()
    )

    user_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=False, index=True
    )

    # Amount in paise — exact integer arithmetic
    amount_paise: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Account number encrypted with AES-256-GCM before storage
    to_account_encrypted: Mapped[str] = mapped_column(Text, nullable=False)
    # Safe to show — e.g. "******7890"
    to_account_masked: Mapped[str] = mapped_column(String(20), nullable=False)

    type: Mapped[str] = mapped_column(String(20), nullable=False)  # transfer, deposit
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    # pending → approved / flagged / rejected

    # Fraud score from the AI engine
    fraud_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Idempotency key — UUID sent by client to prevent double-spend on retry
    idempotency_key: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)

    # Never expose IP to clients — internal audit use only
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    reference_note: Mapped[str | None] = mapped_column(String(200), nullable=True)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="transactions")

    # Indexes for common query patterns
    __table_args__ = (
        Index("ix_transactions_user_status", "user_id", "status"),
        Index("ix_transactions_user_created", "user_id", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<Transaction id={self.id} user_id={self.user_id} amount={self.amount_paise}>"


class AuditLog(Base):
    """
    Append-only compliance trail. In real banks this goes to
    immutable storage (AWS S3 Object Lock / WORM drives).
    We NEVER update or delete audit logs.
    """
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, server_default=func.now()
    )

    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True, index=True
    )  # nullable for failed login attempts (user may not exist)

    action: Mapped[str] = mapped_column(String(50), nullable=False)
    # register, login, login_failed, transfer, balance_check

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(300), nullable=True)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    # success, failure, flagged

    # JSON string with action-specific data
    details: Mapped[str | None] = mapped_column(Text, nullable=True)

    user: Mapped["User | None"] = relationship("User", back_populates="audit_logs")

    def __repr__(self) -> str:
        return f"<AuditLog id={self.id} action={self.action} outcome={self.outcome}>"
