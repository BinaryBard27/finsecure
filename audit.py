"""
app/utils/audit.py — Compliance audit logging.

Every significant action (login, transfer, balance check) creates
an immutable audit log entry. This is the foundation of PCI-DSS
and SOX compliance — regulators need to know who did what, when.

Audit logs are written asynchronously so they don't add latency to
API responses. If audit logging fails, we log the error but never
fail the original request — the user's action already completed.
"""
import asyncio
import json
from typing import Any

from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.db_models import AuditLog


async def write_audit_log(
    db: AsyncSession,
    action: str,
    outcome: str,
    user_id: int | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """
    Write an audit log entry to the database.

    This is called with asyncio.create_task() from route handlers so it
    runs concurrently and doesn't block the API response.

    Args:
        db:          Database session
        action:      What happened — "login", "transfer", "balance_check", etc.
        outcome:     Result — "success", "failure", "flagged"
        user_id:     Who did it (None for failed logins where user may not exist)
        ip_address:  Client IP
        user_agent:  Browser/client identifier
        details:     Dict of action-specific data (serialized to JSON)
    """
    try:
        entry = AuditLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            outcome=outcome,
            details=json.dumps(details) if details else None,
        )
        db.add(entry)
        await db.flush()  # Write to DB without full commit (parent transaction commits)

        logger.debug(
            "Audit log written",
            action=action,
            outcome=outcome,
            user_id=user_id,
        )
    except Exception as e:
        # Never let audit log failure bubble up to the caller
        # The user's actual request already succeeded
        logger.error(f"Failed to write audit log: {e}", action=action, user_id=user_id)


def create_audit_task(
    db: AsyncSession,
    action: str,
    outcome: str,
    **kwargs: Any,
) -> None:
    """
    Fire-and-forget audit log using asyncio.create_task().
    The audit log write happens concurrently with sending the response.

    Usage:
        create_audit_task(db, "transfer", "success", user_id=1, details={...})
    """
    asyncio.create_task(
        write_audit_log(db, action=action, outcome=outcome, **kwargs)
    )
