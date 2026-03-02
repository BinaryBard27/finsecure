"""
app/routers/transactions.py — Financial transaction endpoints.

POST /api/v1/transfer   — Initiate a transfer
GET  /api/v1/balance    — Check account balance
GET  /api/v1/history    — Paginated transaction history
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.fraud import analyze_transaction
from app.config import Settings, get_settings
from app.database import get_db
from app.middlewares.auth import CurrentUser, get_current_user
from app.middlewares.encrypt import Encryptor, mask_account_number
from app.models.db_models import Transaction, User
from app.models.schemas import (
    BalanceResponse,
    HistoryResponse,
    PaginationMeta,
    TransactionResponse,
    TransferRequest,
    TransferResponse,
)
from app.utils.audit import write_audit_log

router = APIRouter(prefix="/api/v1", tags=["Transactions"])


@router.post(
    "/transfer",
    response_model=TransferResponse,
    summary="Initiate a fund transfer",
)
async def transfer(
    request: Request,
    body: TransferRequest,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> TransferResponse:
    """
    Process a fund transfer with real-time fraud scoring.

    Key patterns demonstrated:
    - Idempotency: same idempotency_key → returns cached result, no double charge
    - SELECT FOR UPDATE: row-level lock prevents race conditions on balance
    - AES-256-GCM: account number encrypted before storage
    - Fraud scoring: Z-score + velocity + IP anomaly before approval
    """
    ip = request.client.host if request.client else None
    user_id = current_user.user_id

    # ── 1. Idempotency check ──────────────────────────────────────────────────
    # If we've seen this idempotency key before, return the original result.
    # Handles: client timeout + retry, double-click, network hiccup.
    existing = await db.execute(
        select(Transaction).where(Transaction.idempotency_key == body.idempotency_key)
    )
    existing_tx = existing.scalar_one_or_none()

    if existing_tx:
        logger.info(f"Duplicate request — returning cached result (key={body.idempotency_key})")
        return TransferResponse(
            transaction_id=existing_tx.id,
            status=existing_tx.status,
            fraud_score=existing_tx.fraud_score,
            fraud_signals=["Duplicate request — original result returned"],
            to_account=existing_tx.to_account_masked,
            amount_paise=existing_tx.amount_paise,
            amount_rupees=existing_tx.amount_paise / 100,
            created_at=existing_tx.created_at,
        )

    # ── 2. Load transaction history for fraud analysis ────────────────────────
    history_result = await db.execute(
        select(Transaction)
        .where(Transaction.user_id == user_id, Transaction.status == "approved")
        .order_by(Transaction.created_at.desc())
        .limit(100)  # Last 100 approved transactions
    )
    history = list(history_result.scalars().all())

    # ── 3. Fraud scoring ──────────────────────────────────────────────────────
    fraud_signal = analyze_transaction(
        history=history,
        new_amount_paise=body.amount_paise,
        new_ip=ip or "",
        max_allowed_paise=settings.max_transfer_paise,
    )

    tx_status = "flagged" if fraud_signal.total_score > settings.FRAUD_SCORE_THRESHOLD else "approved"

    # ── 4. Encrypt account number before storage ──────────────────────────────
    encryptor = Encryptor(settings.aes_key_bytes)
    encrypted_account = encryptor.encrypt(body.to_account)
    masked_account = mask_account_number(body.to_account)

    # ── 5. Atomic balance deduction with row-level lock ───────────────────────
    # The entire block below runs in a single DB transaction.
    # If anything fails, everything rolls back — no partial states.
    try:
        # SELECT FOR UPDATE locks the user row.
        # If two transfers run simultaneously, the second waits for the first
        # to commit before reading the balance. No race condition, no double-spend.
        user_result = await db.execute(
            select(User).where(User.id == user_id).with_for_update()
        )
        user = user_result.scalar_one_or_none()

        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

        # Only deduct if approved (flagged transactions are held for review)
        if tx_status == "approved":
            if user.balance_paise < body.amount_paise:
                raise HTTPException(
                    status_code=status.HTTP_402_PAYMENT_REQUIRED,
                    detail="Insufficient balance",
                )
            user.balance_paise -= body.amount_paise

        # Create transaction record
        new_tx = Transaction(
            user_id=user_id,
            amount_paise=body.amount_paise,
            to_account_encrypted=encrypted_account,
            to_account_masked=masked_account,
            type="transfer",
            status=tx_status,
            fraud_score=fraud_signal.total_score,
            idempotency_key=body.idempotency_key,
            ip_address=ip,
            reference_note=body.reference_note,
        )

        db.add(new_tx)
        await db.flush()  # Assign ID to new_tx before we need it
        await db.refresh(new_tx)

        # Audit log in same transaction
        await write_audit_log(
            db=db,
            action="transfer",
            outcome=tx_status,
            user_id=user_id,
            ip_address=ip,
            user_agent=request.headers.get("user-agent"),
            details={
                "transaction_id": new_tx.id,
                "amount_paise": body.amount_paise,
                "to_account_masked": masked_account,
                "fraud_score": round(fraud_signal.total_score, 4),
                "fraud_reasons": fraud_signal.reasons,
            },
        )

    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logger.error(f"Transfer failed for user {user_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Transfer failed. Please try again.",
        )

    logger.info(
        f"Transfer processed: user={user_id} amount=₹{body.amount_paise/100:.2f} "
        f"status={tx_status} fraud_score={fraud_signal.total_score:.2f}"
    )

    return TransferResponse(
        transaction_id=new_tx.id,
        status=tx_status,
        fraud_score=round(fraud_signal.total_score, 4),
        fraud_signals=fraud_signal.reasons,
        to_account=masked_account,
        amount_paise=body.amount_paise,
        amount_rupees=body.amount_paise / 100,
        created_at=new_tx.created_at,
    )


@router.get(
    "/balance",
    response_model=BalanceResponse,
    summary="Get account balance",
)
async def get_balance(
    request: Request,
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> BalanceResponse:
    """Return the current account balance."""
    result = await db.execute(select(User).where(User.id == current_user.user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Audit log balance check (compliance requirement)
    await write_audit_log(
        db=db,
        action="balance_check",
        outcome="success",
        user_id=current_user.user_id,
        ip_address=request.client.host if request.client else None,
        details={},
    )

    return BalanceResponse(
        balance_paise=user.balance_paise,
        balance_rupees=user.balance_paise / 100,
        currency="INR",
    )


@router.get(
    "/history",
    response_model=HistoryResponse,
    summary="Get paginated transaction history",
)
async def get_history(
    current_user: CurrentUser = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),  # Cap at 100 per page
    status_filter: str | None = Query(default=None, alias="status"),
) -> HistoryResponse:
    """
    Return paginated transaction history.
    Optional ?status=flagged to filter by status.
    """
    user_id = current_user.user_id
    offset = (page - 1) * limit

    # Build query
    query = select(Transaction).where(Transaction.user_id == user_id)

    if status_filter:
        query = query.where(Transaction.status == status_filter)

    # Total count for pagination metadata
    count_result = await db.execute(
        select(func.count()).select_from(query.subquery())
    )
    total = count_result.scalar_one()

    # Paginated results
    result = await db.execute(
        query.order_by(Transaction.created_at.desc()).offset(offset).limit(limit)
    )
    transactions = list(result.scalars().all())

    # Map to response schema — never return raw DB models
    tx_responses = [
        TransactionResponse(
            id=tx.id,
            amount_paise=tx.amount_paise,
            amount_rupees=tx.amount_paise / 100,
            to_account=tx.to_account_masked,   # Masked only
            type=tx.type,
            status=tx.status,
            fraud_score=tx.fraud_score,
            reference_note=tx.reference_note,
            created_at=tx.created_at,
        )
        for tx in transactions
    ]

    return HistoryResponse(
        transactions=tx_responses,
        pagination=PaginationMeta(
            page=page,
            limit=limit,
            total=total,
            total_pages=(total + limit - 1) // limit,
        ),
    )
