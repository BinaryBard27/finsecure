"""
app/ai/fraud.py — Real-time fraud detection engine.

Statistical anomaly detection: establish a baseline of normal behavior
for each user, then score deviations across multiple signals.

This is the same foundational approach used at Visa/Mastercard before
they layer on deep learning models. Getting the statistics right first
is more important than jumping to ML.

Signals used:
  1. Amount Z-score     — how unusual is this amount vs user history?
  2. Transaction velocity — too many transactions in a short window?
  3. IP address anomaly  — new IP address never seen before?
  4. Hard limit breach   — exceeds maximum single-transaction amount?
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import numpy as np

from app.models.db_models import Transaction


@dataclass
class FraudSignal:
    """
    Detailed fraud analysis for a transaction.

    We return the full breakdown, not just the score.
    Explainability matters in regulated finance — you need to tell
    a compliance officer WHY a transaction was flagged.
    """
    total_score: float = 0.0
    amount_z_score: float = 0.0
    velocity_score: float = 0.0
    ip_anomaly_score: float = 0.0
    large_amount_flag: bool = False
    reasons: list[str] = field(default_factory=list)


def analyze_transaction(
    history: list[Transaction],
    new_amount_paise: int,
    new_ip: str,
    max_allowed_paise: int,
) -> FraudSignal:
    """
    Score a new transaction against the user's transaction history.

    Args:
        history:           User's past approved transactions
        new_amount_paise:  Amount of this transaction (integer paise)
        new_ip:            Client IP address
        max_allowed_paise: Hard limit from config (in paise)

    Returns:
        FraudSignal with total_score and individual signal breakdown.
        Score > threshold (default 2.5) → transaction is flagged.
    """
    signal = FraudSignal()

    # ── Signal 1: Amount Z-score ──────────────────────────────────────────────
    signal.amount_z_score = _calculate_amount_z_score(history, new_amount_paise)
    if signal.amount_z_score > 3.0:
        signal.reasons.append("Amount is unusually high compared to your transaction history")

    # ── Signal 2: Transaction velocity ───────────────────────────────────────
    # Multiple transactions in a short window = account takeover pattern
    count_1h = _count_transactions_in_window(history, hours=1)
    count_24h = _count_transactions_in_window(history, hours=24)

    if count_1h >= 5:
        signal.velocity_score = count_1h * 0.5
        signal.reasons.append(
            f"High transaction velocity: {count_1h} transactions in the last hour"
        )
    elif count_24h >= 20:
        signal.velocity_score = count_24h * 0.1
        signal.reasons.append(f"Unusually high daily activity: {count_24h} transactions today")

    # ── Signal 3: IP address anomaly ─────────────────────────────────────────
    # If user has history and this IP was never seen before, add risk.
    # Production improvement: use MaxMind GeoIP to detect country-level anomalies.
    if history and new_ip:
        seen_ips = {tx.ip_address for tx in history if tx.ip_address}
        if new_ip not in seen_ips:
            signal.ip_anomaly_score = 0.8
            signal.reasons.append("Transaction from a new IP address not seen before")

    # ── Signal 4: Hard limit check ────────────────────────────────────────────
    if new_amount_paise > max_allowed_paise:
        signal.large_amount_flag = True
        signal.reasons.append(
            f"Amount ₹{new_amount_paise / 100:,.2f} exceeds maximum "
            f"single-transaction limit of ₹{max_allowed_paise / 100:,.2f}"
        )

    # ── Composite score ───────────────────────────────────────────────────────
    # Weighted sum of signals. In a production ML system, these weights
    # would be learned from labeled fraud/non-fraud transaction data.
    score = (
        signal.amount_z_score * 0.5
        + signal.velocity_score * 0.3
        + signal.ip_anomaly_score * 0.2
    )

    if signal.large_amount_flag:
        score += 3.0  # Hard boost for over-limit transactions

    signal.total_score = min(score, 10.0)  # Cap at 10 for consistent range
    return signal


def _calculate_amount_z_score(
    history: list[Transaction],
    new_amount_paise: int,
) -> float:
    """
    Z-score measures how many standard deviations a value is from the mean.
    Formula: z = |x - μ| / σ

    z > 2 → top 5% of extremes
    z > 3 → top 0.3% — very suspicious

    We need at least 5 historical transactions to establish a meaningful baseline.
    Fewer than 5 → can't distinguish anomaly from normal for a new user.
    """
    if len(history) < 5:
        return 0.0  # Insufficient history — no baseline yet

    amounts = np.array([tx.amount_paise for tx in history], dtype=np.float64)
    mean = np.mean(amounts)
    std = np.std(amounts, ddof=1)  # ddof=1 for sample std deviation

    # Guard against division by zero (all historical amounts are identical)
    if std == 0:
        # If new amount differs from the constant, flag it mildly
        return 1.5 if float(new_amount_paise) != mean else 0.0

    z_score = abs(float(new_amount_paise) - mean) / std
    return float(z_score)


def _count_transactions_in_window(
    history: list[Transaction],
    hours: int,
) -> int:
    """Count transactions that occurred within the last `hours` hours."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    return sum(
        1 for tx in history
        if tx.created_at.replace(tzinfo=timezone.utc) > cutoff
    )
