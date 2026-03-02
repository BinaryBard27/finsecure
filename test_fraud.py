"""
tests/test_fraud.py — Unit tests for the fraud detection engine.

These test the statistical logic directly — no DB, no HTTP.
Fast, isolated, reliable.
"""
from datetime import datetime, timedelta, timezone

import pytest

from app.ai.fraud import FraudSignal, analyze_transaction, _calculate_amount_z_score
from app.models.db_models import Transaction


def make_transaction(
    amount_paise: int,
    ip: str = "1.2.3.4",
    hours_ago: int = 0,
    status: str = "approved",
) -> Transaction:
    """Helper to create Transaction objects for testing."""
    tx = Transaction()
    tx.amount_paise = amount_paise
    tx.ip_address = ip
    tx.status = status
    tx.created_at = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    tx.idempotency_key = f"test-{amount_paise}-{hours_ago}"
    return tx


# ── Amount Z-score tests ──────────────────────────────────────────────────────

def test_z_score_returns_zero_with_insufficient_history():
    """Need at least 5 transactions for a meaningful baseline."""
    history = [make_transaction(10_000) for _ in range(4)]  # Only 4
    score = _calculate_amount_z_score(history, 10_000)
    assert score == 0.0


def test_z_score_normal_amount_scores_low():
    """Amount consistent with history should have a low Z-score."""
    # User consistently transfers ₹100 (10,000 paise)
    history = [make_transaction(10_000) for _ in range(10)]
    score = _calculate_amount_z_score(history, 10_000)
    assert score == 0.0  # Exactly the mean — z-score of 0


def test_z_score_unusual_amount_scores_high():
    """Amount way above history should have a high Z-score."""
    # Realistic varied history around ₹100 (with natural variation)
    amounts = [8_000, 9_000, 10_000, 11_000, 12_000, 9_500, 10_500, 8_500, 11_500, 10_000]
    history = [make_transaction(a) for a in amounts]
    # Suddenly ₹50,000 — extremely suspicious vs ₹80-120 history
    score = _calculate_amount_z_score(history, 5_000_000)
    assert score > 3.0


def test_z_score_handles_identical_history():
    """When all historical amounts are identical, std dev = 0. No division by zero."""
    history = [make_transaction(10_000) for _ in range(10)]
    # Different amount with identical history
    score = _calculate_amount_z_score(history, 20_000)
    assert score == 1.5  # Mild flag
    # Same amount
    score_same = _calculate_amount_z_score(history, 10_000)
    assert score_same == 0.0


# ── Full fraud analysis tests ─────────────────────────────────────────────────

def test_new_user_no_history_gets_low_score():
    """New user with no history should not be flagged."""
    signal = analyze_transaction(
        history=[],
        new_amount_paise=10_000,
        new_ip="1.2.3.4",
        max_allowed_paise=50_000_000,
    )
    assert signal.total_score < 2.5
    assert signal.large_amount_flag is False


def test_normal_transaction_approved():
    """Normal transaction consistent with history should score low."""
    history = [make_transaction(10_000) for _ in range(10)]
    signal = analyze_transaction(
        history=history,
        new_amount_paise=12_000,
        new_ip="1.2.3.4",  # Same IP as history
        max_allowed_paise=50_000_000,
    )
    assert signal.total_score < 2.5


def test_over_limit_transaction_gets_hard_boost():
    """Transaction over max limit should always get a high score."""
    signal = analyze_transaction(
        history=[],
        new_amount_paise=60_000_000,  # ₹60,000
        new_ip="1.2.3.4",
        max_allowed_paise=50_000_000,  # Max ₹50,000
    )
    assert signal.large_amount_flag is True
    assert signal.total_score >= 3.0
    assert any("exceeds maximum" in r for r in signal.reasons)


def test_new_ip_raises_score():
    """Transaction from a new IP with existing history raises score."""
    history = [make_transaction(10_000, ip="1.2.3.4") for _ in range(5)]
    signal = analyze_transaction(
        history=history,
        new_amount_paise=10_000,
        new_ip="9.9.9.9",  # Never seen before
        max_allowed_paise=50_000_000,
    )
    assert signal.ip_anomaly_score > 0
    assert any("new IP" in r for r in signal.reasons)


def test_high_velocity_raises_score():
    """5+ transactions in 1 hour should raise velocity score."""
    # All 6 transactions in the last 30 minutes
    history = [make_transaction(10_000, hours_ago=0) for _ in range(6)]
    signal = analyze_transaction(
        history=history,
        new_amount_paise=10_000,
        new_ip="1.2.3.4",
        max_allowed_paise=50_000_000,
    )
    assert signal.velocity_score > 0
    assert any("velocity" in r.lower() for r in signal.reasons)


def test_score_is_capped_at_10():
    """Total score should never exceed 10.0."""
    # Worst case: huge amount, high velocity, new IP, over limit
    history = [make_transaction(10_000, ip="1.2.3.4", hours_ago=0) for _ in range(10)]
    signal = analyze_transaction(
        history=history,
        new_amount_paise=999_999_999,
        new_ip="9.9.9.9",
        max_allowed_paise=10_000,
    )
    assert signal.total_score <= 10.0


def test_fraud_signal_has_reasons_when_flagged():
    """Flagged transactions must have human-readable reasons for audit logs."""
    signal = analyze_transaction(
        history=[],
        new_amount_paise=999_999_999,
        new_ip="1.2.3.4",
        max_allowed_paise=10_000,
    )
    assert len(signal.reasons) > 0
    assert all(isinstance(r, str) for r in signal.reasons)
