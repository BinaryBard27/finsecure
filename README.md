# FinSecure API

> A production-grade financial transaction backend in Python — fraud detection, AES-256-GCM encryption, and secure API patterns used in real fintech systems.

[![CI](https://github.com/YOUR_USERNAME/finsecure-api/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/finsecure-api/actions)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What This Builds

A simulated banking API — users register, authenticate, transfer funds, and check balances. Every transaction is scored by a real-time fraud detection engine before processing.

Every design decision mirrors patterns used in production fintech:

- **`int` paise, never `float` rupees** — no rounding errors, ever (`0.1 + 0.2 ≠ 0.3` in floats)
- **AES-256-GCM encryption** for account numbers — authenticated, tamper-detectable
- **`SELECT FOR UPDATE` row lock** — eliminates the race condition that causes double-spend
- **Idempotency keys** — retrying a failed transfer never charges twice
- **Append-only audit logs** — compliance trail for every action
- **env-check integration** — config validated against schema before CI builds proceed

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                        CLIENT                             │
└──────────────────────┬───────────────────────────────────┘
                       │ HTTPS
┌──────────────────────▼───────────────────────────────────┐
│              FastAPI (uvicorn ASGI)                       │
│  SecurityHeaders → RateLimiter → JWTAuth → Router        │
└──────────────────────┬───────────────────────────────────┘
                       │
          ┌────────────┼────────────┐
          │            │            │
  ┌───────▼──┐  ┌──────▼─────┐  ┌──▼──────────┐
  │  Auth    │  │   Fraud    │  │  Encryptor  │
  │  Router  │  │   Engine   │  │  AES-256-GCM│
  └───────┬──┘  └──────┬─────┘  └──┬──────────┘
          │            │            │
┌─────────▼────────────▼────────────▼──────────┐
│              PostgreSQL (asyncpg)             │
│   users  │  transactions  │  audit_logs      │
└──────────────────────────────────────────────┘
```

### Fraud Detection Engine (`app/ai/fraud.py`)

Three weighted signals → composite score → approve or flag:

| Signal | Method | Weight |
|--------|--------|--------|
| Amount anomaly | Z-score vs user history (numpy) | 50% |
| Transaction velocity | Sliding 1h / 24h windows | 30% |
| IP address anomaly | New IP detection | 20% |
| Hard limit breach | Config ceiling | +3.0 boost |

Score > `FRAUD_SCORE_THRESHOLD` (default 2.5) → status = `flagged`.

---

## Tech Stack

| Layer | Tech | Why |
|-------|------|-----|
| Framework | FastAPI | Async, auto-docs, Pydantic validation |
| DB | PostgreSQL + SQLAlchemy 2.0 async | ACID, async, production-grade |
| Auth | python-jose (JWT HS256) | Stateless, industry standard |
| Encryption | AES-256-GCM (cryptography) | Authenticated — tamper-detectable |
| Passwords | passlib bcrypt (cost 12) | OWASP recommended |
| Rate Limiting | slowapi | Per-IP, Redis-ready |
| Validation | Pydantic v2 | Request/response schemas, type-safe |
| Logging | loguru (JSON) | Structured, ELK/Datadog compatible |
| Config Validation | env-check | Schema-enforced env validation |

---

## Quick Start

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/finsecure-api
cd finsecure-api

# 2. Install
make setup

# 3. Configure
cp .env.example .env
# Edit .env — generate secrets with:
# JWT:  openssl rand -hex 32
# AES:  openssl rand -hex 16

# 4. Validate config (env-check)
make validate-env

# 5. Run
make run
# → http://localhost:8080/docs
```

---

## API Endpoints

```
POST  /api/v1/register     Register a new user
POST  /api/v1/login        Login, receive JWT
POST  /api/v1/transfer     Initiate transfer  (auth required)
GET   /api/v1/balance      Get balance        (auth required)
GET   /api/v1/history      Transaction history (auth required)
GET   /health              Health check
```

### Example: Full Flow

```bash
# Register
curl -X POST http://localhost:8080/api/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","email":"alice@test.com","password":"SecurePass1"}'

# Login → get token
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"SecurePass1"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Transfer
curl -X POST http://localhost:8080/api/v1/transfer \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "amount_paise": 50000,
    "to_account": "9876543210",
    "reference_note": "Rent",
    "idempotency_key": "550e8400-e29b-41d4-a716-446655440000"
  }'

# Balance
curl http://localhost:8080/api/v1/balance \
  -H "Authorization: Bearer $TOKEN"
```

---

## Environment Config

Validated by [env-check](https://github.com/BinaryBard27/env-check) against `schema.json` before every CI build.

| Variable | Required | Description |
|----------|----------|-------------|
| `DATABASE_URL` | ✅ | PostgreSQL URL (must use `postgresql+asyncpg://`) |
| `JWT_SECRET_KEY` | ✅ | Min 32 chars — `openssl rand -hex 32` |
| `AES_ENCRYPTION_KEY` | ✅ | Exactly 32 chars — `openssl rand -hex 16` |
| `APP_ENV` | ✅ | `dev`, `staging`, or `prod` |
| `PORT` | ❌ | Default `8080` |
| `FRAUD_SCORE_THRESHOLD` | ❌ | Default `2.5` |
| `MAX_TRANSFER_AMOUNT` | ❌ | Default `500000` (rupees) |

---

## Key Design Decisions

**Why `int` paise instead of `float` rupees?**
`0.1 + 0.2 = 0.30000000000000004` in floating point. Every amount is stored as integer paise (₹1 = 100). No rounding errors, no lost fractions in high-volume systems.

**Why AES-GCM over AES-CBC?**
GCM provides authenticated encryption. A tampered ciphertext raises an exception on decrypt. CBC has no integrity check — you'd silently get corrupted account numbers.

**Why idempotency keys?**
Network timeouts cause clients to retry. Without idempotency, retry = double charge. Client sends a UUID per unique request; duplicate UUID → cached result, not a new transaction.

**Why `SELECT FOR UPDATE`?**
Two concurrent requests both read `balance = 10000`, both approve a ₹8000 transfer, both write `balance = 2000`. You've given away ₹16000. The row lock forces them to queue.

---

## Running Tests

```bash
make test          # All tests
make test-cover    # With HTML coverage report
make lint          # ruff + bandit security scan
```

---


## License

MIT
