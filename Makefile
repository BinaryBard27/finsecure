.PHONY: help setup validate-env run test test-cover lint clean

help:
	@echo "FinSecure API (Python) — Available commands:"
	@echo ""
	@echo "  make setup         Install all dependencies"
	@echo "  make validate-env  Validate .env against schema.json (uses env-check)"
	@echo "  make run           Start the API server (validates env first)"
	@echo "  make test          Run all tests"
	@echo "  make test-cover    Run tests with HTML coverage report"
	@echo "  make lint          Run ruff linter + bandit security scanner"
	@echo "  make clean         Remove build artifacts"

setup:
	pip install -r requirements.txt
	pip install envcheck-cli ruff bandit
	@echo "✅ Setup complete"

# Validate environment using github.com/BinaryBard27/env-check
validate-env:
	@echo "🔍 Validating environment with env-check..."
	env-check --schema schema.json --env .env --strict
	@echo "✅ Environment config is valid"

# Server starts only after env-check passes
run: validate-env
	uvicorn main:app --host 0.0.0.0 --port 8080 --reload

test:
	pytest tests/ -v

test-cover:
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term-missing
	@echo "✅ Coverage report: htmlcov/index.html"

lint:
	ruff check app/ tests/
	bandit -r app/ -ll

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml .pytest_cache/
