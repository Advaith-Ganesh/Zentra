# =============================================================================
# Zentra — developer commands
# =============================================================================
# Run `make help` for the list.
# =============================================================================

.DEFAULT_GOAL := help
SHELL := /bin/bash

API_DIR  := apps/api
WEB_DIR  := apps/web
VENV     := $(API_DIR)/.venv
PY       := $(VENV)/bin/python
PIP      := $(VENV)/bin/pip

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}'

# ----------------------------------------------------------------------- setup
.PHONY: setup
setup: setup-api setup-web env ## Install everything a new developer needs
	@echo ""
	@echo "Setup complete. Next: make dev"

.PHONY: setup-api
setup-api: ## Create the Python virtualenv and install the API
	python3 -m venv $(VENV)
	$(PIP) install --quiet --upgrade pip
	$(PIP) install --quiet -e "$(API_DIR)[dev]"

.PHONY: setup-web
setup-web: ## Install frontend dependencies
	cd $(WEB_DIR) && npm ci --no-audit --no-fund

.PHONY: env
env: ## Create .env from .env.example if it does not exist
	@if [ ! -f .env ]; then \
	  cp .env.example .env; \
	  echo "Created .env from .env.example."; \
	  echo "Generating development secrets…"; \
	  JWT=$$(openssl rand -hex 32); \
	  KEY=$$($(PY) -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || echo ""); \
	  sed -i.bak "s|^JWT_SECRET=.*|JWT_SECRET=$$JWT|" .env; \
	  if [ -n "$$KEY" ]; then sed -i.bak "s|^SECRETS_ENCRYPTION_KEY=.*|SECRETS_ENCRYPTION_KEY=$$KEY|" .env; fi; \
	  rm -f .env.bak; \
	  echo "Wrote development JWT_SECRET and SECRETS_ENCRYPTION_KEY into .env."; \
	else \
	  echo ".env already exists; leaving it alone."; \
	fi

# ------------------------------------------------------------------- databases
.PHONY: migrate
migrate: ## Apply database migrations
	cd $(API_DIR) && .venv/bin/python -m zentra.db.migrate

.PHONY: migrate-test
migrate-test: ## Apply migrations to the test database
	cd $(API_DIR) && ENVIRONMENT=test .venv/bin/python -m zentra.db.migrate

.PHONY: seed
seed: ## Load the demo dataset (mock providers only)
	cd $(API_DIR) && .venv/bin/python -m zentra.scripts.seed

.PHONY: reseed
reseed: ## Recreate the demo dataset from scratch
	cd $(API_DIR) && .venv/bin/python -m zentra.scripts.seed --reset

# ------------------------------------------------------------------ processes
.PHONY: dev
dev: ## Run the whole stack with Docker Compose
	docker compose up --build

.PHONY: dev-api
dev-api: ## Run the API with autoreload (needs Postgres and Redis)
	cd $(API_DIR) && .venv/bin/uvicorn zentra.main:app --reload --host 0.0.0.0 --port 8000

.PHONY: dev-worker
dev-worker: ## Run the Celery worker
	cd $(API_DIR) && .venv/bin/celery -A zentra.workers.celery_app:celery_app worker --loglevel=INFO

.PHONY: dev-beat
dev-beat: ## Run the Celery scheduler
	cd $(API_DIR) && .venv/bin/celery -A zentra.workers.celery_app:celery_app beat --loglevel=INFO

.PHONY: dev-web
dev-web: ## Run the frontend dev server
	cd $(WEB_DIR) && npm run dev

.PHONY: services
services: ## Start only Postgres and Redis in Docker
	docker compose up -d postgres redis

# ----------------------------------------------------------------------- tests
.PHONY: test
test: test-api test-web ## Run every test suite

.PHONY: test-api
test-api: ## Run the backend test suite
	cd $(API_DIR) && ENVIRONMENT=test .venv/bin/pytest

.PHONY: test-api-cov
test-api-cov: ## Run the backend suite with a coverage report
	cd $(API_DIR) && ENVIRONMENT=test .venv/bin/pytest --cov=zentra --cov-report=term-missing

.PHONY: test-web
test-web: ## Run the frontend test suite
	cd $(WEB_DIR) && npm test

# ------------------------------------------------------------------- code health
.PHONY: lint
lint: lint-api lint-web ## Lint everything

.PHONY: lint-api
lint-api: ## Lint the Python code
	cd $(API_DIR) && .venv/bin/ruff check .

.PHONY: format
format: ## Auto-format the Python code
	cd $(API_DIR) && .venv/bin/ruff check --fix . && .venv/bin/ruff format .

.PHONY: lint-web
lint-web: ## Lint the frontend
	cd $(WEB_DIR) && npx eslint src

.PHONY: typecheck
typecheck: typecheck-api typecheck-web ## Type-check everything

.PHONY: typecheck-api
typecheck-api: ## Type-check the Python code
	cd $(API_DIR) && .venv/bin/mypy zentra

.PHONY: typecheck-web
typecheck-web: ## Type-check the frontend
	cd $(WEB_DIR) && npx tsc --noEmit

.PHONY: build
build: ## Production build of the frontend
	cd $(WEB_DIR) && npm run build

.PHONY: security
security: ## Static security analysis and dependency audit
	cd $(API_DIR) && .venv/bin/bandit -q -c pyproject.toml -r zentra || true
	cd $(API_DIR) && .venv/bin/pip-audit --progress-spinner off || true
	cd $(WEB_DIR) && npm audit --omit=dev || true

.PHONY: check
check: lint typecheck test build ## Everything CI runs

# ----------------------------------------------------------------------- misc
.PHONY: openapi
openapi: ## Write the OpenAPI schema to docs/openapi.json
	cd $(API_DIR) && .venv/bin/python -c "\
import json, pathlib; from zentra.main import create_app; \
pathlib.Path('../../docs/openapi.json').write_text(json.dumps(create_app().openapi(), indent=2))"
	@echo "Wrote docs/openapi.json"

.PHONY: clean
clean: ## Remove build artefacts and caches
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .mypy_cache -prune -exec rm -rf {} + 2>/dev/null || true
	rm -rf $(WEB_DIR)/.next $(WEB_DIR)/coverage $(API_DIR)/htmlcov $(API_DIR)/.coverage
	@echo "Cleaned."

.PHONY: clean-all
clean-all: clean ## Also remove installed dependencies and Docker volumes
	rm -rf $(VENV) $(WEB_DIR)/node_modules
	docker compose down -v 2>/dev/null || true
