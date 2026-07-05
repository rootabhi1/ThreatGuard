# ThreatGuard — developer shortcuts.
# The application lives in threat-modeler/; these targets operate there.
.PHONY: help setup dev test lint clean

APP := threat-modeler
PY  := $(APP)/.venv/bin/python
PIP := $(APP)/.venv/bin/pip
RUFF := $(APP)/.venv/bin/ruff

help:
	@echo "make setup   Create a virtualenv and install dependencies"
	@echo "make dev     Run the app on http://localhost:8000 (dev defaults)"
	@echo "make test    Run all test suites"
	@echo "make lint    Run ruff"
	@echo "make clean   Remove the virtualenv and local databases"

setup:
	cd $(APP) && python3 -m venv .venv
	$(PIP) install -q --upgrade pip
	$(PIP) install -q -r $(APP)/requirements.txt ruff
	@echo "✓ Setup complete. Run 'make dev' to start, or 'make test'."

dev:
	cd $(APP) && ./run.sh

test:
	@cd $(APP) && JWT_SECRET=test INITIAL_ADMIN_EMAIL=admin@corp.io \
	  INITIAL_ADMIN_PASSWORD=AdminPass123! RATE_LIMIT_ENABLED=0 \
	  sh -c 'fail=0; for t in tests/test_*.py; do echo "== $$t =="; rm -f /tmp/mk.db; \
	    THREAT_MODELER_DB=/tmp/mk.db .venv/bin/python "$$t" || fail=1; done; exit $$fail'

lint:
	$(RUFF) check $(APP)

clean:
	rm -rf $(APP)/.venv $(APP)/data/*.db
	@echo "✓ Cleaned."
