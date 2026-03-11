.PHONY: setup up-dev up-prod down test audit logs health clean

# ── Variables ──────────────────────────────────────
COMPOSE_BASE  = docker compose -f docker-compose.yml
COMPOSE_DEV   = $(COMPOSE_BASE) -f docker-compose.dev-mac.yml --profile dev
COMPOSE_PROD  = $(COMPOSE_BASE) -f docker-compose.prod.yml

# ── Setup ──────────────────────────────────────────
setup:
	@echo "=== TARTARUS Setup ==="
	@test -f .env || (cp .env.example .env && echo "  .env created from .env.example")
	@echo "  .env ready"
	@test -d beelzebub/configurations/services || (cp -r beelzebub/configurations/services.example beelzebub/configurations/services && echo "  services/ created from services.example/ — edit YAML files to add your API keys")
	@echo "  Beelzebub services ready"
	@which pre-commit >/dev/null 2>&1 && pre-commit install || echo "  pre-commit not found (pip install pre-commit)"
	@docker compose version 2>/dev/null || echo "  WARNING: docker compose not found"
	@echo "=== Setup complete ==="

# ── Development ────────────────────────────────────
up-dev: setup
	@echo "=== Starting TARTARUS (dev) ==="
	$(COMPOSE_DEV) up --build -d
	@echo ""
	@echo "Waiting for health checks..."
	@sleep 8
	@$(MAKE) health
	@echo ""
	@echo "=== TARTARUS Dev Stack Ready ==="
	@echo "  UI:        http://localhost:8888"
	@echo "  Engine:    http://localhost:9000/health"
	@echo "  RabbitMQ:  http://localhost:15672 (guest/guest)"
	@echo "  Adminer:   http://localhost:9080"
	@echo "  SSH Trap:  ssh -p 2222 root@localhost"
	@echo "  HTTP Trap: http://localhost:8880"

# ── Production ─────────────────────────────────────
up-prod:
	@echo "=== Starting TARTARUS (prod) ==="
	$(COMPOSE_PROD) up --build -d
	@$(MAKE) health

# ── Stop ───────────────────────────────────────────
down:
	$(COMPOSE_DEV) down 2>/dev/null || $(COMPOSE_BASE) down

# ── Test ───────────────────────────────────────────
test:
	@echo "=== Running tests ==="
	cd engine && python -m pytest tests/ -v

# ── Audit ──────────────────────────────────────────
audit:
	@echo "=== TARTARUS Constraint Audit ==="
	@LINES=$$(wc -l < engine/main.py); echo "  main.py: $$LINES lines"; \
		if [ $$LINES -lt 500 ]; then echo "  C2: PASS (< 500)"; else echo "  C2: FAIL (>= 500)"; fi
	@if grep -rn --include='*.py' "import pandas\|from pandas" engine/ 2>/dev/null; then \
		echo "  C1: FAIL (pandas found)"; \
	else \
		echo "  C1: PASS (no pandas)"; \
	fi
	@echo "=== Audit complete ==="

# ── Health ─────────────────────────────────────────
health:
	@echo "=== Health Check ==="
	@$(COMPOSE_DEV) ps 2>/dev/null || $(COMPOSE_BASE) ps
	@echo ""
	@curl -sf http://localhost:9000/health 2>/dev/null && echo "" || echo "  Engine: UNREACHABLE"
	@curl -sf http://localhost:8888/ >/dev/null 2>&1 && echo "  UI: OK" || echo "  UI: UNREACHABLE"

# ── Logs ───────────────────────────────────────────
logs:
	$(COMPOSE_DEV) logs -f --tail=50

# ── Test SSH honeypot ──────────────────────────────
test-ssh:
	@echo "=== Testing SSH Honeypot ==="
	@echo "Connecting to SSH honeypot on port 2222..."
	@sshpass -p root ssh -o StrictHostKeyChecking=no -p 2222 root@localhost whoami 2>/dev/null || \
		echo "  (install sshpass for automated test, or: ssh -p 2222 root@localhost)"

# ── Test HTTP honeypot ─────────────────────────────
test-http:
	@echo "=== Testing HTTP Honeypot ==="
	@curl -s http://localhost:8880/ | head -5

# ── Clean ──────────────────────────────────────────
clean:
	$(COMPOSE_DEV) down -v --remove-orphans 2>/dev/null || true
	docker system prune -f
