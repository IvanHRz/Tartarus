#!/usr/bin/env bash
set -euo pipefail

echo "=== TARTARUS Phase 0 Verification ==="
FAILURES=0

check() {
    local name=$1 url=$2 expected=$3
    if curl -sf "$url" 2>/dev/null | grep -q "$expected"; then
        echo "  OK  $name"
    else
        echo "  FAIL  $name"
        FAILURES=$((FAILURES + 1))
    fi
}

echo ""
echo "Container status:"
docker compose -f docker-compose.yml -f docker-compose.dev-mac.yml --profile dev ps \
    --format "table {{.Name}}\t{{.Status}}" 2>/dev/null || echo "  (compose not running)"

echo ""
echo "Endpoint checks:"
check "Engine /health"  "http://localhost:9000/health" '"status":"ok"'
check "UI index"        "http://localhost:8888/"        "TARTARUS"
check "RabbitMQ Mgmt"   "http://guest:guest@localhost:15672/api/overview" "rabbitmq_version"
check "Adminer"         "http://localhost:9080/"        "adminer"

echo ""
if [ $FAILURES -eq 0 ]; then
    echo "=== ALL CHECKS PASSED ==="
else
    echo "=== $FAILURES CHECK(S) FAILED ==="
    exit 1
fi
