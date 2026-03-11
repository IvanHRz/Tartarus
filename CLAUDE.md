# CLAUDE.md — TARTARUS Operational Rules

## 1. Project Context

TARTARUS is an IR (Incident Response) deception platform built on Beelzebub honeypot.
It captures attacker interactions via LLM-powered honeypots, scores risk with Sigma/YARA,
and visualizes attack patterns as a Neural Graph in real-time Canvas.

## 2. Tech Stack & Constraints

| Layer | Technology | Constraint |
|-------|-----------|------------|
| Backend | Python 3.12+, FastAPI, uvicorn | Async-first, streaming I/O |
| Data | Polars (LazyFrame) | NEVER use Pandas. All transforms vectorized. |
| Frontend | HTML5 Canvas + vanilla JS | NO frameworks: no D3, React, Vue, Cytoscape (C3) |
| Honeypot | Beelzebub (Go, Docker) | Config in beelzebub/configurations/ |
| DB | PostgreSQL 15 | asyncpg for async access |
| Cache | Redis 7 | Session state + pub/sub |
| Broker | RabbitMQ 3 | Event bus: fast (visual) + slow (forensic) paths |
| Target HW | Apple Silicon M4 | ARM64 native images only |

## 3. Hard Rules (Non-Negotiable)

- **C1**: No pandas — ever. `grep -r "import pandas" engine/` = 0 results.
- **C2**: `engine/main.py` < 500 lines. Enforced by pre-commit.
- **C3**: Canvas puro. No D3, vis.js, Cytoscape, React, Vue. HTML5 Canvas + requestAnimationFrame.
- **C4**: No Docker socket mounted in any container.
- **C5**: API keys only in `.env`. Never in code, configs, or logs.
- **C6**: Every active skill has a test in `engine/tests/`.
- **C7**: Pre-commit from the first commit. `.pre-commit-config.yaml` always active.
- **C8**: Polars LazyFrame for event streams > 1000/min.

## 4. Project Structure

```
engine/main.py          — FastAPI endpoints (< 500 lines)
engine/engine/          — Business logic modules
engine/tests/           — pytest suite
ui/src/                 — Static HTML/CSS/JS (Canvas puro)
beelzebub/configurations/ — Beelzebub YAML configs
db/init.sql             — PostgreSQL schema
```

## 5. Coding Standards

- Async-first: use `asyncio.to_thread()` for CPU-bound work
- Never fabricate timestamps — use real event data or `null`
- Never mutate original evidence metadata
- Prefer `pl.Expr` chains over `apply()`/`map_elements()`
- Backend functions in `main.py` are core — extract to `engine/engine/` when approaching limit

## 6. Session Protocol

- Read `CLAUDE.md` at session start
- Check memory files for project state
- After major changes, update memory
