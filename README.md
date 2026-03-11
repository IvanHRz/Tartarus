# TARTARUS — IR Deception Platform

Active defense and deception platform for Incident Response, built on [Beelzebub](https://github.com/mariocandela/beelzebub) honeypot.

## Quick Start (Mac M4)

```bash
make up-dev
```

Services:

| Service | URL |
|---------|-----|
| UI | http://localhost:8888 |
| Engine API | http://localhost:9000/health |
| RabbitMQ Management | http://localhost:15672 (guest/guest) |
| Adminer (DB) | http://localhost:9080 |
| SSH Honeypot | `ssh -p 2222 root@localhost` |

## Commands

| Command | Description |
|---------|-------------|
| `make setup` | Copy .env, install pre-commit |
| `make up-dev` | Start all 7 containers (dev ports) |
| `make up-prod` | Start production stack |
| `make down` | Stop all containers |
| `make test` | Run pytest |
| `make audit` | Check constraints (lines, no pandas) |
| `make logs` | Tail container logs |
| `make health` | Verify all services |
| `make clean` | Remove containers + volumes |

## Architecture

```
Beelzebub (honeypot) --> RabbitMQ --> Engine (FastAPI) --> PostgreSQL
                                         |
                                     WebSocket
                                         |
                                    UI (Canvas)
```

## Tech Stack

- **Honeypot**: Beelzebub (Go, LLM-powered)
- **Backend**: Python 3.12+ / FastAPI / Polars
- **Frontend**: HTML5 Canvas (no frameworks)
- **DB**: PostgreSQL 15 + Redis 7
- **Broker**: RabbitMQ 3
- **LLMs**: DeepSeek, OpenAI (via Beelzebub)
