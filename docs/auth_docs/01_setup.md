# Setup Guide

## Prerequisites
- Python 3.11+
- PostgreSQL 16+
- Docker & Docker Compose

## Local Development Setup

### Step 1: Infrastructure
```bash
docker compose up -d

---

Starts:
    PostgreSQL
    Redis (reserved for future use)

Step 2: Python Environment
    python -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Step 3: Run API
    uvicorn app.main:app --reload --port 8000

Step 4: Verify
    GET /healthz
    GET /healthz/db

Environment Variables
    See app/core/config.py for authoritative definitions.
