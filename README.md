# Hawkeye — AI-Powered Autonomous Operations Intelligence Platform

**Hawkeye Backend v4.1**

Hawkeye is an operations-intelligence backend organized around the canonical flow:

**Observe → Correlate → Predict → Decide**

The current release preserves the existing service/repository/router layering and the existing AI Gateway/Orchestrator architecture while adding release hardening for approval safety, tenant isolation, AI evidence handling, event dispatch, authentication, CORS, ingestion limits, and ML artifact integrity.

## Current architecture

1. **Observe**
   - Alert ingestion and normalization
   - Authenticated, workspace-scoped telemetry
   - Configurable batch/raw-log/description/metadata limits

2. **Correlate**
   - Temporal/entity correlation
   - Canonical incident construction
   - Knowledge Graph hydration

3. **Predict**
   - Bundled scikit-learn root-cause model
   - Threat Intelligence
   - Risk and Business Impact
   - Prediction and Confidence Engine
   - Incident Memory and Workflow Intelligence

4. **Decide**
   - Decision Engine
   - Decision Simulator
   - Playbook proposals and simulations
   - Explicit human approval before operational execution
   - Digital Twin snapshots and reporting

## AI Gateway

The AI layer is provider-neutral:

- **AI Gateway / Orchestrator** selects providers and owns integration flow.
- **GeminiProvider** calls Gemini without fallback to another provider on failure.
- **LocalProvider** uses the local inference client.
- **EvidencePackage** is the sole provider-facing evidence contract.
- Both providers receive equivalent logical evidence sections.
- Telemetry and external intelligence are explicitly treated as untrusted data.
- Model output is schema-validated and evidence-grounded.
- AI recommendations cannot execute actions or bypass approval.

The operational invariant is:

`PROPOSED → SIMULATED → PENDING_APPROVAL → APPROVED → EXECUTING → COMPLETED`

If approval is required and is not explicitly approved, the execution boundary rejects the action.

## Tenant isolation and RBAC

Authenticated principals carry:

- `user_id`
- `workspace_id`
- `role`

Workspace identity comes from the verified JWT. Request-body and query/path workspace values are never trusted for authorization.

Tenant scoping applies across incidents, alerts, assets, Knowledge Graph data, Threat Intelligence, Workflow Intelligence, Risk, Business Impact, Prediction, Confidence, Incident Memory, Decision Engine, Decision Simulator, Playbooks, Reports, Digital Twin data, AI evidence, and WebSockets.

WebSocket connections retain `connection_id`, `user_id`, `workspace_id`, `role`, and authorized topics. Broadcasts are workspace-scoped.

## Demo Login Credentials

`DEMO_MODE=true` provides three built-in local demo accounts when `AUTH_USERS_JSON` is empty. A configured `AUTH_USERS_JSON` always overrides them:

| Username   | Password       | Role       | What the role can do |
|------------|----------------|------------|-----------------------|
| `admin`    | `admin123`     | `admin`    | Full access: all workspace data, playbook/action approval and execution, and administrative configuration. |
| `analyst`  | `analyst123`   | `analyst`  | Investigative access: alerts, incidents, correlation, predictions, and AI evidence — can investigate, simulate, approve/reject, and execute playbooks in the local demo. |
| `operator` | `operator123`  | `operator` | Operational access: can investigate, simulate, approve/reject, and execute approved playbooks in the local demo. |

Log in via `POST /api/auth/token` with `{"username", "password", "workspace"}` (`workspace` is `"default"` for all three accounts), or through the frontend login screen, which calls this endpoint for you.

These are **demo-only credentials for local evaluation**. Do not reuse them on internet-facing instances. For shared or production deployment, set `DEMO_MODE=false`, generate a strong `JWT_SECRET`, and provide fresh `AUTH_USERS_JSON` hashes.

## REST and WebSocket APIs

Core endpoints include:

- `GET /health`
- `GET/POST /alerts`
- `POST /alerts/batch`
- `GET/PUT /incidents`
- `POST /incidents/{incident_id}/actions/{action_id}/execute`
- `POST /analyze`
- `POST /api/simulate`
- `GET /api/dashboard`
- `GET /api/incidents`
- `GET /api/reports`
- `GET /api/ai/health`
- `GET /api/ai/models`
- `POST /api/ai/analyze`
- `WS /ws`

The legacy action execution endpoint remains for compatibility but is secured by the same domain/repository approval invariant as every other execution path.

## ML artifact

The bundled root-cause model and dependency manifest are pinned to the same scikit-learn version (`1.8.0`). The model retains SHA-256 integrity verification.

Model health reports availability, compatibility, and failure reason explicitly. A failed model load is not presented as an active model.

## Configuration

Important settings include:

- `JWT_SECRET`
- `JWT_ALGORITHM`
- `JWT_ISSUER` / `JWT_AUDIENCE` (optional, recommended in production)
- `AUTH_REQUIRED`
- `AUTH_USERS_JSON`
- `FRONTEND_ORIGINS` / `FRONTEND_ORIGIN`
- `MAX_BATCH_SIZE`
- `MAX_RAW_LOG_CHARS`
- `MAX_DESCRIPTION_CHARS`
- `MAX_METADATA_BYTES`
- `GEMINI_API_KEY`
- `GEMINI_MODEL`

Production requires authentication, a strong JWT secret, configured user registry, and explicit CORS origins. Wildcard CORS origins are rejected when credentials are enabled.

## Requirements

- **Python 3.12.x** (the repo pins this exactly via `.python-version`; `run.sh` provisions its venv with `python3.12` explicitly). **Do not use Python 3.13+**: `numpy==1.26.4` and `pandas==2.2.2` in `requirements.txt` predate Python 3.13 and have no prebuilt wheels for it, so `pip install -r requirements.txt` on 3.13 either fails outright or falls back to a from-source build that needs a full C/Fortran toolchain not present in typical dev containers (including the `python:3.13-slim` Docker base, which is why the image now targets `python:3.12-slim`). If you must use a different interpreter, upgrade both pins to a version pair that ships 3.13 wheels — otherwise stay on 3.12.
- **Node.js 18+** and npm, for the Vite/React 19 frontend.
- **PostgreSQL 16** for anything beyond a throwaway local run — the backend's `lifespan` startup hook calls `init_db()` unconditionally and raises `RuntimeError("DATABASE_URL is required")` if `DATABASE_URL` isn't set, so the server will not boot without a database target configured (Docker Compose and `run.sh` both provision this for you).

## Setup

### Option A — one-command local run (recommended)

```bash
./run.sh
```

This provisions a local Postgres container, creates a `python3.12` venv, installs backend deps, copies `.env.example` → `.env` on first run, applies Alembic migrations, starts the backend on `http://localhost:8000`, installs frontend deps, and starts the frontend on `http://localhost:5173`. `Ctrl+C` stops both.

### Option B — Docker Compose (closest to production)

```bash
cp .env.example .env
docker compose up --build
```

Backend starts on `http://localhost:8000` after Postgres reports healthy and Alembic migrations apply; health check at `/health`.

### Option C — manual step-by-step

```bash
python3.12 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# then edit .env: set DATABASE_URL to a reachable Postgres instance
# (or, for a quick non-production smoke test only, DATABASE_URL=sqlite:///./hawkeye.db —
# SQLite self-initializes its schema but is rejected outright when ENV=production)

alembic upgrade head          # skip only if using the SQLite quick-start above
uvicorn app.main:app --host 0.0.0.0 --port 8000

# in a second terminal
npm install
npm run dev
```

Development defaults are intentionally convenient. Production deployments should provide explicit security configuration through environment variables.

### Option D — Windows

`run.sh` is a bash script and does not run natively on Windows. Use one of the following instead.

**D1 — Docker Compose (recommended on Windows; identical to Option B)**

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) with WSL2 backend enabled. In PowerShell:

```powershell
$env:JWT_SECRET = -join ((48..57)+(97..102) | Get-Random -Count 64 | % {[char]$_})
$env:AUTH_USERS_JSON = Get-Content .env.example | Select-String 'AUTH_USERS_JSON=' | % { $_ -replace 'AUTH_USERS_JSON=', '' }
docker compose up --build
```

Backend starts on `http://localhost:8000`; health check at `/health`. This path avoids installing Python/Node/PostgreSQL on the host entirely.

**D2 — Manual step-by-step (native Windows)**

Prerequisites: [Python 3.12.x](https://www.python.org/downloads/) (check "Add python.exe to PATH" during install; do **not** install 3.13+, see Requirements above), [Node.js 18+](https://nodejs.org/), and [PostgreSQL 16](https://www.postgresql.org/download/windows/) (or use SQLite for a quick local smoke test, per Option C).

In PowerShell, from the project root:

```powershell
py -3.12 -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt

Copy-Item .env.example .env
# then edit .env: set DATABASE_URL to a reachable Postgres instance
# (or, for a quick non-production smoke test only, DATABASE_URL=sqlite:///./hawkeye.db)

alembic upgrade head          # skip only if using the SQLite quick-start above
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

In a second PowerShell terminal:

```powershell
npm install
npm run dev
```

> If `venv\Scripts\Activate.ps1` is blocked by execution policy, run PowerShell as your normal user and execute `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first, then re-run the activation command. Command Prompt users can activate instead with `venv\Scripts\activate.bat`.

## Testing

```bash
pip install -r requirements.txt   # pytest is included in requirements.txt
pytest -q
python -m compileall -q app
npm run typecheck                 # frontend: tsc --noEmit
```

The release test suite covers approval safety, RBAC, tenant isolation, WebSocket isolation, AI prompt-injection boundaries, evidence grounding, provider parity, event dispatch, ML artifact compatibility/integrity, CORS validation, ingestion limits, and authentication claims.

## Release posture

This backend is an **MVP with production-hardening controls**, not a claim of universal detection or guaranteed prevention.

- **MVP:** deterministic intelligence modules, bundled ML artifact, Local/Gemini provider integrations, and an in-process EventBus.
- **Production hardening:** PostgreSQL persistence, fail-closed authentication, tenant isolation, approval gates, evidence validation, durable event-dispatch recovery, input limits, CORS validation, token redaction, and ML integrity/version checks.
- **Future infrastructure:** durable external event brokers, enterprise identity integration, distributed workers, and other deployment-scale infrastructure.

Hawkeye does **not** claim 100% detection, fully autonomous security, certified production deployment, or guaranteed attack prevention.

## Durable Persistence (V4.1.1 P0)

Hawkeye's production-critical state is persisted through SQLAlchemy with PostgreSQL as the production database. The existing application architecture remains unchanged:

`Observe → Correlate → Predict → Decide`

The persistence layer covers events, normalized events, incidents, assets, entities, Knowledge Graph data, Threat Intelligence, risk, prediction, confidence, Incident Memory, decisions, simulations, playbooks, and playbook executions. Every tenant-bound record carries `workspace_id`, and repository access is workspace-scoped.

The existing in-process EventBus remains the event transport. A durable event-dispatch/outbox record is written before publication so events accepted around process restarts are recoverable; Kafka and Redis are intentionally not introduced.

Production configuration must provide a PostgreSQL `DATABASE_URL`. Use Alembic migrations before starting a production database.

## Final demo and deployment

See `DEMO.md` for the deterministic credential-compromise attack-chain demo
(`python -m app.simulator.demo`) and offline/real-AI instructions. The complete
deployment path is available in `Dockerfile` and `docker-compose.yml`; container
startup waits for PostgreSQL, runs Alembic migrations, and exposes `/health`
on `http://localhost:8000`.

This README is the canonical architecture and setup reference for this submission.
