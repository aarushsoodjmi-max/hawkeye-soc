"""
HawkEye SOC — Unified Backend
=============================
FastAPI application entrypoint.

CANONICAL REST CONTRACT (used by the frontend, all under /api):
- POST /api/auth/token
- GET  /api/dashboard
- GET  /api/events
- GET  /api/incidents, /api/incidents/{id}
- PUT  /api/incidents/{id}/status
- POST /api/incidents/{id}/actions/{action_id}/execute
- POST /api/incidents/{id}/assets/{asset_id}/toggle-isolation
- GET/POST /api/alerts, GET /api/alerts/{id}
- GET  /api/assets, /api/assets/{id}
- GET  /api/graph, /api/graph/traverse
- GET  /api/reports, /api/reports/{incident_id}(/executive|/export)
- GET  /api/audit
- POST /api/ai/analyze, GET /api/ai/health, GET /api/ai/models
- api modules: /api/prediction, /api/confidence, /api/decision,
  /api/playbooks, /api/decision-simulator (+ workspace-prefixed aliases)

LEGACY (DEPRECATED — retained only for backwards compatibility and tests;
NOT used by the frontend): /alerts*, /incidents*, /analyze, /simulate,
/simulator, /health.
"""

import logging
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Request
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings, validate_security_settings
from app.core.security import install_security_logging_filter
from app.routes import alerts, incidents, analyze, simulator
from app.modules.prediction.router import router as prediction_router
from app.modules.incident_memory.router import router as incident_memory_router
from app.modules.confidence_engine.router import router as confidence_router
from app.modules.decision_engine.router import router as decision_router
from app.modules.decision_simulator.router import router as decision_simulator_router
from app.modules.playbooks.router import router as playbooks_router
from app.modules.ai.router import router as ai_router
from app.transport.router import router as transport_router
from app.transport.auth_router import router as auth_router
from app.transport.ws_router import router as ws_router
from app.core.event_bus import event_bus
from app.core.websocket import manager
from app.core.auth import current_principal, require_workspace
from app.core.observability import set_request_context, reset_request_context
from app.repositories import repository
from app.ml.predictor import model_health
from app.db import init_db, PersistentStateRepository, get_engine

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
# Never log passwords, JWT secrets, API keys, authorization headers or
# bearer tokens, even if a code path accidentally tries to.
install_security_logging_filter()
logger = logging.getLogger("hawkeye.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_security_settings()
    init_db()
    if settings.DEMO_MODE:
        # Demo bootstrap is explicit and idempotent: seed only when the
        # configured workspace has no persisted baseline data.
        try:
            repository.seed_demo_data()
        except Exception as exc:
            logger.error("Demo initialization failed: %s", type(exc).__name__)
            raise
    if settings.ENV == "production":
        # Fail fast when the configured PostgreSQL is unreachable. Alembic owns
        # the schema (app startup never runs create_all against PostgreSQL);
        # this check only verifies connectivity.
        with get_engine().connect():
            pass
    logger.info("HawkEye SOC Backend initializing...")
    await event_bus.start()

    async def websocket_bridge(topic: str, payload: dict):
        await manager.publish(topic, payload)
        event_id = payload.get("event_id")
        workspace = payload.get("workspace")
        if event_id and workspace:
            PersistentStateRepository().mark_dispatch(workspace, event_id, "DELIVERED")

    # Subscribe the WebSocket layer to every canonical Event Bus topic.
    for topic in event_bus.TOPICS:
        await event_bus.subscribe(topic, websocket_bridge)

    # Recover events durably queued before a restart or transient dispatcher outage.
    durable_events = PersistentStateRepository().queued_dispatches()
    for workspace_id, event_id, topic, payload in durable_events:
        try:
            delivered = await event_bus.publish(topic, payload)
            if delivered:
                PersistentStateRepository().mark_dispatch(workspace_id, event_id, "DELIVERED")
            else:
                logger.error("Durable event recovery subscriber failure for event_id=%s", event_id)
        except Exception:
            logger.error("Durable event recovery failed for event_id=%s", event_id)

    logger.info(
        "Active incidents: %d, Active alerts: %d",
        len(repository.incidents),
        len(repository.alerts),
    )
    yield

    for topic in event_bus.TOPICS:
        await event_bus.unsubscribe(topic, websocket_bridge)
    await event_bus.stop()
    logger.info("HawkEye SOC Backend shutting down.")


async def _request_context_middleware(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    tokens = set_request_context(request=rid)
    try:
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response
    finally:
        reset_request_context(tokens)


app = FastAPI(
    title="HawkEye SOC Backend",
    description="Causal SOC Alert Correlation, Root Cause Intelligence, and Attack Simulation Engine",
    version="4.1.1",
    lifespan=lifespan,
)

app.middleware("http")(_request_context_middleware)

# Configure CORS from explicit environment origins
frontend_origin = settings.FRONTEND_ORIGINS
configured_origins = (
    [origin.strip() for origin in frontend_origin.split(",") if origin.strip()]
    if frontend_origin
    else ["http://localhost:5173"]
)
# Treat localhost and 127.0.0.1 as equivalent frontend loopback origins while
# preserving explicitly configured ports and avoiding wildcard CORS.
allowed_origins = []
for origin in configured_origins:
    if origin not in allowed_origins:
        allowed_origins.append(origin)
    if origin.startswith("http://localhost:"):
        alias = "http://127.0.0.1:" + origin.rsplit(":", 1)[1]
        if alias not in allowed_origins:
            allowed_origins.append(alias)
    elif origin.startswith("http://127.0.0.1:"):
        alias = "http://localhost:" + origin.rsplit(":", 1)[1]
        if alias not in allowed_origins:
            allowed_origins.append(alias)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Route registrations
app.include_router(alerts.router, prefix="/alerts", tags=["Alerts"], dependencies=[Depends(current_principal)])
app.include_router(incidents.router, prefix="/incidents", tags=["Incidents"], dependencies=[Depends(current_principal)])
app.include_router(incidents.router, prefix="/incident", tags=["Incidents"], dependencies=[Depends(current_principal)])
app.include_router(analyze.router, prefix="/analyze", tags=["Analysis"], dependencies=[Depends(current_principal)])
app.include_router(simulator.router, prefix="/api/simulate", tags=["Simulator"], dependencies=[Depends(current_principal)])
app.include_router(simulator.router, prefix="/simulate", tags=["Simulator"], dependencies=[Depends(current_principal)])
app.include_router(simulator.router, prefix="/simulator", tags=["Simulator"], dependencies=[Depends(current_principal)])

# Session 5 — Decision Intelligence. Legacy paths are retained; workspace-prefixed
# aliases enforce require_workspace and match the v3 API contract.
app.include_router(prediction_router, prefix="/api/prediction", tags=["Prediction"], dependencies=[Depends(current_principal)])
app.include_router(incident_memory_router, prefix="/api", tags=["Incident Memory"], dependencies=[Depends(current_principal)])
app.include_router(confidence_router, prefix="/api/confidence", tags=["Confidence Engine"], dependencies=[Depends(current_principal)])
app.include_router(decision_router, prefix="/api/decision", tags=["Decision Engine"], dependencies=[Depends(current_principal)])
app.include_router(decision_simulator_router, prefix="/api/decision-simulator", tags=["Decision Simulator"], dependencies=[Depends(current_principal)])
app.include_router(playbooks_router, prefix="/api/playbooks", tags=["Playbooks"], dependencies=[Depends(current_principal)])
app.include_router(ai_router, prefix="/api/ai", tags=["AI"], dependencies=[Depends(current_principal)])

# Workspace-prefixed aliases: REQUIRED for every module so no tenant-scoped
# surface is reachable without an explicit workspace match.
app.include_router(prediction_router, prefix="/api/workspaces/{ws}/prediction", tags=["Prediction"], dependencies=[Depends(require_workspace)])
app.include_router(incident_memory_router, prefix="/api/workspaces/{ws}", tags=["Incident Memory"], dependencies=[Depends(require_workspace)])
app.include_router(confidence_router, prefix="/api/workspaces/{ws}/confidence", tags=["Confidence Engine"], dependencies=[Depends(require_workspace)])
app.include_router(decision_router, prefix="/api/workspaces/{ws}/decision", tags=["Decision Engine"], dependencies=[Depends(require_workspace)])
app.include_router(decision_simulator_router, prefix="/api/workspaces/{ws}/decision-simulator", tags=["Decision Simulator"], dependencies=[Depends(require_workspace)])
app.include_router(playbooks_router, prefix="/api/workspaces/{ws}/playbooks", tags=["Playbooks"], dependencies=[Depends(require_workspace)])
app.include_router(ai_router, prefix="/api/workspaces/{ws}/ai", tags=["AI"], dependencies=[Depends(require_workspace)])

# Session 7 — authenticated transport layer
app.include_router(auth_router)
app.include_router(transport_router)
app.include_router(ws_router)


@app.get("/health", tags=["Health"])
def health_check():
    """Service health and telemetry check."""
    return {
        "status": "ok",
        "service": "HawkEye SOC Backend",
        "version": "4.1.1",
        "activeIncidents": len(repository.incidents),
        "totalAlerts": len(repository.alerts),
        "ml": model_health(),
    }
