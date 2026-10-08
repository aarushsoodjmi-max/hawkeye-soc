# Transport Layer

The transport layer exposes authenticated REST groups and a topic-based WebSocket endpoint.

## Authentication

`POST /api/auth/token` requires a configured username and password. The server determines the user's role and workspace from `AUTH_USERS_JSON`; clients cannot self-select either value.

REST requests use:

`Authorization: Bearer <JWT>`

WebSocket clients should prefer `Authorization: Bearer <JWT>` during the WebSocket handshake. `/ws?token=<JWT>&topics=...` remains a compatibility path; raw query tokens are not logged or retained after validation.

### Production configuration

Set:

- `ENV=production`
- `AUTH_REQUIRED=true`
- `JWT_SECRET` to a random value of at least 32 bytes
- `FRONTEND_ORIGINS` to one or more explicit origins (wildcard is rejected with credentials)
- `AUTH_USERS_JSON` to a JSON user registry containing PBKDF2-SHA256 password hashes

Generate a password hash with:

```bash
python -m app.transport.password_hash
```

The production application refuses to start if authentication, the JWT secret, the user registry, or explicit CORS origins are missing/insecure.

## Authorization

- `viewer`: read-only access
- `analyst`: read access plus alert ingestion, analysis, simulation, incident updates, and notes
- `admin`: all analyst capabilities plus SOAR action, asset-isolation, and playbook execution

Workspace-prefixed routes require the URL workspace to match the authenticated JWT workspace.

## REST groups

- `GET /api/dashboard`
- `GET /api/events`
- `GET /api/incidents`
- `GET /api/incidents/{incident_id}`
- `GET /api/assets`
- `GET /api/assets/{asset_id}`
- `GET /api/graph`
- `GET /api/graph/traverse?entity_id=AST-01&depth=2`
- `POST /api/incidents/{incident_id}/simulate`
- `GET /api/reports`

## WebSocket topics

- `event.normalized`
- `incident.updated`
- `risk.updated`
- `confidence.updated`
- `playbook.executed`
