# Hawkeye deterministic demo

The deterministic demo exercises the real backend services with a stable,
synthetic attack chain:

**credential compromise → impossible travel → VPN login → PowerShell → credential access → lateral movement → privileged account → critical server**

It drives the same backend stages used by live telemetry:

**telemetry → normalization → correlation → incident → KG/TI → risk → prediction → confidence → AI investigation → simulation → approval → playbook → execution → verification → resolution**

## Offline deterministic demo

From the repository root:

```bash
python -m app.simulator.demo
```

The demo uses the provider-neutral `AiResponse` contract through a deterministic
`demo` provider adapter. This keeps the demo repeatable without requiring an
external LLM. It does **not** register the demo provider in production's
provider registry and it cannot execute actions without the normal approval
and execution gates.

Reset the demo workspace before running (the default):

```bash
python -m app.simulator.demo
```

To preserve the existing demo workspace state:

```bash
python -m app.simulator.demo --no-reset
```

## Real Local AI demo

Start the local inference service, configure `HAWKEYE_AI_SERVER_URL`, then run:

```bash
python -m app.simulator.demo --real-ai
```

No automatic provider fallback is performed if Local AI is unavailable.

## Docker demo

```bash
docker compose up --build
```

The backend waits for PostgreSQL health, applies Alembic migrations, and then
starts on `http://localhost:8000`. Health is available at `/health`.

For a production deployment, replace all demo credentials/secrets and use a
managed PostgreSQL instance plus explicit production authentication/CORS
configuration.
