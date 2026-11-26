# OOOSEC Security Core MVP

## Scope

This is a separate internal FastAPI service. It does not replace the existing Node.js API, Telegram bot, AI agent, Mini App, or MongoDB deployment.

The first increment provides:
- bearer-token authentication for service/API access;
- a GitHub-only asset registry;
- scan-job creation with a fixed scanner allowlist;
- idempotency-key handling;
- liveness and database-readiness endpoints.

Scanner execution is deliberately not implemented in this increment. Jobs are stored as `queued`; a later Scanner Engine worker will claim them using an atomic database operation.

## Configuration

Add these values to the local `.env` file:

- `SECURITY_CORE_API_TOKEN`: random secret with at least 32 characters;
- `MONGODB_URI`: MongoDB connection string reachable from the Compose network;
- `SECURITY_DB_NAME`: dedicated database name, default `ooosec_security`.

Generate a token locally with:

```bash
openssl rand -hex 32
```

Never commit the real `.env` file or share the token in issues, logs, or chat.

## Run locally

```bash
cp .env.example .env
# Set SECURITY_CORE_API_TOKEN to a locally generated value.
docker compose -f docker-compose.yml -f docker-compose.security.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.security.yml up -d --build mongo security-core
```

The Security Core has no published host port. It is reachable only by services on the Compose network. Runtime restrictions include non-root UID, read-only root filesystem, dropped Linux capabilities, no-new-privileges, and bounded CPU, memory, PID count, and temporary storage.

## API

- `GET /health/live`: liveness probe.
- `GET /health/ready`: MongoDB readiness probe.
- `POST /api/v1/assets`: register an HTTPS GitHub repository.
- `POST /api/v1/scans`: enqueue one allowed scanner profile for an active asset.
- `GET /api/v1/scans/{scan_id}`: inspect a scan job.

Protected endpoints require `Authorization: Bearer <SECURITY_CORE_API_TOKEN>`.

Allowed scanner identifiers: `gitleaks`, `bandit`, `pip-audit`, `trivy`. They are identifiers only in this increment; no user-supplied shell command or Docker parameter is accepted.

## Database and deployment safety

The service uses a dedicated MongoDB database and collections prefixed with `security_`. It does not alter existing bot or Mini App collections and does not create MongoDB users or change the MongoDB server's authentication mode.

The existing Compose stack must be backed up and tested before production deployment. MongoDB authentication, backups, TLS, secret-manager integration, and deployment-specific network restrictions remain required before public production use.

## Tests

```bash
python -m pip install -r security-core/requirements.txt
cd security-core
pytest -q
python -m pip_audit -r requirements.txt
bandit -q -r app
```
