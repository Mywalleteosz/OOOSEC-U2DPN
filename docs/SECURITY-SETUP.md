# OOOSEC-U2DPN — secure local setup

## Current repository limitations

- `apps` is stored as a Git submodule pointer, but there is no `.gitmodules` file. The API source cannot currently be fetched or built reliably.
- `blockchain/lithosphere` is also a Git submodule pointer without corresponding metadata.
- Do not delete or replace either gitlink until the original source repository URLs and intended revisions are confirmed.

## Local environment

1. Copy the example environment file:

   ```bash
   cp .env.example .env
   ```

2. Set real values for `BOT_TOKEN` and `OPENAI_API_KEY`.
3. Generate an n8n encryption key:

   ```bash
   openssl rand -hex 32
   ```

4. Put the generated value in `N8N_ENCRYPTION_KEY` in `.env`.
5. Keep `.env` out of Git. Never paste credentials into issues, pull requests, logs, or chat.

## Start the currently buildable services

```bash
docker compose up -d bot mongo n8n
```

The bot and n8n ports are bound to `127.0.0.1`. MongoDB is also published only on loopback. The Telegram bot container runs as a non-root user and does not mount host editor directories.

The API service is not included in this command because its source submodule is currently unresolved.

## Before any public deployment

- Configure MongoDB authentication and update application connection strings.
- Pin the n8n image to a reviewed release or digest.
- Put secrets in the deployment platform's secret manager.
- Add TLS, access controls, backups, monitoring, and tested restore procedures.
- Review every service's network exposure before changing loopback bindings.
