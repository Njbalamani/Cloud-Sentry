# Deployment Guide

## Environment variables

Copy `.env.example` to `.env` and configure every deployment-specific value.

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Django signing key. Production requires at least 50 characters. |
| `DEBUG` | Must be `False` in production. |
| `ALLOWED_HOSTS` | Comma-separated hostnames allowed by Django. |
| `CSRF_TRUSTED_ORIGINS` | Comma-separated origins allowed for CSRF-protected requests. |
| `CORS_ALLOWED_ORIGINS` | Comma-separated browser origins allowed for API access. |
| `DATABASE_URL` | PostgreSQL connection string. |
| `TESTING` | Use `True` only for tests and ephemeral local runs. |
| `DEMO_MODE` | Enables labelled synthetic assessments and demo report inclusion. |
| `ALLOW_PUBLIC_REGISTRATION` | Disable after the first administrator account is created. |
| `FIELD_ENCRYPTION_KEY` | Fernet key used to encrypt stored cloud credentials. |
| `AI_EXPLANATIONS_ENABLED` | Enables optional Gemini explanation calls. |
| `GEMINI_API_KEY` | API key used only when AI explanations are enabled. |
| `AWS_DEFAULT_REGION` | Default AWS region for assessment configuration. |
| `PROWLER_BIN` | Optional executable path for Prowler mode. |
| `SCAN_TIMEOUT_SECONDS` | Timeout for external assessment adapters. |
| `LOG_LEVEL` | Application log level. |

Generate a Fernet key with the `cryptography` package installed:

```powershell
.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Never commit `.env`, cloud credentials, tokens, or generated reports.

## Local SQLite run

```powershell
$env:TESTING='1'
.\.venv\Scripts\python.exe manage.py migrate
.\.venv\Scripts\python.exe manage.py seed_rules
.\.venv\Scripts\python.exe manage.py seed_controls
.\.venv\Scripts\python.exe manage.py runserver
```

## Docker Compose run

```powershell
Copy-Item .env.example .env
docker compose up --build
```

The stack starts PostgreSQL, waits for database readiness, applies migrations, seeds rules and controls, collects static files, and starts Gunicorn on port 8000. The media volume preserves generated reports.

## Production release sequence

```powershell
python -m pip install -r requirements.txt
python manage.py migrate
python manage.py seed_rules
python manage.py seed_controls
python manage.py collectstatic --noinput
gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 120
```

Run database migrations as a release step before starting application workers. Use a reverse proxy for TLS termination and serve collected static files through WhiteNoise or the proxy.

## Production checklist

- Set `DEBUG=False`.
- Use a strong `SECRET_KEY` with at least 50 characters.
- Set a stable `FIELD_ENCRYPTION_KEY`; changing it makes existing encrypted credentials unreadable.
- Use a managed PostgreSQL database with encrypted storage and automated backups.
- Restrict `ALLOWED_HOSTS`, `CSRF_TRUSTED_ORIGINS`, and `CORS_ALLOWED_ORIGINS`.
- Disable `ALLOW_PUBLIC_REGISTRATION` after administrator provisioning.
- Keep `DEMO_MODE=False` unless synthetic demonstrations are intentionally enabled.
- Provide AWS IAM credentials with read-only permissions only.
- Keep `PROWLER_BIN` empty unless the binary is installed and approved.
- Mount persistent storage for `MEDIA_ROOT`.
- Monitor request IDs returned in the `X-Request-ID` response header.
- Review generated logs without exposing credential material.

## Operational commands

```powershell
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test tests -v 2
python manage.py seed_demo_data --organization-slug your-organization-slug
```

## Security posture

CloudSentry only calls read-only AWS APIs. Remediation records, review decisions, and generated recommendations are advisory. No automatic cloud modification workflow exists, and demo data is always persisted with `is_demo=True`.
