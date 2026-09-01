# Railway deployment

Zentra deploys as three Railway services from one repository, plus managed
Postgres (or hosted Supabase) and Redis.

| Service | Dockerfile | Start command |
| --- | --- | --- |
| `zentra-api` | `infrastructure/docker/api.Dockerfile` | default (`uvicorn`) |
| `zentra-worker` | `infrastructure/docker/api.Dockerfile` | `celery -A zentra.workers.celery_app:celery_app worker --loglevel=INFO --concurrency=4` |
| `zentra-beat` | `infrastructure/docker/api.Dockerfile` | `celery -A zentra.workers.celery_app:celery_app beat --loglevel=INFO` |

The frontend deploys to Vercel or to a fourth Railway service using
`infrastructure/docker/web.Dockerfile`.

The API and the worker deliberately share one image. A worker running different
scanner code from the API that queued the job is a class of bug worth designing
out.

## First deploy

1. Create the project and add the Postgres and Redis plugins (or point
   `DATABASE_URL` at hosted Supabase).
2. Create the three services above from this repository, each with the
   Dockerfile and start command from the table.
3. Set the environment variables below on **all three** services. Railway
   supports shared variables — use one shared group rather than three copies.
4. Deploy `zentra-api` first. Run migrations once:
   `railway run --service zentra-api python -m zentra.db.migrate`
5. Point Stripe's webhook endpoint at
   `https://<api-domain>/api/v1/webhooks/stripe` and copy the signing secret
   into `STRIPE_WEBHOOK_SECRET`.

## Required environment variables

Production refuses to start without these. `zentra.config` validates them at
import time, so a misconfigured deploy fails immediately and loudly rather than
running in an unsafe state.

```
ENVIRONMENT=production
DEBUG=false
USE_MOCK_SCANNERS=false
RATE_LIMIT_ENABLED=true

DATABASE_URL=postgresql+psycopg://…
REDIS_URL=redis://…
CELERY_BROKER_URL=redis://…/1
CELERY_RESULT_BACKEND=redis://…/2

JWT_SECRET=<openssl rand -hex 32>
SECRETS_ENCRYPTION_KEY=<Fernet key>

APP_URL=https://app.yourdomain.com
API_URL=https://api.yourdomain.com
CORS_ALLOWED_ORIGINS=https://app.yourdomain.com

AUTH_PROVIDER=supabase
SUPABASE_URL=…
SUPABASE_ANON_KEY=…
SUPABASE_SERVICE_ROLE_KEY=…
SUPABASE_JWT_SECRET=…

STRIPE_SECRET_KEY=…
STRIPE_WEBHOOK_SECRET=…
STRIPE_STARTER_PRICE_ID=…
STRIPE_GROWTH_PRICE_ID=…
STRIPE_SCALE_PRICE_ID=…

EMAIL_PROVIDER=resend
RESEND_API_KEY=…

LOG_FORMAT=json
```

Optional, and safe to omit — the affected check reports "not assessed" rather
than failing:

```
HIBP_API_KEY=…      # breach history
SHODAN_API_KEY=…    # internet exposure
NVD_API_KEY=…       # raises the CVE lookup rate limit
SLACK_CLIENT_ID=…   # Slack integration; also needs FEATURE_SLACK=true
SLACK_CLIENT_SECRET=…
SLACK_SIGNING_SECRET=…
SENTRY_DSN=…
```

## Health checks

Point Railway's health check at `/health` on `zentra-api`. It is deliberately
cheap and touches no dependency, so a Redis blip cannot cause a restart loop.

`/ready` additionally verifies Postgres and Redis, and returns 503 when either
is unreachable. Use it for load-balancer readiness, not for liveness.

The worker has no HTTP surface. Monitor it with
`celery -A zentra.workers.celery_app:celery_app inspect ping`, and watch the
`zentra.reap_stuck_scans` task, which fails any scan left running for more than
30 minutes so a lost worker never silently swallows a job.

## Storage note

Generated PDF reports are written to `REPORT_STORAGE_DIR`. Railway containers
have ephemeral filesystems, so mount a volume on both `zentra-api` and
`zentra-worker` at the same path — the worker writes the file and the API
serves it. Reports expire after 30 days and are purged by a scheduled task.

For a multi-replica deployment, move report storage to object storage
(S3/R2/Supabase Storage) before scaling the API past one instance. This is a
known limitation, recorded in the README.
