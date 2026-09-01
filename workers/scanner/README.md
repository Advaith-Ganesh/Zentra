# Scanner worker

The worker does not live here as a separate codebase. It is the same `zentra`
Python package as the API (`apps/api/zentra/`), started with a different
command:

```bash
celery -A zentra.workers.celery_app:celery_app worker --loglevel=INFO
celery -A zentra.workers.celery_app:celery_app beat  --loglevel=INFO \
  --schedule=/app/state/celerybeat-schedule
```

Both processes ship in the same Docker image
(`infrastructure/docker/api.Dockerfile`).

## Why it is not a separate service

A worker running different scanner or scoring code from the API that queued the
job is a class of bug worth designing out rather than monitoring for. Sharing
one package and one image makes a version skew between them impossible.

The separation that actually matters — the one this directory would have
provided — is process isolation, and that is real: the worker runs in its own
container, scales independently, and has no HTTP surface.

## Where the code is

| Concern | Location |
| --- | --- |
| Celery app and schedule | `apps/api/zentra/workers/celery_app.py` |
| Tasks | `apps/api/zentra/workers/tasks.py` |
| Dispatch from the API | `apps/api/zentra/workers/dispatch.py` |
| Scanning engine | `apps/api/zentra/scanners/` |
| Scoring engine | `apps/api/zentra/scoring/` |

See [docs/scanning-engine.md](../../docs/scanning-engine.md).
