"""Celery application.

Run with::

    celery -A zentra.workers.celery_app:celery_app worker --loglevel=INFO
    celery -A zentra.workers.celery_app:celery_app beat --loglevel=INFO
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab
from celery.signals import setup_logging, task_failure, task_prerun

from zentra.config import get_settings
from zentra.logging import configure_logging, get_logger, request_id_var

log = get_logger("zentra.worker")

settings = get_settings()

celery_app = Celery(
    "zentra",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["zentra.workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    task_track_started=True,
    # Hard ceilings so a wedged provider cannot hold a worker slot forever.
    task_time_limit=600,
    task_soft_time_limit=540,
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=200,
    broker_connection_retry_on_startup=True,
    result_expires=86_400,
    task_default_queue="zentra",
)

# Make this the app that `@shared_task` binds to in every process that imports
# it, including the API. Without this, a task published from the API would go
# to Celery's default queue while the worker consumes `zentra`.
celery_app.set_default()

celery_app.conf.beat_schedule = {
    "rescan-due-vendors": {
        "task": "zentra.rescan_due_vendors",
        "schedule": crontab(minute=f"*/{max(settings.rescan_sweep_minutes, 5)}"),
    },
    "reap-stuck-scans": {
        "task": "zentra.reap_stuck_scans",
        "schedule": crontab(minute="*/15"),
    },
    "recompute-benchmarks": {
        "task": "zentra.recompute_benchmarks",
        "schedule": crontab(hour="3", minute="20"),
    },
    "weekly-summary": {
        "task": "zentra.send_weekly_summaries",
        "schedule": crontab(day_of_week="mon", hour="8", minute="0"),
    },
    "purge-expired-data": {
        "task": "zentra.purge_expired_data",
        "schedule": crontab(hour="4", minute="0"),
    },
}


@setup_logging.connect
def _configure_worker_logging(**_kwargs: object) -> None:
    configure_logging(settings.log_level, settings.log_format, service="zentra-worker")


@task_prerun.connect
def _bind_task_context(task_id: str | None = None, **_kwargs: object) -> None:
    request_id_var.set(f"task-{task_id}" if task_id else None)


@task_failure.connect
def _log_task_failure(
    task_id: str | None = None, exception: BaseException | None = None, **_kwargs: object
) -> None:
    log.error(
        "task_failed",
        task_id=task_id,
        error_type=type(exception).__name__ if exception else "unknown",
    )
