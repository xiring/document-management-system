"""Celery application (broker: Redis). Run worker: ``celery -A app.celery_app worker -l info``."""

from __future__ import annotations

from celery import Celery

from app.config import settings

celery_app = Celery(
    "dms",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["app.tasks.jobs"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_default_retry_delay=60,
    task_max_retries=5,
)
