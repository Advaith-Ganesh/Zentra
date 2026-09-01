"""Assembles the v1 API surface."""

from __future__ import annotations

from fastapi import APIRouter

from zentra.api.v1 import admin, auth, billing, me, public, public_api, reports, slack, vendors

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(me.router)
api_router.include_router(me.alerts_router)
api_router.include_router(me.keys_router)
api_router.include_router(me.benchmark_router)
api_router.include_router(me.integrations_router)
api_router.include_router(vendors.router)
api_router.include_router(vendors.scans_router)
api_router.include_router(vendors.findings_router)
api_router.include_router(reports.router)
api_router.include_router(billing.router)
api_router.include_router(billing.webhook_router)
api_router.include_router(public.router)
api_router.include_router(public_api.router)
api_router.include_router(slack.router)
api_router.include_router(admin.router)

__all__ = ["api_router"]
