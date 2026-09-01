"""Deployment-level feature flags.

These gate whole subsystems that may be incomplete or require credentials
Zentra does not have in a given environment. They are orthogonal to plan
entitlements: a flag says "this capability exists in this deployment", an
entitlement says "this customer has paid for it".
"""

from __future__ import annotations

from enum import StrEnum

from zentra.config import get_settings
from zentra.errors import FeatureDisabledError


class Flag(StrEnum):
    BENCHMARKING = "benchmarking"
    SLACK = "slack"
    TEAMS = "teams"
    MSSP = "mssp"
    WHITE_LABEL = "white_label"
    PUBLIC_API = "public_api"
    ADVANCED_SCANNERS = "advanced_scanners"


def is_enabled(flag: Flag | str) -> bool:
    name = flag.value if isinstance(flag, Flag) else flag
    settings = get_settings()
    if name == Flag.SLACK.value:
        # Slack is only usable when the OAuth credentials actually exist.
        return settings.feature_slack and bool(
            settings.slack_client_id
            and settings.slack_client_secret
            and settings.slack_signing_secret
        )
    return settings.feature_enabled(name)


def require(flag: Flag | str) -> None:
    if not is_enabled(flag):
        name = flag.value if isinstance(flag, Flag) else flag
        raise FeatureDisabledError(f"The {name.replace('_', ' ')} feature is not enabled.")


def all_flags() -> dict[str, bool]:
    return {flag.value: is_enabled(flag) for flag in Flag}
