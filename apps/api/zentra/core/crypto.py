"""Envelope encryption for integration secrets stored at rest."""

from __future__ import annotations

from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken

from zentra.config import get_settings
from zentra.errors import ZentraError


class SecretDecryptionError(ZentraError):
    status_code = 500
    code = "SECRET_DECRYPTION_FAILED"
    message = "A stored integration secret could not be decrypted."


class MissingEncryptionKeyError(ZentraError):
    status_code = 503
    code = "ENCRYPTION_KEY_MISSING"
    message = (
        "SECRETS_ENCRYPTION_KEY is not configured; integrations that store "
        "credentials are unavailable."
    )


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    key = get_settings().secrets_encryption_key
    if not key:
        raise MissingEncryptionKeyError()
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise MissingEncryptionKeyError(
            "SECRETS_ENCRYPTION_KEY is not a valid Fernet key."
        ) from exc


def encryption_available() -> bool:
    try:
        _fernet()
    except MissingEncryptionKeyError:
        return False
    return True


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    try:
        return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise SecretDecryptionError() from exc


def reset_cache() -> None:
    _fernet.cache_clear()
