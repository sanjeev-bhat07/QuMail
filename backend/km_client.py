"""
KM Client — abstracts the Key Manager HTTP API away from the rest of the
app. Swapping the mock KM for a real vendor's ETSI 014-compliant KM later
means changing only KM_BASE_URL, nothing else in the application.
"""

import base64
import os

import httpx

KM_BASE_URL = os.environ.get("QUMAIL_KM_URL", "http://localhost:8001")


class KeyBankExhausted(Exception):
    pass


class KeyAlreadyConsumed(Exception):
    pass


def request_encryption_key(sae_id: str = "sender-sae") -> tuple[str, bytes]:
    """Sender side — get a fresh key. Returns (key_id, key_bytes)."""
    resp = httpx.get(f"{KM_BASE_URL}/api/v1/keys/{sae_id}/enc_keys", timeout=10)
    if resp.status_code == 410:
        raise KeyBankExhausted("Key bank exhausted")
    resp.raise_for_status()
    data = resp.json()
    return data["key_ID"], base64.b64decode(data["key"])


def request_decryption_key(key_id: str, sae_id: str = "receiver-sae") -> bytes:
    """Receiver side — fetch the matching key by ID."""
    resp = httpx.get(
        f"{KM_BASE_URL}/api/v1/keys/{sae_id}/dec_keys",
        params={"key_ID": key_id},
        timeout=10,
    )
    if resp.status_code == 403:
        raise KeyAlreadyConsumed(f"Key {key_id} already consumed")
    resp.raise_for_status()
    data = resp.json()
    return base64.b64decode(data["key"])


def get_key_status(sae_id: str = "sender-sae") -> dict:
    resp = httpx.get(f"{KM_BASE_URL}/api/v1/keys/{sae_id}/status", timeout=10)
    resp.raise_for_status()
    return resp.json()
