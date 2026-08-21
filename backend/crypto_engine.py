"""
Crypto Engine — pluggable strategy per security level.

Level 1: No Quantum Security      — passthrough (relies on SMTP/IMAP TLS only)
Level 2: Quantum-Aided AES        — QKD key -> HKDF -> AES-256-GCM
Level 3: Quantum-Secure OTP       — raw XOR with single-use QKD key material
Attachment hybrid (used under L3) — OTP wraps a random AES session key,
                                      AES-256-GCM does the bulk encryption,
                                      so large files don't burn the 1KB key bank.
"""

import base64
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


@dataclass
class EncryptedPayload:
    security_level: int
    ciphertext: str          # base64
    key_id: str | None = None
    nonce: str | None = None      # base64, for AES-GCM
    session_key_wrapped: str | None = None  # base64, only for hybrid attachment mode
    extra: dict = field(default_factory=dict)


# ---------- Level 1: No Quantum Security ----------

def encrypt_level1(plaintext: bytes) -> EncryptedPayload:
    return EncryptedPayload(
        security_level=1,
        ciphertext=base64.b64encode(plaintext).decode(),
    )


def decrypt_level1(payload: EncryptedPayload) -> bytes:
    return base64.b64decode(payload.ciphertext)


# ---------- Level 2: Quantum-Aided AES ----------

def _derive_aes_key(qkd_key_material: bytes, length: int = 32) -> bytes:
    """QKD key -> HKDF-SHA256 -> AES key of the requested length."""
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=b"qumail-l2-aes-key")
    return hkdf.derive(qkd_key_material)


def encrypt_level2(plaintext: bytes, qkd_key_material: bytes, key_id: str) -> EncryptedPayload:
    aes_key = _derive_aes_key(qkd_key_material)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    return EncryptedPayload(
        security_level=2,
        ciphertext=base64.b64encode(ciphertext).decode(),
        key_id=key_id,
        nonce=base64.b64encode(nonce).decode(),
    )


def decrypt_level2(payload: EncryptedPayload, qkd_key_material: bytes) -> bytes:
    aes_key = _derive_aes_key(qkd_key_material)
    nonce = base64.b64decode(payload.nonce)
    ciphertext = base64.b64decode(payload.ciphertext)
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)


# ---------- Level 3: Quantum-Secure OTP ----------

def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if len(key) < len(data):
        raise ValueError(
            f"OTP key too short for plaintext: key={len(key)}B, "
            f"plaintext={len(data)}B. Use the hybrid attachment scheme for "
            f"payloads larger than the key size."
        )
    return bytes(d ^ k for d, k in zip(data, key))


def encrypt_level3(plaintext: bytes, qkd_key_material: bytes, key_id: str) -> EncryptedPayload:
    ciphertext = _xor_bytes(plaintext, qkd_key_material)
    return EncryptedPayload(
        security_level=3,
        ciphertext=base64.b64encode(ciphertext).decode(),
        key_id=key_id,
    )


def decrypt_level3(payload: EncryptedPayload, qkd_key_material: bytes) -> bytes:
    ciphertext = base64.b64decode(payload.ciphertext)
    return _xor_bytes(ciphertext, qkd_key_material)


# ---------- Hybrid scheme for attachments (OTP wraps an AES session key) ----------

def encrypt_attachment_hybrid(attachment_bytes: bytes, qkd_key_material: bytes, key_id: str) -> EncryptedPayload:
    """
    1. Generate a random AES-256 session key locally.
    2. Wrap (OTP-encrypt) that session key using the small QKD key — this is
       cheap on the key bank since session keys are only 32 bytes.
    3. Encrypt the actual attachment with AES-256-GCM using the session key.
    This keeps OTP-grade protection on the key material while attachments
    of arbitrary size don't exhaust the 1KB quantum key bank.
    """
    session_key = os.urandom(32)
    if len(qkd_key_material) < len(session_key):
        raise ValueError("QKD key material shorter than session key — cannot wrap safely.")
    wrapped_session_key = _xor_bytes(session_key, qkd_key_material[: len(session_key)])

    nonce = os.urandom(12)
    ciphertext = AESGCM(session_key).encrypt(nonce, attachment_bytes, None)

    return EncryptedPayload(
        security_level=3,
        ciphertext=base64.b64encode(ciphertext).decode(),
        key_id=key_id,
        nonce=base64.b64encode(nonce).decode(),
        session_key_wrapped=base64.b64encode(wrapped_session_key).decode(),
        extra={"mode": "hybrid_attachment"},
    )


def decrypt_attachment_hybrid(payload: EncryptedPayload, qkd_key_material: bytes) -> bytes:
    wrapped_session_key = base64.b64decode(payload.session_key_wrapped)
    session_key = _xor_bytes(wrapped_session_key, qkd_key_material[: len(wrapped_session_key)])
    nonce = base64.b64decode(payload.nonce)
    ciphertext = base64.b64decode(payload.ciphertext)
    return AESGCM(session_key).decrypt(nonce, ciphertext, None)


# ---------- Dispatcher ----------

def encrypt(level: int, plaintext: bytes, qkd_key_material: bytes | None = None, key_id: str | None = None) -> EncryptedPayload:
    if level == 1:
        return encrypt_level1(plaintext)
    if level == 2:
        return encrypt_level2(plaintext, qkd_key_material, key_id)
    if level == 3:
        return encrypt_level3(plaintext, qkd_key_material, key_id)
    raise ValueError(f"Unsupported security level: {level}")


def decrypt(payload: EncryptedPayload, qkd_key_material: bytes | None = None) -> bytes:
    if payload.security_level == 1:
        return decrypt_level1(payload)
    if payload.security_level == 2:
        return decrypt_level2(payload, qkd_key_material)
    if payload.security_level == 3:
        return decrypt_level3(payload, qkd_key_material)
    raise ValueError(f"Unsupported security level: {payload.security_level}")
