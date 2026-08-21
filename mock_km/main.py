"""
Mock Key Manager (KM) — ETSI GS QKD 014-shaped REST API.

Simulates two SAEs (Secure Application Entities) — sender and receiver —
sharing a pre-generated symmetric key bank, per the QuMail problem
statement's assumption that local KMs at both ends have already
generated symmetric quantum keys.

Real endpoints this mirrors (simplified for prototype purposes):
  GET  /api/v1/keys/{slave_SAE_ID}/enc_keys
  GET  /api/v1/keys/{master_SAE_ID}/dec_keys?key_ID=...
  GET  /api/v1/keys/{SAE_ID}/status
"""

import base64
import os
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="QuMail Mock Key Manager (ETSI GS QKD 014-shaped)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

KEY_SIZE_BYTES = 1024  # 1 KB keys, per problem statement's key-bank assumption
INITIAL_KEY_COUNT = 100

# In-memory key bank: key_id -> {"value": bytes, "reserved": bool, "consumed": bool, "issued_at": str}
# "reserved" = handed out via enc_keys, no longer available for future enc_keys calls.
# "consumed" = retrieved via dec_keys, i.e. actually used to decrypt — enforces single-use.
# Shared bank simulates both ends already holding the same symmetric keys.
KEY_BANK: dict[str, dict] = {}


def _seed_key_bank():
    for _ in range(INITIAL_KEY_COUNT):
        key_id = str(uuid.uuid4())
        KEY_BANK[key_id] = {
            "value": secrets.token_bytes(KEY_SIZE_BYTES),
            "reserved": False,
            "consumed": False,
            "issued_at": None,
        }


_seed_key_bank()


class KeyContainer(BaseModel):
    key_ID: str
    key: str  # base64
    key_size: int


class StatusResponse(BaseModel):
    SAE_ID: str
    stored_key_count: int
    max_key_count: int
    key_size: int


@app.get("/api/v1/keys/{slave_sae_id}/enc_keys", response_model=KeyContainer)
def get_encryption_key(slave_sae_id: str):
    """
    Sender side: request a fresh, never-before-issued key to encrypt with.
    Marks it 'reserved' immediately so a second enc_keys call — e.g. for a
    body + a separate attachment in the same message — can never receive
    the same key twice. This was a real bug: without this flag, two
    back-to-back enc_keys calls returned identical key material.
    """
    for key_id, entry in KEY_BANK.items():
        if not entry["reserved"] and not entry["consumed"]:
            entry["reserved"] = True
            entry["issued_at"] = datetime.now(timezone.utc).isoformat()
            return KeyContainer(
                key_ID=key_id,
                key=base64.b64encode(entry["value"]).decode(),
                key_size=KEY_SIZE_BYTES,
            )
    raise HTTPException(status_code=410, detail="Key bank exhausted — no unused keys remain")


@app.get("/api/v1/keys/{master_sae_id}/dec_keys", response_model=KeyContainer)
def get_decryption_key(master_sae_id: str, key_ID: str = Query(...)):
    """
    Receiver side: fetch the key matching a given key_ID to decrypt with.
    Marks it CONSUMED on retrieval — enforces single-use at the server,
    not client trust, which is what actually makes the OTP guarantee real.
    """
    entry = KEY_BANK.get(key_ID)
    if entry is None:
        raise HTTPException(status_code=404, detail="Unknown key_ID")
    if entry["consumed"]:
        raise HTTPException(
            status_code=403,
            detail="Key already consumed — single-use keys cannot be re-issued",
        )
    entry["consumed"] = True
    return KeyContainer(
        key_ID=key_ID,
        key=base64.b64encode(entry["value"]).decode(),
        key_size=KEY_SIZE_BYTES,
    )


@app.get("/api/v1/keys/{sae_id}/status", response_model=StatusResponse)
def get_status(sae_id: str):
    # "Available" means never reserved — i.e. what a NEW enc_keys call could
    # still hand out. A reserved-but-not-yet-consumed key (already given to
    # a sender, not yet decrypted by a receiver) is not double-countable.
    available = sum(1 for e in KEY_BANK.values() if not e["reserved"])
    return StatusResponse(
        SAE_ID=sae_id,
        stored_key_count=available,
        max_key_count=INITIAL_KEY_COUNT,
        key_size=KEY_SIZE_BYTES,
    )


@app.post("/api/v1/admin/replenish")
def replenish_keys(count: int = 100):
    """Demo/admin helper — top up the key bank (not part of ETSI 014 spec)."""
    for _ in range(count):
        key_id = str(uuid.uuid4())
        KEY_BANK[key_id] = {"value": secrets.token_bytes(KEY_SIZE_BYTES), "reserved": False, "consumed": False, "issued_at": None}
    return {"added": count, "total": len(KEY_BANK)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
