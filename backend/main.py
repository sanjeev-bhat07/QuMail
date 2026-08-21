"""
QuMail Orchestrator — wires GUI <-> KM Client <-> Crypto Engine <-> Email Layer.
Run this alongside mock_km/main.py (separate process, port 8001).
"""

import base64
from dataclasses import asdict

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

import crypto_engine
import db
import email_layer
import km_client

app = FastAPI(title="QuMail Orchestrator")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

db.init_db()


@app.get("/api/key-status")
def key_status():
    try:
        return km_client.get_key_status()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"KM unreachable: {e}")


def _encrypt_attachment(level: int, attachment_bytes: bytes) -> tuple[dict, str | None]:
    """
    Encrypts an attachment appropriately per level. Always uses its OWN
    fresh key — separate from the body's key — so single-use enforcement
    stays clean (body and attachment each consume one key).
    Returns (payload_dict, key_id_used).
    """
    if level == 1:
        payload = crypto_engine.encrypt_level1(attachment_bytes)
        return asdict(payload), None

    key_id, key_material = km_client.request_encryption_key()

    if level == 2:
        # AES-GCM's derived key is fixed-length regardless of attachment
        # size, so no hybrid wrapping needed — same scheme as the body.
        payload = crypto_engine.encrypt_level2(attachment_bytes, key_material, key_id)
    else:  # level == 3
        # Raw OTP can't handle attachments larger than the key (1KB), so
        # use the hybrid scheme: OTP wraps a random AES session key, and
        # AES-GCM does the bulk encryption.
        payload = crypto_engine.encrypt_attachment_hybrid(attachment_bytes, key_material, key_id)

    return asdict(payload), key_id


@app.post("/api/compose")
async def compose(
    to: str = Form(...),
    subject: str = Form(...),
    body: str = Form(...),
    security_level: int = Form(...),
    attachment: UploadFile | None = File(None),
):
    if security_level not in (1, 2, 3):
        raise HTTPException(status_code=400, detail="security_level must be 1, 2, or 3")

    plaintext = body.encode("utf-8")
    key_id = None

    if security_level == 1:
        body_payload = crypto_engine.encrypt(1, plaintext)
    else:
        try:
            key_id, key_material = km_client.request_encryption_key()
        except km_client.KeyBankExhausted:
            raise HTTPException(
                status_code=409,
                detail="Quantum key bank exhausted. Try Level 1, or replenish keys.",
            )
        body_payload = crypto_engine.encrypt(security_level, plaintext, key_material, key_id)

    payload_json = asdict(body_payload)

    attachment_meta = None
    if attachment is not None and attachment.filename:
        attachment_bytes = await attachment.read()
        try:
            att_payload, att_key_id = _encrypt_attachment(security_level, attachment_bytes)
        except km_client.KeyBankExhausted:
            raise HTTPException(
                status_code=409,
                detail="Quantum key bank exhausted while encrypting attachment.",
            )
        attachment_meta = {
            "filename": attachment.filename,
            "size": len(attachment_bytes),
            "key_id": att_key_id,
            "payload": att_payload,
        }
        payload_json["attachment"] = attachment_meta

    try:
        email_layer.send_email(to, subject, payload_json)
    except RuntimeError as e:
        # Gmail creds not configured — still report success on encryption so
        # the crypto pipeline can be demoed/tested independently of email creds.
        return {
            "status": "encrypted_only",
            "detail": str(e),
            "payload_preview": payload_json,
        }

    db.log_sent_message(to, subject, security_level, key_id)
    return {
        "status": "sent",
        "security_level": security_level,
        "key_id": key_id,
        "attachment_key_id": attachment_meta["key_id"] if attachment_meta else None,
    }


@app.get("/api/inbox")
def inbox():
    try:
        messages = email_layer.fetch_inbox()
    except RuntimeError as e:
        raise HTTPException(status_code=412, detail=str(e))
    return messages


@app.post("/api/decrypt/{key_id}")
def decrypt_message(key_id: str, ciphertext_payload: dict):
    # Strip attachment sub-object before building EncryptedPayload —
    # it's decrypted separately via /api/decrypt-attachment.
    body_only = {k: v for k, v in ciphertext_payload.items() if k != "attachment"}
    payload = crypto_engine.EncryptedPayload(**body_only)
    if payload.security_level == 1:
        plaintext = crypto_engine.decrypt(payload)
    else:
        try:
            key_material = km_client.request_decryption_key(key_id)
        except km_client.KeyAlreadyConsumed:
            raise HTTPException(status_code=403, detail="Key already used — cannot decrypt twice")
        plaintext = crypto_engine.decrypt(payload, key_material)
    return {"plaintext": plaintext.decode("utf-8", errors="replace")}


@app.post("/api/decrypt-attachment")
def decrypt_attachment(attachment_meta: dict):
    """Decrypts an attachment sub-payload and returns raw bytes for download."""
    filename = attachment_meta.get("filename", "attachment.bin")
    att_key_id = attachment_meta.get("key_id")
    att_payload_dict = attachment_meta.get("payload", {})
    level = att_payload_dict.get("security_level")

    if level == 1:
        plaintext = crypto_engine.decrypt_level1(crypto_engine.EncryptedPayload(**att_payload_dict))
    else:
        try:
            key_material = km_client.request_decryption_key(att_key_id)
        except km_client.KeyAlreadyConsumed:
            raise HTTPException(status_code=403, detail="Attachment key already used — cannot decrypt twice")
        if level == 2:
            plaintext = crypto_engine.decrypt_level2(crypto_engine.EncryptedPayload(**att_payload_dict), key_material)
        else:  # level 3, hybrid scheme
            plaintext = crypto_engine.decrypt_attachment_hybrid(crypto_engine.EncryptedPayload(**att_payload_dict), key_material)

    return Response(
        content=plaintext,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

