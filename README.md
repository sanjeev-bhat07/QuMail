# QuMail — Quantum-Secured Email Client

**Smart India Hackathon 2026 · Team CodexQuantum**

Problem Statement (Internal Selection Hackathon)SIH260004 · Indian Space Research Organisation (ISRO)

QuMail is an email client that integrates Quantum Key Distribution (QKD)
with existing email infrastructure — Gmail, Yahoo, and other standard
providers — without requiring any changes to those providers' servers.
Encryption happens entirely at the application layer, so QuMail-secured
messages travel over ordinary SMTP/IMAP while remaining unreadable to
anyone without access to the matching quantum key.

## Why

Conventional email encryption (RSA/TLS) is expected to become breakable
once large-scale quantum computers mature. Adversaries can already record
encrypted traffic today and decrypt it retroactively once that happens —
a threat model known as "harvest now, decrypt later." QKD offers a way
out: keys distributed via QKD carry information-theoretic security
guarantees that don't depend on an attacker's future computing power.

QuMail's goal is to make that security usable inside a real email
workflow, today, on top of infrastructure people already use.

## Features

- **Three configurable security levels**, selectable per message:

  | Level | Name | Mechanism |
  |---|---|---|
  | L1 | No Quantum Security | Standard TLS only (baseline) |
  | L2 | Quantum-Aided AES | QKD key → HKDF → AES-256-GCM |
  | L3 | Quantum-Secure (OTP) | One-Time Pad — information-theoretically unbreakable |

- **Full interoperability** with Gmail and other standard providers via
  SMTP/IMAP — no server-side changes required
- **Key Manager (KM) integration** via an API shaped to the ETSI GS QKD
  014 industry standard, so a real QKD vendor's KM can be substituted in
  later with no changes to the rest of the application
- **Encrypted attachments** of any size, via a hybrid scheme: a random
  AES session key is generated locally, wrapped with a QKD key using
  OTP, and used to encrypt the attachment with AES-256-GCM — this keeps
  attachments quantum-key-protected without exhausting the (small) QKD
  key bank
- **Enforced single-use keys** — the Key Manager itself rejects any
  attempt to reuse a key for decryption, which is what makes the OTP
  security guarantee real rather than assumed
- **Live key-bank status** in the UI, so users can see key availability
  before it becomes a problem

## Architecture

```
frontend/index.html  --HTTP-->  backend/main.py (orchestrator)
                                       |
                        +--------------+--------------+
                        |              |               |
                 backend/km_client  crypto_engine   email_layer
                        |                                |
                mock_km/main.py                   Gmail SMTP/IMAP
                (ETSI GS QKD 014-shaped API)
```

| Component | Responsibility |
|---|---|
| `mock_km/main.py` | Key Manager server — issues and tracks quantum keys. Swappable for real QKD hardware with no changes elsewhere. |
| `backend/crypto_engine.py` | Implements all three security levels plus the hybrid attachment scheme. |
| `backend/km_client.py` | HTTP client abstracting the KM API. |
| `backend/email_layer.py` | SMTP/IMAP integration; packages ciphertext + metadata into standard emails. |
| `backend/db.py` | Local SQLite cache for sent-message metadata. |
| `frontend/index.html` | Compose/inbox UI with per-message security level selection and live key-bank status. |

## Getting Started

### Prerequisites

- Python 3.11+
- A Gmail account with an [App Password](https://myaccount.google.com/apppasswords)
  (only needed for actually sending/receiving — see below)

### Installation

```bash
git clone <this-repo-url>
cd qumail
pip install -r requirements.txt
```

### Configuration (optional)

To send/receive real email, set:

```bash
export QUMAIL_GMAIL_USER="youraddress@gmail.com"
export QUMAIL_GMAIL_APP_PASSWORD="your16charapppassword"
```

Without these set, the app still runs the full encryption pipeline and
reports the result instead of sending — useful for exploring the
Key Manager and crypto engine on their own.

### Running

Two servers need to run concurrently:

```bash
# Terminal 1 — Key Manager
cd mock_km
python main.py        # http://localhost:8001

# Terminal 2 — Orchestrator backend
cd backend
python main.py        # http://localhost:8000
```

Then open `frontend/index.html` in a browser.

## Security Model

QuMail's design assumes both communicating parties already hold a
shared, pre-generated symmetric key bank — consistent with how QKD
systems provision keys in practice. The `key_id` travels alongside the
ciphertext in cleartext, but this reveals nothing to an interceptor:
only a party with independent access to the shared key bank can resolve
a `key_id` into actual key material.

Level 3 (OTP) provides unconditional security in the information-
theoretic sense — given a truly random key at least as long as the
message, used exactly once, the ciphertext provably reveals zero
information about the plaintext. This holds regardless of an attacker's
computational resources, including future quantum computers. QuMail
enforces the single-use requirement server-side, at the Key Manager,
rather than relying on client behavior.

## Roadmap

- Real QKD hardware integration (e.g. ID Quantique, Toshiba) via the
  existing ETSI 014-shaped interface
- Browser extension / Outlook add-in — running as a layer inside
  Gmail's and Outlook's own interfaces, rather than a standalone client
- OAuth2 authentication in place of Gmail App Passwords
- True MIME multipart attachment handling for large files
- PQC-secured control channel for key-request authentication

## Known Limitations

- Uses a mock Key Manager; real QKD hardware integration is future work
- Authenticates to Gmail via App Password rather than OAuth2
- Attachments are currently embedded as base64 within the message
  payload rather than as native MIME attachment parts

## Team

**CodexQuantum** · Mentor: Dr. Vinutha K
