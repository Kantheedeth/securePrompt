"""SecurePrompt audit proxy — verifies encrypted prompt packets and logs every decision.

SECURITY MODEL COMPARISON
==========================
- vs TLS:
  TLS secures the transport channel between two endpoints; once decrypted at the
  server the payload is plaintext. SecurePrompt encrypts the payload itself, so
  a packet can be stored, forwarded, or archived while remaining confidential and
  cryptographically verifiable at any future point — independent of the channel.

- vs PGP:
  PGP provides equivalent payload-level encryption and signing, but has no
  mandatory server-side audit trail. SecurePrompt adds a tamper-evident,
  append-only audit log (audit.log) that records every verification outcome with
  a key fingerprint and non-repudiation status, enabling compliance reporting and
  legal evidence that a specific sender created a specific prompt.

- vs S/MIME:
  S/MIME achieves similar goals for email but relies on standard library RSA
  (PKCS#1 / CMS). SecurePrompt intentionally uses a custom RSA implementation
  (rsa_engine.py) to demonstrate the underlying number theory — prime generation,
  modular exponentiation, and the Extended Euclidean Algorithm — as a coursework
  exercise in applied cryptography.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, render_template, request

import key_manager
from client import KEYS_DIR, create_secure_packet
from rsa_engine import (
    b64decode_bytes,
    decrypt_bytes,
    import_packet,
    load_key,
    verify_signature_bytes,
)

BASE_DIR = Path(__file__).resolve().parent
AUDIT_LOG = BASE_DIR / "audit.log"
PACKETS_DIR = BASE_DIR / "packets"


# ---------------------------------------------------------------------------
# Cryptographic helpers
# ---------------------------------------------------------------------------

def aes_decrypt(ciphertext: bytes, session_key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-256-CBC ciphertext and strip PKCS7 padding."""
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def compute_key_fingerprint(key: dict) -> str:
    """Return the first 16 hex chars of SHA-256 of the key modulus (traceable key ID)."""
    modulus_bytes = str(key["modulus"]).encode("utf-8")
    return hashlib.sha256(modulus_bytes).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Key validation
# ---------------------------------------------------------------------------

def check_key_expiry(key: dict) -> tuple[bool, str]:
    """Return (is_expired, reason_string) by comparing created_at + ttl_days to now.

    Returns (False, '') when the key has no expiry metadata, treating it as valid.
    """
    meta = key.get("metadata", {})
    created_at_str = meta.get("created_at")
    if not created_at_str:
        return False, ""
    try:
        ttl_days = int(meta.get("ttl_days", 365))
        created_at = datetime.fromisoformat(created_at_str)
        expiry = created_at + timedelta(days=ttl_days)
        if datetime.now(timezone.utc) > expiry:
            return True, f"expired on {expiry.date().isoformat()} (TTL: {ttl_days} days)"
    except (ValueError, TypeError):
        return False, ""
    return False, ""


def _lookup_sender_key(sender_id: str, keys_dir: Path) -> tuple[dict, bool]:
    """Load the public key for sender_id; return (key, sender_id_matches_filename).

    Tries {sender_id}_public.json first. Falls back to employee_public.json when
    the preferred file is absent; the boolean is False in that case to signal a
    filename/sender_id mismatch that should be logged as a warning.
    """
    preferred = keys_dir / f"{sender_id}_public.json"
    fallback = keys_dir / "employee_public.json"
    if preferred.exists():
        return load_key(preferred), True
    if fallback.exists():
        return load_key(fallback), False
    raise FileNotFoundError(
        f"No public key found for sender_id '{sender_id}'. "
        f"Tried '{preferred}' and '{fallback}'."
    )


# ---------------------------------------------------------------------------
# Packet verification
# ---------------------------------------------------------------------------

def verify_secure_packet(
    packet: dict,
    server_private_key: dict,
    keys_dir: Path,
) -> dict:
    """Decrypt and verify a secure packet; return a result dict with all check outcomes.

    Performs sender key lookup, key expiry check, AES decryption, SHA-256 digest
    comparison, and RSA signature verification. All outcomes are included in the
    returned dict so they can be logged and displayed without additional computation.
    """
    outer_sender_id = packet.get("sender_id", "employee")
    sender_public_key, sender_id_key_match = _lookup_sender_key(outer_sender_id, keys_dir)

    warnings: list[str] = []
    if not sender_id_key_match:
        warnings.append(
            f"sender_id '{outer_sender_id}' does not match key filename; "
            f"used fallback employee_public.json"
        )

    is_expired, expiry_reason = check_key_expiry(sender_public_key)
    if is_expired:
        warnings.append(f"Key {expiry_reason}")
        return {
            "accepted": False,
            "sender_id": outer_sender_id,
            "digest_matches": False,
            "signature_matches": False,
            "non_repudiation": False,
            "rejection_reason": f"key expired: {expiry_reason}",
            "prompt": "",
            "key_expired": True,
            "sender_id_key_match": sender_id_key_match,
            "inner_outer_id_match": True,
            "sender_public_key": sender_public_key,
            "warnings": warnings,
        }

    wrapped_key = b64decode_bytes(packet["wrapped_session_key"])
    iv = b64decode_bytes(packet["iv"])
    ciphertext = b64decode_bytes(packet["ciphertext"])

    session_key = decrypt_bytes(wrapped_key, server_private_key)
    try:
        payload_bytes = aes_decrypt(ciphertext, session_key, iv)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(
            "Payload integrity check failed. Packet may be tampered or corrupted."
        ) from exc

    prompt = payload["prompt"]
    prompt_digest = hashlib.sha256(prompt.encode("utf-8")).digest()
    received_digest = base64.b64decode(payload["digest"])
    signature = base64.b64decode(payload["signature"])
    recovered_digest = verify_signature_bytes(signature, sender_public_key)

    digest_matches = prompt_digest == received_digest
    signature_matches = prompt_digest == recovered_digest

    inner_sender_id = payload.get("sender_id", outer_sender_id)
    inner_outer_id_match = inner_sender_id == outer_sender_id
    if not inner_outer_id_match:
        warnings.append(
            f"sender_id in decrypted payload ('{inner_sender_id}') "
            f"differs from outer packet sender_id ('{outer_sender_id}')"
        )

    accepted = digest_matches and signature_matches
    if accepted:
        rejection_reason = ""
    elif not digest_matches and not signature_matches:
        rejection_reason = "digest and signature mismatch"
    elif not digest_matches:
        rejection_reason = "digest mismatch"
    else:
        rejection_reason = "signature mismatch"

    return {
        "accepted": accepted,
        "prompt": prompt,
        "sender_id": outer_sender_id,
        "digest_matches": digest_matches,
        "signature_matches": signature_matches,
        "non_repudiation": digest_matches and signature_matches,
        "rejection_reason": rejection_reason,
        "key_expired": False,
        "sender_id_key_match": sender_id_key_match,
        "inner_outer_id_match": inner_outer_id_match,
        "sender_public_key": sender_public_key,
        "warnings": warnings,
    }


def reject_result(packet: dict, error_message: str) -> dict:
    """Build a rejection result dict for packets that fail before signature verification."""
    return {
        "accepted": False,
        "sender_id": packet.get("sender_id", "employee"),
        "digest_matches": False,
        "signature_matches": False,
        "non_repudiation": False,
        "rejection_reason": f"decryption failed: {error_message}",
        "prompt": "",
        "error": error_message,
        "key_expired": False,
        "sender_id_key_match": True,
        "inner_outer_id_match": True,
        "sender_public_key": None,
        "warnings": [],
    }


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def log_audit_event(result: dict, packet: dict | None = None) -> None:
    """Append a JSON audit event to audit.log for every verification attempt."""
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    sender_public_key = result.get("sender_public_key")
    entry: dict = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": result.get("sender_id", "unknown"),
        "accepted": result["accepted"],
        "digest_matches": result.get("digest_matches"),
        "signature_matches": result.get("signature_matches"),
        "non_repudiation": result.get("non_repudiation", False),
        "rejection_reason": result.get("rejection_reason", ""),
        "key_fingerprint": (
            compute_key_fingerprint(sender_public_key) if sender_public_key else None
        ),
        "prompt_preview": result.get("prompt", "")[:120],
        "warnings": result.get("warnings", []),
    }
    if packet:
        entry["packet_fields"] = list(packet.keys())
    with AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------

def read_packet(path: str | Path) -> dict:
    """Read and deserialize a secure packet JSON file."""
    return import_packet(Path(path).read_text(encoding="utf-8"))


def build_default_paths() -> dict:
    """Return default filesystem paths for keys and packet input."""
    return {
        "employee_public": KEYS_DIR / "employee_public.json",
        "server_private": KEYS_DIR / "server_private.json",
        "packet_input": PACKETS_DIR / "secure_prompt_packet.json",
    }


def _read_audit_tail(n: int = 5) -> list[dict]:
    """Return the last n audit log entries in reverse chronological order."""
    if not AUDIT_LOG.exists():
        return []
    lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-n:]
    return [json.loads(line) for line in reversed(lines)]


def _get_passphrase_if_needed(private_key_paths: list[Path]) -> str | None:
    """Prompt for a passphrase once if any of the given private key files is encrypted."""
    for path in private_key_paths:
        try:
            raw = json.loads(Path(path).read_text(encoding="utf-8"))
            if raw.get("encrypted"):
                return key_manager.prompt_passphrase()
        except (FileNotFoundError, json.JSONDecodeError):
            continue
    return None


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:
    """Create and configure the Flask audit proxy application.

    All four RSA keys are loaded once at startup and cached in app.config so
    routes never repeat the expensive PBKDF2 key derivation on every request.
    If private key files are not yet present (before key_setup.py is run) the
    app starts with None keys and routes return a helpful error message.
    """
    defaults = build_default_paths()
    flask_app = Flask(__name__)

    passphrase = _get_passphrase_if_needed([
        KEYS_DIR / "employee_private.json",
        defaults["server_private"],
    ])

    try:
        _server_private = key_manager.load_private_key_encrypted(
            defaults["server_private"], passphrase
        )
        _employee_private = key_manager.load_private_key_encrypted(
            KEYS_DIR / "employee_private.json", passphrase
        )
    except FileNotFoundError:
        _server_private = None
        _employee_private = None

    try:
        _employee_public = load_key(defaults["employee_public"])
        _server_public = load_key(KEYS_DIR / "server_public.json")
    except FileNotFoundError:
        _employee_public = None
        _server_public = None

    flask_app.config.update(
        SERVER_PRIVATE=_server_private,
        EMPLOYEE_PRIVATE=_employee_private,
        EMPLOYEE_PUBLIC=_employee_public,
        SERVER_PUBLIC=_server_public,
        KEYS_DIR=KEYS_DIR,
    )

    @flask_app.get("/")
    def index() -> str:
        """Render the main gateway form with the latest audit tail."""
        audit_tail = _read_audit_tail()
        return render_template("index.html", result=None, audit_tail=audit_tail, prompt_value="")

    @flask_app.post("/submit")
    def submit_prompt() -> str:
        """Receive a prompt, wrap it into a secure packet, verify, and log the outcome."""
        prompt_text = request.form.get("prompt", "").strip()
        tamper = request.form.get("tamper") == "on"

        if not prompt_text:
            return render_template(
                "index.html",
                result={"accepted": False, "error": "Prompt cannot be empty."},
                audit_tail=[],
                prompt_value="",
            )

        employee_private = flask_app.config["EMPLOYEE_PRIVATE"]
        server_private = flask_app.config["SERVER_PRIVATE"]
        server_public = flask_app.config["SERVER_PUBLIC"]
        keys_dir: Path = flask_app.config["KEYS_DIR"]

        if not employee_private or not server_private or not server_public:
            error_result = {
                "accepted": False,
                "error": "Keys not loaded. Run key_setup.py first.",
                "sender_id": "unknown",
                "digest_matches": False,
                "signature_matches": False,
                "non_repudiation": False,
                "rejection_reason": "keys unavailable",
                "warnings": [],
                "sender_public_key": None,
            }
            return render_template(
                "index.html", result=error_result, audit_tail=[], prompt_value=prompt_text
            )

        packet = create_secure_packet(prompt_text, employee_private, server_public)
        if tamper:
            ciphertext = bytearray(b64decode_bytes(packet["ciphertext"]))
            if ciphertext:
                ciphertext[0] ^= 1
            packet["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")

        try:
            result = verify_secure_packet(packet, server_private, keys_dir)
        except Exception as exc:
            result = reject_result(packet, str(exc))
            result["prompt"] = prompt_text

        log_audit_event(result, packet)
        audit_tail = _read_audit_tail()
        return render_template(
            "index.html", result=result, audit_tail=audit_tail, prompt_value=prompt_text
        )

    @flask_app.get("/health")
    def health() -> dict:
        """Return a simple liveness check response."""
        return {"status": "ok"}

    return flask_app


# Module-level app instance for `flask run`.
# Set SECUREPROMPT_PASSPHRASE in the environment before importing if keys are encrypted.
app = create_app()


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Verify a packet file on the CLI, or start the Flask web server with --serve."""
    defaults = build_default_paths()
    parser = argparse.ArgumentParser(description="SecurePrompt audit proxy")
    parser.add_argument("--packet", default=str(defaults["packet_input"]))
    parser.add_argument("--employee-public", default=str(defaults["employee_public"]))
    parser.add_argument("--server-private", default=str(defaults["server_private"]))
    parser.add_argument("--serve", action="store_true", help="Run the Flask web interface.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    if args.serve:
        app.run(host=args.host, port=args.port, debug=True)
        return

    # CLI verification mode — reuse the pre-loaded key from the module-level app if
    # available; otherwise load it fresh (prompts for passphrase if encrypted).
    server_private = app.config.get("SERVER_PRIVATE") or key_manager.load_private_key_encrypted(
        args.server_private
    )
    packet = read_packet(args.packet)
    try:
        result = verify_secure_packet(packet, server_private, KEYS_DIR)
    except Exception as exc:
        result = reject_result(packet, str(exc))
    log_audit_event(result, packet)
    printable = {k: v for k, v in result.items() if k != "sender_public_key"}
    print(json.dumps(printable, indent=2))


if __name__ == "__main__":
    main()
