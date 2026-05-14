import argparse
import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from flask import Flask, render_template, request

from client import KEYS_DIR, create_secure_packet
from rsa_engine import (
    b64decode_bytes,
    import_packet,
    load_key,
    decrypt_bytes,
    verify_signature_bytes,
)


BASE_DIR = Path(__file__).resolve().parent
AUDIT_LOG = BASE_DIR / "audit.log"
PACKETS_DIR = BASE_DIR / "packets"


def aes_decrypt(ciphertext, session_key, iv):
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def verify_secure_packet(packet, server_private_key, sender_public_key):
    wrapped_key = b64decode_bytes(packet["wrapped_session_key"])
    iv = b64decode_bytes(packet["iv"])
    ciphertext = b64decode_bytes(packet["ciphertext"])

    session_key = decrypt_bytes(wrapped_key, server_private_key)
    try:
        payload_bytes = aes_decrypt(ciphertext, session_key, iv)
        payload = json.loads(payload_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("Payload integrity check failed. Packet may be tampered or corrupted.") from exc

    prompt = payload["prompt"]
    prompt_digest = hashlib.sha256(prompt.encode("utf-8")).digest()
    received_digest = base64.b64decode(payload["digest"])
    signature = base64.b64decode(payload["signature"])
    decrypted_signature_digest = verify_signature_bytes(signature, sender_public_key)

    digest_matches = prompt_digest == received_digest
    signature_matches = prompt_digest == decrypted_signature_digest

    return {
        "accepted": digest_matches and signature_matches,
        "prompt": prompt,
        "sender_id": payload["sender_id"],
        "digest_matches": digest_matches,
        "signature_matches": signature_matches,
    }


def reject_result(packet, error_message):
    return {
        "accepted": False,
        "sender_id": packet.get("sender_id", "employee_001"),
        "digest_matches": False,
        "signature_matches": False,
        "prompt": "",
        "error": error_message,
    }


def log_audit_event(result, packet=None):
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "sender_id": result.get("sender_id", "unknown"),
        "accepted": result["accepted"],
        "digest_matches": result.get("digest_matches"),
        "signature_matches": result.get("signature_matches"),
        "prompt_preview": result.get("prompt", "")[:120],
    }
    if packet:
        entry["packet_fields"] = list(packet.keys())
    with AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry) + "\n")


def read_packet(path):
    return import_packet(Path(path).read_text(encoding="utf-8"))


def build_default_paths():
    return {
        "employee_public": KEYS_DIR / "employee_public.json",
        "server_private": KEYS_DIR / "server_private.json",
        "packet_input": PACKETS_DIR / "secure_prompt_packet.json",
    }


def create_app():
    app = Flask(__name__)
    defaults = build_default_paths()

    @app.get("/")
    def index():
        audit_tail = []
        if AUDIT_LOG.exists():
            lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-5:]
            audit_tail = [json.loads(line) for line in reversed(lines)]
        return render_template("index.html", result=None, audit_tail=audit_tail, prompt_value="")

    @app.post("/submit")
    def submit_prompt():
        prompt_text = request.form.get("prompt", "").strip()
        tamper = request.form.get("tamper") == "on"

        if not prompt_text:
            return render_template(
                "index.html",
                result={"accepted": False, "error": "Prompt cannot be empty."},
                audit_tail=[],
                prompt_value="",
            )

        employee_private = load_key(KEYS_DIR / "employee_private.json")
        employee_public = load_key(defaults["employee_public"])
        server_private = load_key(defaults["server_private"])
        server_public = load_key(KEYS_DIR / "server_public.json")

        packet = create_secure_packet(prompt_text, employee_private, server_public)
        if tamper:
            ciphertext = bytearray(b64decode_bytes(packet["ciphertext"]))
            if ciphertext:
                ciphertext[0] ^= 1
            packet["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")

        try:
            result = verify_secure_packet(packet, server_private, employee_public)
        except Exception as exc:
            result = reject_result(packet, str(exc))
            result["prompt"] = prompt_text

        log_audit_event(result, packet)
        audit_tail = []
        if AUDIT_LOG.exists():
            lines = AUDIT_LOG.read_text(encoding="utf-8").splitlines()[-5:]
            audit_tail = [json.loads(line) for line in reversed(lines)]
        return render_template("index.html", result=result, audit_tail=audit_tail, prompt_value=prompt_text)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    return app


def main():
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
        app = create_app()
        app.run(host=args.host, port=args.port, debug=True)
        return

    packet = read_packet(args.packet)
    employee_public = load_key(args.employee_public)
    server_private = load_key(args.server_private)
    try:
        result = verify_secure_packet(packet, server_private, employee_public)
    except Exception as exc:
        result = reject_result(packet, str(exc))
    log_audit_event(result, packet)
    print(json.dumps(result, indent=2))


app = create_app()


if __name__ == "__main__":
    main()
