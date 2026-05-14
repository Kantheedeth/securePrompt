"""SecurePrompt client — builds an encrypted, signed prompt packet.

DESIGN NOTE — FILE-BASED TRANSPORT
====================================
This client writes the secure packet to a local JSON file rather than
transmitting it over a network connection. In a production deployment the
packet would be POSTed over a TLS-secured channel (e.g. HTTPS with mutual
TLS) to the audit proxy. Payload-level encryption (AES-256-CBC + RSA key
wrap) and the RSA digital signature provide end-to-end security that
survives any intermediate storage or forwarding hop — TLS would add a
defence-in-depth transport-layer protection on top of these payload-level
guarantees, ensuring the packet is not observable even in transit.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import key_manager
from rsa_engine import b64encode_bytes, encrypt_bytes, export_packet, load_key, sign_bytes


KEYS_DIR = Path(__file__).resolve().parent / "keys"


def sha256_digest(data: bytes) -> bytes:
    """Return the SHA-256 digest of data."""
    return hashlib.sha256(data).digest()


def generate_session_key() -> bytes:
    """Generate a cryptographically random 256-bit AES session key."""
    return os.urandom(32)


def aes_encrypt(data: bytes, session_key: bytes) -> tuple[bytes, bytes]:
    """Encrypt data with AES-256-CBC using a fresh random IV; return (iv, ciphertext)."""
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(session_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return iv, ciphertext


def create_secure_packet(
    prompt_text: str,
    sender_private_key: dict,
    receiver_public_key: dict,
    sender_id: str = "employee",
) -> dict:
    """Hash, sign, and encrypt prompt_text into a portable secure packet dict."""
    prompt_bytes = prompt_text.encode("utf-8")
    digest = sha256_digest(prompt_bytes)
    signature = sign_bytes(digest, sender_private_key)

    payload = {
        "sender_id": sender_id,
        "prompt": prompt_text,
        "signature": b64encode_bytes(signature),
        "digest": b64encode_bytes(digest),
    }
    payload_bytes = json.dumps(payload).encode("utf-8")

    session_key = generate_session_key()
    iv, ciphertext = aes_encrypt(payload_bytes, session_key)
    wrapped_key = encrypt_bytes(session_key, receiver_public_key)

    return {
        "sender_id": sender_id,
        "wrapped_session_key": b64encode_bytes(wrapped_key),
        "iv": b64encode_bytes(iv),
        "ciphertext": b64encode_bytes(ciphertext),
    }


def write_packet(packet: dict, output_path: str | Path) -> None:
    """Serialize packet to JSON and write to output_path, creating parents as needed."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(export_packet(packet), encoding="utf-8")


def build_default_paths() -> dict:
    """Return the default filesystem paths for keys and packet output."""
    return {
        "employee_private": KEYS_DIR / "employee_private.json",
        "server_public": KEYS_DIR / "server_public.json",
        "packet_output": Path(__file__).resolve().parent / "packets" / "secure_prompt_packet.json",
    }


def main() -> None:
    """Parse CLI arguments and create a secure packet from the supplied prompt."""
    defaults = build_default_paths()
    parser = argparse.ArgumentParser(description="SecurePrompt client packager")
    parser.add_argument("prompt", help="Prompt text to protect before transmission.")
    parser.add_argument(
        "--sender-id",
        default="employee",
        help=(
            "Identity label for this sender. The server will look up "
            "keys/{sender_id}_public.json to verify the signature."
        ),
    )
    parser.add_argument("--employee-private", default=str(defaults["employee_private"]))
    parser.add_argument("--server-public", default=str(defaults["server_public"]))
    parser.add_argument("--output", default=str(defaults["packet_output"]))
    args = parser.parse_args()

    employee_private = key_manager.load_private_key_encrypted(args.employee_private)
    server_public = load_key(args.server_public)
    packet = create_secure_packet(args.prompt, employee_private, server_public, args.sender_id)
    write_packet(packet, args.output)
    print(f"Secure packet written to {args.output}")


if __name__ == "__main__":
    main()
