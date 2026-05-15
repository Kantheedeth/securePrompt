"""Password-based protection for RSA private keys.

Derives a 256-bit AES key from a user passphrase using PBKDF2HMAC-SHA256,
then encrypts the private key JSON with AES-256-CBC before writing to disk.
The plaintext private key never touches disk in the new format.

Backward compatible: key files without an "encrypted" field are treated as
legacy plaintext JSON and loaded directly without prompting for a passphrase.

Set the SECUREPROMPT_PASSPHRASE environment variable to avoid interactive
prompts when running the server non-interactively (e.g. with gunicorn).
"""

from __future__ import annotations

import base64
import getpass
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS: int = 390_000
SALT_SIZE: int = 16


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from passphrase + salt using PBKDF2HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def prompt_passphrase(confirm: bool = False) -> str:
    """Read passphrase from SECUREPROMPT_PASSPHRASE env var or interactive prompt."""
    env_pass = os.environ.get("SECUREPROMPT_PASSPHRASE")
    if env_pass:
        return env_pass
    passphrase = getpass.getpass("Enter private key passphrase: ")
    if confirm:
        confirm_pass = getpass.getpass("Confirm passphrase: ")
        if passphrase != confirm_pass:
            raise ValueError("Passphrases do not match.")
    return passphrase


def encrypt_private_key(key_json: str, passphrase: str) -> dict:
    """Return an AES-256-CBC encryption envelope dict for the given key JSON string."""
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(16)
    derived_key = _derive_key(passphrase, salt)

    data = key_json.encode("utf-8")
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return {
        "encrypted": True,
        "kdf": "PBKDF2HMAC-SHA256",
        "iterations": PBKDF2_ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_private_key(envelope: dict, passphrase: str) -> str:
    """Decrypt an AES-256-CBC encryption envelope and return the raw key JSON string."""
    salt = base64.b64decode(envelope["salt"])
    iv = base64.b64decode(envelope["iv"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    derived_key = _derive_key(passphrase, salt)

    cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")


def save_private_key_encrypted(path: Path | str, key_payload: dict, passphrase: str) -> None:
    """Serialize key_payload to JSON, encrypt with passphrase, and write to path."""
    key_json = json.dumps(key_payload, indent=2)
    envelope = encrypt_private_key(key_json, passphrase)
    Path(path).write_text(json.dumps(envelope, indent=2), encoding="utf-8")


def load_private_key_encrypted(path: Path | str, passphrase: str | None = None) -> dict:
    """Load a private key from path, decrypting with passphrase when the file is encrypted.

    Falls back to plain JSON parsing for legacy unencrypted key files so that
    existing keys remain usable without regeneration.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not raw.get("encrypted"):
        return {
            "owner": raw.get("owner", "unknown"),
            "role": raw.get("role", "unknown"),
            "exponent": int(raw["exponent"]),
            "modulus": int(raw["modulus"]),
            "metadata": raw.get("metadata", {}),
        }
    if passphrase is None:
        passphrase = prompt_passphrase()
    key_json = decrypt_private_key(raw, passphrase)
    payload = json.loads(key_json)
    return {
        "owner": payload.get("owner", "unknown"),
        "role": payload.get("role", "unknown"),
        "exponent": int(payload["exponent"]),
        "modulus": int(payload["modulus"]),
        "metadata": payload.get("metadata", {}),
    }
