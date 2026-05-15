"""RSA key pair generation for SecurePrompt.

Generates 2048-bit (default) RSA key pairs for the employee and server roles.
Private keys are encrypted with a user-supplied passphrase via PBKDF2HMAC +
AES-256-CBC (see key_manager.py) so plaintext private material never rests on
disk in the new format.  Public keys are stored as plaintext JSON.

Each generated key JSON includes two metadata fields used by the server:
  - created_at: UTC ISO-8601 timestamp of generation
  - ttl_days:   days until the key is considered expired (default 365)

The server rejects packets whose signing key has passed its expiry date and
logs a warning to audit.log.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import key_manager
from rsa_engine import key_to_serializable, rsa_key_gen, save_key, validate_generated_prime


BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"


def generate_named_keypair(
    owner: str,
    bits: int,
    passphrase: str,
    ttl_days: int = 365,
) -> dict:
    """Generate an RSA key pair for owner, save encrypted private + plaintext public keys.

    Returns the metadata dict (includes bits, created_at, ttl_days).
    """
    public_key, private_key, metadata = rsa_key_gen(bits)
    if not validate_generated_prime(int(metadata["p"])) or not validate_generated_prime(int(metadata["q"])):
        raise ValueError(f"Prime validation failed for {owner}.")

    metadata["created_at"] = datetime.now(timezone.utc).isoformat()
    metadata["ttl_days"] = ttl_days

    save_key(KEYS_DIR / f"{owner}_public.json", public_key, owner, "public", metadata)

    private_payload = key_to_serializable(private_key, owner, "private", metadata)
    key_manager.save_private_key_encrypted(
        KEYS_DIR / f"{owner}_private.json", private_payload, passphrase
    )

    return metadata


def main() -> None:
    """Parse arguments, prompt for a passphrase once, and generate both key pairs."""
    parser = argparse.ArgumentParser(description="Generate SecurePrompt RSA key pairs.")
    parser.add_argument(
        "--bits",
        type=int,
        default=2048,
        choices=[1024, 2048],
        help="RSA modulus size. Use 2048 to generate keys from two 1024-bit primes.",
    )
    parser.add_argument(
        "--ttl-days",
        type=int,
        default=365,
        help="Days before the generated keys expire (default: 365).",
    )
    args = parser.parse_args()

    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    print("Private keys will be password-protected.")
    passphrase = key_manager.prompt_passphrase(confirm=True)

    employee_meta = generate_named_keypair("employee", args.bits, passphrase, args.ttl_days)
    server_meta = generate_named_keypair("server", args.bits, passphrase, args.ttl_days)

    print(f"Generated employee and server RSA key pairs in {KEYS_DIR}")
    print(f"Employee modulus bits : {employee_meta['bits']}")
    print(f"Server modulus bits   : {server_meta['bits']}")
    print(f"Key TTL               : {args.ttl_days} days")
    print(f"Keys expire after     : {employee_meta['created_at'][:10]} + {args.ttl_days}d")


if __name__ == "__main__":
    main()
