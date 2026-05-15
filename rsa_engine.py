"""Custom RSA implementation for SecurePrompt (coursework demonstration).

KNOWN LIMITATIONS — NOT FOR PRODUCTION USE
==========================================
1. Block encoding (no OAEP):
   Plaintext is split into fixed-size blocks with a 2-byte length prefix instead
   of OAEP (Optimal Asymmetric Encryption Padding). Plain-block RSA is vulnerable
   to chosen-plaintext attacks because it is deterministic. A production system
   must use RSA-OAEP as specified in PKCS#1 v2.2 (RFC 8017).

2. Signing (no PSS):
   The RSA private-key transform is applied directly to the SHA-256 hash rather
   than using RSA-PSS (Probabilistic Signature Scheme). PSS has a formal security
   proof and randomises each signature. A production system should use RSA-PSS,
   available via cryptography.hazmat.primitives.asymmetric.padding.PSS.

3. No timing-attack blinding:
   Private-key modular exponentiations are not blinded. An attacker with precise
   timing measurements of many decryption calls could recover the private exponent
   via a side-channel attack. Production RSA libraries apply multiplicative
   blinding before each private-key operation to prevent this.

4. This module is intentionally self-contained to demonstrate RSA number theory
   from scratch: prime generation, modular inverse via the Extended Euclidean
   Algorithm, and square-and-multiply exponentiation. All of these are provided
   by the standard 'cryptography' library and should be used in production code.
"""

from __future__ import annotations

import base64
import json
import math
from pathlib import Path

from mulInverseByExtendedEuclidean import mul_inverse
from PrimeGenerator import generate_prime, is_miller_rabin_passed


DEFAULT_PUBLIC_EXPONENT: int = 65537


def modulo_exp(base: int, exponent: int, modulus: int) -> int:
    """Compute base^exponent mod modulus using square-and-multiply in O(log exponent)."""
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def gcd(a: int, b: int) -> int:
    """Return the greatest common divisor of a and b."""
    while b:
        a, b = b, a % b
    return a


def rsa_key_gen(
    bits: int = 1024,
    public_exponent: int = DEFAULT_PUBLIC_EXPONENT,
) -> tuple[dict, dict, dict]:
    """Generate an RSA key pair and return (public_key, private_key, metadata)."""
    if bits < 512:
        raise ValueError("RSA key size must be at least 512 bits.")

    prime_bits = bits // 2
    while True:
        p_value = generate_prime(prime_bits)
        q_value = generate_prime(prime_bits)
        if p_value == q_value:
            continue
        phi_n = (p_value - 1) * (q_value - 1)
        if gcd(public_exponent, phi_n) == 1:
            break

    modulus = p_value * q_value
    private_exponent = mul_inverse(public_exponent, phi_n)

    public_key = {"exponent": public_exponent, "modulus": modulus}
    private_key = {"exponent": private_exponent, "modulus": modulus}
    metadata: dict = {
        "p": p_value,
        "q": q_value,
        "phi_n": phi_n,
        "bits": modulus.bit_length(),
    }
    return public_key, private_key, metadata


def key_byte_lengths(key: dict) -> tuple[int, int]:
    """Return (plain_block_bytes, cipher_block_bytes) for the given key."""
    modulus_bytes = math.ceil(key["modulus"].bit_length() / 8)
    plain_block_bytes = max(3, modulus_bytes - 1)
    return plain_block_bytes, modulus_bytes


def rsa_transform_bytes(data: bytes, key: dict) -> bytes:
    """Apply the RSA forward transform (encrypt or sign) to raw bytes block by block."""
    plain_block_bytes, cipher_block_bytes = key_byte_lengths(key)
    max_chunk_size = plain_block_bytes - 2
    blocks = []
    if not data:
        data = b""
    for index in range(0, len(data) or 1, max_chunk_size):
        chunk = data[index:index + max_chunk_size]
        encoded_chunk = (len(chunk).to_bytes(2, "big") + chunk).ljust(plain_block_bytes, b"\x00")
        message_int = int.from_bytes(encoded_chunk, "big")
        cipher_int = modulo_exp(message_int, key["exponent"], key["modulus"])
        blocks.append(cipher_int.to_bytes(cipher_block_bytes, "big"))
    return b"".join(blocks)


def rsa_inverse_transform_bytes(data: bytes, key: dict) -> bytes:
    """Apply the RSA inverse transform (decrypt or verify) to raw bytes block by block."""
    plain_block_bytes, cipher_block_bytes = key_byte_lengths(key)
    if len(data) % cipher_block_bytes != 0:
        raise ValueError("Ciphertext length is not aligned to RSA block size.")

    blocks = []
    for index in range(0, len(data), cipher_block_bytes):
        chunk = data[index:index + cipher_block_bytes]
        cipher_int = int.from_bytes(chunk, "big")
        message_int = modulo_exp(cipher_int, key["exponent"], key["modulus"])
        if message_int >= 1 << (plain_block_bytes * 8):
            raise ValueError("RSA block decoding failed. Packet may be tampered or keys may not match.")
        decoded_chunk = message_int.to_bytes(plain_block_bytes, "big")
        chunk_length = int.from_bytes(decoded_chunk[:2], "big")
        if chunk_length > plain_block_bytes - 2:
            raise ValueError("RSA payload length is invalid. Packet may be tampered or keys may not match.")
        blocks.append(decoded_chunk[2:2 + chunk_length])

    return b"".join(blocks)


def encrypt_bytes(data: bytes, public_key: dict) -> bytes:
    """Encrypt data with an RSA public key (forward transform)."""
    return rsa_transform_bytes(data, public_key)


def decrypt_bytes(data: bytes, private_key: dict) -> bytes:
    """Decrypt data with an RSA private key (inverse transform)."""
    return rsa_inverse_transform_bytes(data, private_key)


def sign_bytes(data: bytes, private_key: dict) -> bytes:
    """Sign data by applying the RSA private-key transform to the digest bytes."""
    return rsa_transform_bytes(data, private_key)


def verify_signature_bytes(signature: bytes, public_key: dict) -> bytes:
    """Recover the digest from a signature using the RSA public-key inverse transform."""
    return rsa_inverse_transform_bytes(signature, public_key)


def key_to_serializable(
    key: dict,
    owner: str,
    role: str,
    metadata: dict | None = None,
) -> dict:
    """Convert an RSA key dict to a JSON-serializable dict."""
    payload: dict = {
        "owner": owner,
        "role": role,
        "exponent": str(key["exponent"]),
        "modulus": str(key["modulus"]),
    }
    if metadata:
        payload["metadata"] = {name: str(value) for name, value in metadata.items()}
    return payload


def save_key(
    path: Path | str,
    key: dict,
    owner: str,
    role: str,
    metadata: dict | None = None,
) -> None:
    """Serialize an RSA key to plaintext JSON and write to path (use for public keys only)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = key_to_serializable(key, owner, role, metadata)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def load_key(path: Path | str) -> dict:
    """Load a plaintext RSA public key from a JSON file."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return {
        "owner": payload.get("owner", "unknown"),
        "role": payload.get("role", "unknown"),
        "exponent": int(payload["exponent"]),
        "modulus": int(payload["modulus"]),
        "metadata": payload.get("metadata", {}),
    }


def export_packet(packet: dict) -> str:
    """Serialize a secure packet dict to an indented JSON string."""
    return json.dumps(packet, indent=2)


def import_packet(packet_text: str) -> dict:
    """Deserialize a JSON string to a secure packet dict."""
    return json.loads(packet_text)


def b64encode_bytes(data: bytes) -> str:
    """Base64-encode bytes to an ASCII string."""
    return base64.b64encode(data).decode("ascii")


def b64decode_bytes(data: str) -> bytes:
    """Decode a Base64 ASCII string to bytes."""
    return base64.b64decode(data.encode("ascii"))


def validate_generated_prime(prime_value: int) -> bool:
    """Verify that a generated prime passes the Miller-Rabin primality test."""
    return is_miller_rabin_passed(prime_value)
