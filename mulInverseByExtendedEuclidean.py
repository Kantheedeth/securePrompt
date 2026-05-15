from __future__ import annotations


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Return (gcd, x, y) satisfying a*x + b*y == gcd (Bezout's identity)."""
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t


def mul_inverse(value: int, modulus: int) -> int:
    """Return the modular multiplicative inverse of value mod modulus.

    Uses the Extended Euclidean Algorithm. Raises ValueError when the inverse
    does not exist (i.e. gcd(value, modulus) != 1).
    """
    gcd, x_value, _ = extended_gcd(value, modulus)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist for non-coprime values.")
    return x_value % modulus


def mulInverse(value: int, modulus: int) -> int:
    """Alias for mul_inverse kept for backward compatibility."""
    return mul_inverse(value, modulus)
