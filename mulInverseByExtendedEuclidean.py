def extended_gcd(a, b):
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    return old_r, old_s, old_t


def mul_inverse(value, modulus):
    gcd, x_value, _ = extended_gcd(value, modulus)
    if gcd != 1:
        raise ValueError("Modular inverse does not exist for non-coprime values.")
    return x_value % modulus


def mulInverse(value, modulus):
    return mul_inverse(value, modulus)
