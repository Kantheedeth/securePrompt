import random

SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29,
    31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
    73, 79, 83, 89, 97, 101, 103, 107, 109, 113,
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173,
    179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251, 257, 263, 269, 271, 277, 281,
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349,
]


def n_bit_random(bits):
    candidate = random.getrandbits(bits)
    candidate |= (1 << (bits - 1))
    candidate |= 1
    return candidate


def get_low_level_prime(bits):
    while True:
        candidate = n_bit_random(bits)
        for divisor in SMALL_PRIMES:
            if candidate % divisor == 0 and divisor * divisor <= candidate:
                break
        else:
            return candidate


def is_miller_rabin_passed(candidate, rounds=20):
    if candidate in (2, 3):
        return True
    if candidate <= 1 or candidate % 2 == 0:
        return False

    exponent = candidate - 1
    max_divisions_by_two = 0
    while exponent % 2 == 0:
        exponent >>= 1
        max_divisions_by_two += 1

    def is_composite(witness):
        if pow(witness, exponent, candidate) == 1:
            return False
        for power in range(max_divisions_by_two):
            if pow(witness, (2 ** power) * exponent, candidate) == candidate - 1:
                return False
        return True

    for _ in range(rounds):
        witness = random.randrange(2, candidate - 1)
        if is_composite(witness):
            return False
    return True


def generate_prime(bits):
    while True:
        prime_candidate = get_low_level_prime(bits)
        if is_miller_rabin_passed(prime_candidate):
            return prime_candidate
