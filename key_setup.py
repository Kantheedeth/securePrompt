import argparse
from pathlib import Path

from rsa_engine import rsa_key_gen, save_key, validate_generated_prime


BASE_DIR = Path(__file__).resolve().parent
KEYS_DIR = BASE_DIR / "keys"


def generate_named_keypair(owner, bits):
    public_key, private_key, metadata = rsa_key_gen(bits)
    if not validate_generated_prime(int(metadata["p"])) or not validate_generated_prime(int(metadata["q"])):
        raise ValueError(f"Prime validation failed for {owner}.")

    save_key(KEYS_DIR / f"{owner}_public.json", public_key, owner, "public", metadata)
    save_key(KEYS_DIR / f"{owner}_private.json", private_key, owner, "private", metadata)
    return metadata


def main():
    parser = argparse.ArgumentParser(description="Generate SecurePrompt RSA key pairs.")
    parser.add_argument(
        "--bits",
        type=int,
        default=2048,
        choices=[1024, 2048],
        help="RSA modulus size. Use 2048 to generate keys from two 1024-bit primes.",
    )
    args = parser.parse_args()

    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    employee_meta = generate_named_keypair("employee", args.bits)
    server_meta = generate_named_keypair("server", args.bits)

    print(f"Generated employee and server RSA key pairs in {KEYS_DIR}")
    print(f"Employee modulus bits: {employee_meta['bits']}")
    print(f"Server modulus bits: {server_meta['bits']}")


if __name__ == "__main__":
    main()
