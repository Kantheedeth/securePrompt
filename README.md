# SecurePrompt

SecurePrompt is a cryptographic middleware demo for securing enterprise AI prompts before they reach an internal audit proxy.

It demonstrates two guarantees:

- Authentication: the employee signs the prompt digest with a custom RSA private key, proving who sent it.
- Confidentiality: the prompt payload is encrypted with a one-time AES-256 session key, then that session key is wrapped with the server's custom RSA public key.

## Technical Challenge Coverage

The project includes custom number theory code used by the RSA layer:

- `PrimeGenerator.py`: Miller-Rabin primality testing and large-prime generation
- `mulInverseByExtendedEuclidean.py`: Extended Euclidean Algorithm for modular inverse
- `rsa_engine.py`: square-and-multiply modular exponentiation and RSA block operations

## Secure Pipeline

1. The client hashes the prompt with SHA-256.
2. The client signs that digest with the employee private RSA key.
3. The client packages `prompt + signature + digest` into a JSON payload.
4. The payload is encrypted with a random AES-256 session key.
5. The AES key is encrypted with the server public RSA key.
6. The server decrypts the AES key, decrypts the payload, recomputes the SHA-256 digest, and verifies the signature with the employee public key.
7. The result is written to `audit.log` as accepted or rejected.

## Files

- `client.py`: builds a secure packet
- `server.py`: verifies packets or runs the Flask audit proxy UI
- `key_setup.py`: generates employee and server RSA key pairs
- `keys/`: generated RSA keys
- `packets/`: sample secure packets
- `templates/index.html`: browser demo interface

## Setup

```bash
python -m venv .venv
./.venv/bin/pip install -r requirements.txt
```

## Generate Keys

Default generation uses a 2048-bit RSA modulus, which means two 1024-bit primes.

```bash
./.venv/bin/python key_setup.py
```

## Command-Line Demo

Create a protected packet:

```bash
./.venv/bin/python client.py "Review the unreleased merger briefing and highlight antitrust risk."
```

Verify the packet at the audit proxy:

```bash
./.venv/bin/python server.py --packet packets/secure_prompt_packet.json
```

## Web Demo

Run the Flask interface:

```bash
./.venv/bin/python server.py --serve
```

Then open `http://127.0.0.1:5000`.

The UI can also simulate a man-in-the-middle modification by corrupting the ciphertext before verification.

## Notes

- RSA operations are implemented in-house for the coursework requirement.
- SHA-256 and AES-256 come from standard cryptographic libraries to mirror a realistic hybrid enterprise design.
- Sample packets must be regenerated whenever keys are regenerated, because the wrapped AES key depends on the current RSA key pair.
