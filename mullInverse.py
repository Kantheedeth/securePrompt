import myRSA
import hashlib
import os
import json


def preview_text(text, limit=80):
    if len(text) <= limit:
        return text
    return text[:limit] + "..."


def preview_bytes(data, limit=24):
    hex_data = data.hex()
    if len(hex_data) <= limit * 2:
        return hex_data
    return hex_data[: limit * 2] + "..."

def generate_symmetric_key():
    """Generates a random 32-byte (256-bit) symmetric key."""
    return os.urandom(32)

def symmetric_encrypt(plaintext_string, key_bytes):
    """
    A simple, standard-library pure Python stream cipher.
    Acts like AES-CTR mode, using SHA-256 to generate a keystream.
    """
    plaintext_bytes = plaintext_string.encode('utf-8')
    nonce = os.urandom(8)
    ciphertext = bytearray()
    counter = 0
    
    for i in range(0, len(plaintext_bytes), 32):
        block_data = nonce + counter.to_bytes(8, 'big') + key_bytes
        keystream = hashlib.sha256(block_data).digest()
        chunk = plaintext_bytes[i:i+32]
        for j in range(len(chunk)):
            ciphertext.append(chunk[j] ^ keystream[j])
        counter += 1
        
    return nonce + bytes(ciphertext)

def symmetric_decrypt(ciphertext_bytes, key_bytes):
    """Decrypts data encrypted by our pure Python stream cipher."""
    nonce = ciphertext_bytes[:8]
    actual_ciphertext = ciphertext_bytes[8:]
    plaintext = bytearray()
    counter = 0
    
    for i in range(0, len(actual_ciphertext), 32):
        block_data = nonce + counter.to_bytes(8, 'big') + key_bytes
        keystream = hashlib.sha256(block_data).digest()
        chunk = actual_ciphertext[i:i+32]
        for j in range(len(chunk)):
            plaintext.append(chunk[j] ^ keystream[j])
        counter += 1
        
    return plaintext.decode('utf-8')

def pgp_encrypt(message, sender_private_key, receiver_public_key, verbose=False):
    print("\n--- PGP ENCRYPTION PHASE ---")
    
    # 1. Digital Signature: Hash message, encrypt hash with Sender's Private Key
    print("1. Hashing message and signing with Sender's Private Key...")
    msg_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
    signature = myRSA.encryptText(msg_hash, sender_private_key)
    if verbose:
        print(f"   Message hash: {msg_hash}")
        print(f"   Signature preview: {preview_text(signature)}")
    
    # 2. Package Message and Signature
    payload = json.dumps({"message": message, "signature": signature})
    
    # 3. Generate symmetric session key
    print("2. Generating symmetric session key...")
    session_key = generate_symmetric_key()
    if verbose:
        print(f"   Session key (hex): {session_key.hex()}")
    
    # 4. Encrypt payload symmetrically
    print("3. Encrypting payload with symmetric session key...")
    encrypted_payload = symmetric_encrypt(payload, session_key)
    if verbose:
        print(f"   Payload preview: {preview_text(payload)}")
        print(f"   Encrypted payload preview (hex): {preview_bytes(encrypted_payload)}")
    
    # 5. Encrypt symmetric key with Receiver's Public Key
    print("4. Encrypting session key with Receiver's Public Key...")
    session_key_hex = session_key.hex()
    encrypted_session_key = myRSA.encryptText(session_key_hex, receiver_public_key)
    if verbose:
        print(f"   Encrypted session key preview: {preview_text(encrypted_session_key)}")
    
    return encrypted_session_key, encrypted_payload

def pgp_decrypt(encrypted_session_key, encrypted_payload, receiver_private_key, sender_public_key, verbose=False):
    print("\n--- PGP DECRYPTION PHASE ---")
    
    # 1. Decrypt session key with Receiver's Private Key
    print("1. Decrypting session key with Receiver's Private Key...")
    session_key_hex = myRSA.descryptText(encrypted_session_key, receiver_private_key)
    session_key = bytes.fromhex(session_key_hex)
    if verbose:
        print(f"   Recovered session key (hex): {session_key_hex}")
    
    # 2. Decrypt payload using symmetric key
    print("2. Decrypting payload with symmetric session key...")
    payload_json = symmetric_decrypt(encrypted_payload, session_key)
    payload = json.loads(payload_json)
    message = payload["message"]
    signature = payload["signature"]
    if verbose:
        print(f"   Decrypted payload preview: {preview_text(payload_json)}")
        print(f"   Recovered signature preview: {preview_text(signature)}")
    
    # 3. Verify Signature: Decrypt signature using Sender's Public Key
    print("3. Verifying signature with Sender's Public Key...")
    decrypted_hash = myRSA.descryptText(signature, sender_public_key)
    if verbose:
        print(f"   Decrypted signature hash: {decrypted_hash}")
    
    # 4. Hash the extracted message and compare to ensure authenticity
    expected_hash = hashlib.sha256(message.encode('utf-8')).hexdigest()
    is_authentic = (expected_hash == decrypted_hash)
    print("   -> Signature Match Valid:", is_authentic)
    
    return message, is_authentic

def load_key(filepath):
    """Reads a public or private key from a text file."""
    with open(filepath, 'r') as f:
        e = int(f.readline().strip())
        n = int(f.readline().strip())
    return (e, n)

def save_pgp_packet(filepath, enc_session_key, enc_payload):
    """Saves the encrypted session key and symmetric payload to a file."""
    with open(filepath, 'wb') as f:
        session_key_bytes = enc_session_key.encode('utf-8')
        f.write(len(session_key_bytes).to_bytes(4, 'big'))
        f.write(session_key_bytes)
        f.write(enc_payload)

def load_pgp_packet(filepath):
    """Loads the encrypted session key and symmetric payload from a file."""
    with open(filepath, 'rb') as f:
        key_len = int.from_bytes(f.read(4), 'big')
        enc_session_key = f.read(key_len).decode('utf-8')
        enc_payload = f.read()
    return enc_session_key, enc_payload

if __name__ == "__main__":
    print("=== PGP SYSTEM ===")
    print("1. Send a message to User B (User A -> User B)")
    print("2. Receive a message from User B (User A <- User B)")
    choice = input("Select an option (1/2): ").strip()
    verbose = input("Enable verbose demo output? (y/n): ").strip().lower() == 'y'
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    if choice == '1':
        try:
            pr_a = load_key(os.path.join(script_dir, "PR_A.txt"))
            pu_b = load_key(os.path.join(script_dir, "../PKI/PU_B.txt"))
            msg = input("\nEnter the secret message to send to B: ")
            enc_session_key, enc_payload = pgp_encrypt(msg, pr_a, pu_b, verbose=verbose)
            save_pgp_packet(os.path.join(script_dir, "../UserB/message.pgp"), enc_session_key, enc_payload)
            print("\n[SUCCESS] Message encrypted and saved to ../UserB/message.pgp")
        except FileNotFoundError as e:
            print(f"\n[ERROR] Missing key file: {e.filename}")
            print("Ensure you have generated keys for User A and User B using rsa-keygen.py!")
            
    elif choice == '2':
        try:
            pr_a = load_key(os.path.join(script_dir, "PR_A.txt"))
            pu_b = load_key(os.path.join(script_dir, "../PKI/PU_B.txt"))
            enc_session_key, enc_payload = load_pgp_packet(os.path.join(script_dir, "message.pgp"))
            msg, is_auth = pgp_decrypt(enc_session_key, enc_payload, pr_a, pu_b, verbose=verbose)
            print(f"\n[SUCCESS] Decrypted Message: '{msg}'")
        except FileNotFoundError as e:
            print(f"\n[ERROR] File not found: {e.filename}")
