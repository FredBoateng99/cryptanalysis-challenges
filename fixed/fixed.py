# fixed.py
# Secure replacement for the AES-ECB educational demo.
# - Uses PBKDF2-HMAC-SHA256 to derive a 256-bit key from a passphrase/PIN + random salt
# - Uses AES-GCM (AEAD) to avoid repeated-block leakage and to make tampering detectable
# - Stores file as: <16 bytes salt><12 bytes nonce><16 bytes tag><ciphertext>
#
#  - Use Argon2 (or another memory-hard KDF) if available.
#  - Use a long passphrase or randomly generated key, not a 4-digit PIN.
#  - Consider hardware-backed key protection and rate-limiting login attempts.

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os

# === Configurable parameters (tune these for your environment) ===
OUTFILE = "fixed_email_aesgcm.bin"
KDF_SALT_BYTES = 16
AES_GCM_NONCE_BYTES = 12    # recommended size for GCM
AES_KEY_BYTES = 32          # AES-256
KDF_ITERATIONS = 500_000    # <-- increase to raise cost per guess (tradeoff: encryption/decryption cost)
KDF_DKLEN = AES_KEY_BYTES
# NOTE: PBKDF2 in pycryptodome uses 'dkLen' as the kwarg name (capital L).
# explicitly request HMAC-SHA256 by passing hmac_hash_module=SHA256.

# NOTE:this demo  allows a short passphrase/PIN to be supplied for compatibility with your lab,
# but the security relies on a strong passphrase or a high-cost KDF. Prefer long passphrases.
DEMO_PASSPHRASE = "0420"    # replace with user-supplied passphrase in real use

# === Plaintext builder (avoid predictable markers that make brute-force trivial) ===
def build_email_like_plaintext():
    """
    Builds an email-like plaintext WITHOUT an easily-recognizable fixed marker.
    We keep the same structure as the original demo but avoid including a simple
    known marker (e.g., 'SECRET:') that would let an attacker trivially detect
    successful decryption.
    """
    header = (
        b"From: alice@example.com\n"
        b"To:   bob@example.com\n"
        b"Subj: Monthly Billing\n\n"
    )
    # 16-byte-ish blocks for readability; repeated content is fine because GCM+nonce prevents
    # deterministic repeated ciphertext blocks.
    block_item = b"ITEM: SUBSCRIBER  "   # 16 bytes
    block_amount = b"AMT:   $0100.00   "  # 16 bytes
    block_note = b"NOTE: PLEASE PAY   "  # 16 bytes
    # Put a secret value at the end but as data (no marker that is constant across encryptions).
    # This secret might be random per run or an application-managed secret.
    secret_data = b"ACCOUNT-REF:" + get_random_bytes(8)  # unpredictable per-file
    # pad/truncate secret_data to 16 bytes block for clean layout (optional)
    secret_block = (secret_data + b" " * 16)[:16]
    body = block_item + block_item + block_item + block_amount + block_note + secret_block
    plaintext = header + body
    return plaintext

# === Key derivation: PBKDF2 ===
def derive_key(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS, dklen: int = KDF_DKLEN) -> bytes:
    """
    Derive a symmetric key from a passphrase and salt using PBKDF2-HMAC-SHA256.
    - Increasing 'iterations' increases cost per guess for attacker and defender.
    - Prefer Argon2 in production if available (not used here for portability).
    """
    # Note: pycryptodome's PBKDF2 expects dkLen (capital L) and supports specifying the hash module
    return PBKDF2(passphrase.encode("utf-8"), salt, dkLen=dklen, count=iterations, hmac_hash_module=SHA256)

# === Encrypt & write file ===
def encrypt_and_write_file(passphrase: str, outpath: str = OUTFILE):
    plaintext = build_email_like_plaintext()
    salt = get_random_bytes(KDF_SALT_BYTES)
    key = derive_key(passphrase, salt)

    nonce = get_random_bytes(AES_GCM_NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)

    # File layout: salt || nonce || tag || ciphertext
    with open(outpath, "wb") as f:
        f.write(salt + nonce + tag + ct)

    print(f"Wrote secure file: {outpath}")
    print(f" - salt ({len(salt)} bytes) and nonce ({len(nonce)} bytes) are stored with the file.")
    print(f" - tag ({len(tag)} bytes) is stored with the file for authenticity verification.")
    print(f" - KDF iterations: {KDF_ITERATIONS} (adjust KDF_ITERATIONS in the script to increase cost).")
    print("Important: without the correct passphrase the file cannot be decrypted (GCM tag will fail).")

# === Decrypt helper ===
def decrypt_file(path: str, passphrase: str) -> bytes:
    """
    Decrypt the file previously produced with encrypt_and_write_file.
    Raises ValueError on authentication failure or format errors.
    """
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < (KDF_SALT_BYTES + AES_GCM_NONCE_BYTES + 16):
        raise ValueError("file too small or corrupted")

    salt = data[:KDF_SALT_BYTES]
    nonce = data[KDF_SALT_BYTES:KDF_SALT_BYTES + AES_GCM_NONCE_BYTES]
    tag = data[KDF_SALT_BYTES + AES_GCM_NONCE_BYTES: KDF_SALT_BYTES + AES_GCM_NONCE_BYTES + 16]
    ct = data[KDF_SALT_BYTES + AES_GCM_NONCE_BYTES + 16:]

    key = derive_key(passphrase, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # decrypt_and_verify will raise ValueError if tag check fails (wrong key/tampered)
    plaintext = cipher.decrypt_and_verify(ct, tag)
    return plaintext

# === Small CLI demo when run directly ===
def main():
    demo_out = OUTFILE
    passphrase = DEMO_PASSPHRASE

    # Create secure file
    encrypt_and_write_file(passphrase, demo_out)

    # Attempt to decrypt (demo)
    try:
        recovered = decrypt_file(demo_out, passphrase)
        print("\nSuccessfully decrypted file with correct passphrase. Plaintext preview:")
        print(recovered.decode("utf-8", errors="replace"))
    except ValueError:
        print("Failed to decrypt/verify file (this should not happen with correct passphrase).")

    # Demonstrate wrong passphrase -> decryption/auth failure
    wrong = passphrase[:-1] + ("9" if passphrase[-1] != "9" else "8")
    try:
        _ = decrypt_file(demo_out, wrong)
        print("Unexpected: wrong passphrase succeeded (this should not happen).")
    except Exception:
        print("As expected, wrong passphrase failed to decrypt/verify (GCM tag mismatch).")

if __name__ == "__main__":
    main()
