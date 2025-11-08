# fixed.py (improved output)
# Secure replacement for the AES-ECB educational demo.
# - Uses PBKDF2-HMAC-SHA256 to derive a 256-bit key from a passphrase/PIN + random salt
# - Uses AES-GCM (AEAD) to avoid repeated-block leakage and to make tampering detectable
# - Stores file as: <16 bytes salt><12 bytes nonce><16 bytes tag><ciphertext>

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import os

OUTFILE = "fixed/fixed_email_aesgcm.bin"
KDF_SALT_BYTES = 16
AES_GCM_NONCE_BYTES = 12
AES_KEY_BYTES = 32
KDF_ITERATIONS = 10000   # keep demo-fast; set to 500_000 for realistic cost
KDF_DKLEN = AES_KEY_BYTES

DEMO_PASSPHRASE = "0420"

def build_email_like_plaintext():
    header = (
        b"From: alice@example.com\n"
        b"To:   bob@example.com\n"
        b"Subj: Monthly Billing\n\n"
    )
    block_item = b"ITEM: SUBSCRIBER  "
    block_amount = b"AMT:   $0100.00   "
    block_note = b"NOTE: PLEASE PAY   "
    secret_data = b"ACCOUNT-REF:" + get_random_bytes(8)
    secret_block = (secret_data + b" " * 16)[:16]
    body = block_item + block_item + block_item + block_amount + block_note + secret_block
    return header + body

def derive_key(passphrase: str, salt: bytes, iterations: int = KDF_ITERATIONS, dklen: int = KDF_DKLEN) -> bytes:
    return PBKDF2(passphrase.encode("utf-8"), salt, dkLen=dklen, count=iterations, hmac_hash_module=SHA256)

def encrypt_and_write_file(passphrase: str, outpath: str = OUTFILE):
    plaintext = build_email_like_plaintext()
    salt = get_random_bytes(KDF_SALT_BYTES)
    key = derive_key(passphrase, salt)
    nonce = get_random_bytes(AES_GCM_NONCE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    with open(outpath, "wb") as f:
        f.write(salt + nonce + tag + ct)
    print(f"Wrote secure file: {outpath}")
    print(f" - salt ({len(salt)} bytes) and nonce ({len(nonce)} bytes) are stored with the file.")
    print(f" - tag ({len(tag)} bytes) is stored with the file for authenticity verification.")
    print(f" - KDF iterations (demo): {KDF_ITERATIONS}")

def decrypt_file(path: str, passphrase: str) -> bytes:
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
    plaintext = cipher.decrypt_and_verify(ct, tag)
    return plaintext

def _print_plaintext_preview(data: bytes, label: str = "Plaintext"):
    print(f"\n=== {label} (len={len(data)} bytes) ===")
    # try to print UTF-8 with replacement
    try:
        text = data.decode("utf-8")
        print(text)
    except Exception:
        # fallback: show repr and hex preview
        print("Non-text bytes or decode error. Showing safe representations:")
        print(repr(data))
    preview_len = min(160, len(data))
    print("\nHex preview (first {} bytes):".format(preview_len))
    print(data[:preview_len].hex())
    print(f"=== end {label} ===\n")

def main():
    demo_out = OUTFILE
    passphrase = DEMO_PASSPHRASE

    # Create secure file
    encrypt_and_write_file(passphrase, demo_out)

    # Attempt to decrypt (demo)
    try:
        recovered = decrypt_file(demo_out, passphrase)
        print("\nSuccessfully decrypted file with correct passphrase.")
        _print_plaintext_preview(recovered, "Recovered plaintext")
    except Exception as e:
        print("Failed to decrypt/verify file with correct passphrase (unexpected):", e)

    # Demonstrate wrong passphrase -> decryption/auth failure
    wrong = passphrase[:-1] + ("9" if passphrase[-1] != "9" else "8")
    try:
        _ = decrypt_file(demo_out, wrong)
        print("Unexpected: wrong passphrase succeeded (this should not happen).")
    except Exception:
        print("As expected, wrong passphrase failed to decrypt/verify (GCM tag mismatch).")

if __name__ == "__main__":
    main()

