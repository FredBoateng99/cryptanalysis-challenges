# vulnerable_ecb_vuln_only.py
# Shows two AES-ECB vulnerabilities together:
# 1) Very small key space (4-digit PIN repeated to 16 bytes)
# 2) ECB mode leakage via repeated 16-byte plaintext blocks


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# === Configuration (change PIN for experiments) ===
PIN = "0420"               # 4-digit PIN (very small keyspace)
MARKER = b"SECRET:"        # known marker to help later brute-force verification
OUTFILE = "vuln_email_ecb.bin"

def make_vulnerable_cipher(pin: str):
    """
    Weak key derivation: repeat a short PIN to form a 16-byte AES key.
    This creates only 10,000 possible keys for 4-digit PINs.
    """
    key = (pin.encode() * 4)[:16]
    cipher = AES.new(key, AES.MODE_ECB)
    return key, cipher

def build_email_like_plaintext():
    """
    Construct an 'email-like' plaintext where several 16-byte blocks are identical
    so that AES-ECB produces identical ciphertext blocks (pattern leakage).
    Each block below is carefully crafted to be exactly 16 bytes.
    """
    header = (
        b"From: alice@example.com\n"
        b"To:   bob@example.com\n"
        b"Subj: Monthly Billing\n\n"
    )

    # Blocks are exactly 16 bytes each.
    # Repeating the SAME block multiple times will produce identical ciphertext blocks under ECB.
    block_item = b"ITEM: SUBSCRIBER"   # 16 bytes
    block_amount = b"AMT:   .00  " # 16 bytes
    # include the marker inside its own block so brute-force detection is simple later
    block_secret = b"SECRET:8675309  "  # 16 bytes (contains MARKER)
    block_note = b"NOTE: PLEASE PAY  "  # 16 bytes

    # Build body with repeated blocks; repeating block_item 3 times shows ECB repetition clearly.
    body = block_item + block_item + block_item + block_amount + block_note + block_secret

    plaintext = header + body
    return plaintext

def main():
    key, cipher = make_vulnerable_cipher(PIN)
    plaintext = build_email_like_plaintext()

    # Pad and encrypt using AES-ECB
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))

    # Save ciphertext for later use (e.g., brute-force or tampering demos)
    with open(OUTFILE, "wb") as f:
        f.write(ciphertext)

    # Output for the lab: show plaintext (for reference) and the ciphertext broken into 16-byte blocks.
    # Observers should notice identical ciphertext hex for the repeated blocks.
    print("=== Vulnerability demo (AES-ECB, weak 4-digit PIN) ===")
    print(f"PIN (lab setting): {PIN}")
    print("\nPlaintext (visible for demo):")
    print(plaintext.decode(errors="replace"))
    print("\nCiphertext blocks (16 bytes each, hex):")
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        print(f"Block {i//16:02d}: {block.hex()}")

    print(f"\nCiphertext written to: {OUTFILE}")
    print("\nObserve: identical hex values for the repeated plaintext blocks (ITEM: SUBSCRIBER).")
    print("This demonstrates ECB leakage; combined with a 4-digit PIN-derived key, this ciphertext is easily attackable.")

if __name__ == "__main__":
    main()
