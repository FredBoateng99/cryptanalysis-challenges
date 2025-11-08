# Vulnerable.py
# two-time-pad vulnerable demo (banking-style OTP reuse), wrapped as run_vulnerable()

import secrets
import binascii
from pathlib import Path

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt_reuse_key(plaintexts):
    maxlen = max(len(p) for p in plaintexts)
    key = secrets.token_bytes(maxlen)  # vulnerable if reused
    cts = [xor_bytes(p, key[:len(p)]) for p in plaintexts]
    return cts, key

def save_hex(filename: str, data: bytes):
    Path(filename).write_text(binascii.hexlify(data).decode())

def run_vulnerable():
    # Synthetic, clearly-fake banking messages (padding to equal lengths for demo)
    m1 = (b"TXN:TRANSFER|FROM:FAKE-ACCT-00011122|TO:FAKE-ACCT-88877766|AMT:$5,000.00|DATE:2025-11-01|REF:PayrollNov").ljust(120, b' ')
    m2 = (b"ALERT:LOW_BAL|ACCT:FAKE-ACCT-00011122|BAL:$49.32|DATE:2025-11-02|ACTION:DepositOrFeeMayApply").ljust(120, b' ')
    m3 = (b"TXN:PAYMENT|ACCT:FAKE-ACCT-88877766|TO:MERCHANT-ACME|AMT:$129.95|DATE:2025-11-02|REF:ORDER#A1234").ljust(120, b' ')
    m4 = (b"CONF:WIRE|FROM:FAKE-ACCT-44433322|TO:FAKE-ACCT-00011122|AMT:$12,500.00|DATE:2025-10-30|REF:CapitalMove").ljust(120, b' ')
    plaintexts = [m1, m2, m3, m4]

    cts, key = encrypt_reuse_key(plaintexts)

    # Save ciphertexts and key for the demo exploit (we save key only for 'show full recovery' in class).
    for i, ct in enumerate(cts, start=1):
        save_hex(f"ciphertext{i}.hex", ct)
    save_hex("reused_key.hex", key)  # demo only

    print("vulnerable: Wrote ciphertext1.hex .. ciphertext4.hex and reused_key.hex (for demo only).")
    print("vulnerable: ciphertext lengths:", [len(x) for x in cts])
    # Return lengths so orchestrator can report
    return {"cts_lengths": [len(x) for x in cts]}

if __name__ == "__main__":
    out = run_vulnerable()
    print("run_vulnerable returned:", out)
