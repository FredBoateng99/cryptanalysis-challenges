# test/test.py
# Purpose: verify that AES-GCM output from fixed_email_aesgcm.bin
# contains no repeated 16-byte ciphertext blocks (unlike ECB mode).

from collections import defaultdict
from pathlib import Path

BLOCK = 16
PATH = Path("fixed/fixed_email_aesgcm.bin")  # correct path from project root
data = open(PATH, "rb").read()

# Skip salt|nonce|tag (16 + 12 + 16 = 44 bytes) — per fixed.py format
payload = data[16 + 12 + 16:]

def split_blocks(b):
    return [b[i:i+BLOCK] for i in range(0, len(b), BLOCK)]

blocks = split_blocks(payload)
counts = defaultdict(int)
idx_by_hex = defaultdict(list)

for i, blk in enumerate(blocks):
    if len(blk) < BLOCK:
        # possible short last block; still include for completeness
        continue
    h = blk.hex()
    counts[h] += 1
    idx_by_hex[h].append(i)

repeated = {h: idx_by_hex[h] for h, c in counts.items() if c > 1}

print("=== AES-GCM ciphertext block analysis ===")
if not repeated:
    print(" No repeated 16-byte ciphertext blocks detected — secure.")
else:
    print(" Repeated ciphertext blocks found (hex -> indices):")
    for h, idxs in repeated.items():
        print(f"{h} {idxs}")
    print("Check that a unique nonce is used per encryption.")
