#!/usr/bin/env python3
"""Task 1 - Why encryption alone is insufficient (AES-CTR, no MAC, no sequence numbers).

Run:  python baseline_ctr.py

Shows two attacks by an on-path relay that never learns the key:
  1. Bit-flipping: READ -> WIPE by XOR-ing the ciphertext with (old XOR new).
  2. Replay: the same ciphertext delivered twice is processed twice.
"""
import json
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

COMMAND = b'{"action":"READ","path":"notes.txt"}'
OLD_ACTION = b"READ"
NEW_ACTION = b"WIPE"  # equal length (4 bytes), so the JSON stays well-formed


# ---------------------------------------------------------------- endpoints
class Sender:
    """Holds the secret key. Encrypts with AES-256-CTR only (no integrity)."""

    def __init__(self, key: bytes):
        self.key = key

    def send(self, plaintext: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(16)
        enc = Cipher(algorithms.AES(self.key), modes.CTR(nonce)).encryptor()
        return nonce, enc.update(plaintext) + enc.finalize()


class Receiver:
    """Holds the same key. Decrypts and 'executes' whatever comes out."""

    def __init__(self, key: bytes):
        self.key = key
        self.executed: list[dict] = []

    def receive(self, nonce: bytes, ciphertext: bytes) -> dict:
        dec = Cipher(algorithms.AES(self.key), modes.CTR(nonce)).decryptor()
        plaintext = dec.update(ciphertext) + dec.finalize()
        cmd = json.loads(plaintext)          # no way to tell it was tampered with
        self.executed.append(cmd)            # no way to tell it was seen before
        return cmd


# ---------------------------------------------------------------- attacker
def relay_flip(nonce: bytes, ciphertext: bytes, offset: int,
               old: bytes, new: bytes) -> tuple[bytes, bytes]:
    """On-path relay. Knows (or guesses) the plaintext layout, NOT the key.

    CTR: C = P xor KS  =>  C xor (old xor new) = (P xor old xor new) xor KS
    so the receiver decrypts to P with `old` replaced by `new`.
    """
    assert len(old) == len(new)
    delta = bytes(a ^ b for a, b in zip(old, new))
    c = bytearray(ciphertext)
    for i, d in enumerate(delta):
        c[offset + i] ^= d
    return nonce, bytes(c)


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> None:
    key = os.urandom(32)
    sender, receiver = Sender(key), Receiver(key)

    print("=== Task 1: AES-256-CTR without a MAC ===")
    print(f"plaintext P      : {COMMAND.decode()}")
    nonce, ct = sender.send(COMMAND)
    print(f"nonce            : {nonce.hex()}")
    print(f"ciphertext C     : {ct.hex()}")

    # ---- Attack 1: bit flipping
    off = COMMAND.index(OLD_ACTION)
    _, ct_mod = relay_flip(nonce, ct, off, OLD_ACTION, NEW_ACTION)
    print("\n--- Attack 1: bit flip by relay (key never used) ---")
    print(f"offset of action : {off}")
    print(f"modified C'      : {ct_mod.hex()}")
    cmd = receiver.receive(nonce, ct_mod)
    print(f"receiver got     : {json.dumps(cmd, separators=(',', ':'))}")

    # Show the XOR relation byte by byte for the action field.
    p_mod = json.dumps(cmd, separators=(",", ":")).encode()
    seg = slice(off, off + len(OLD_ACTION))
    print("\nXOR relation on the action bytes (C xor C' == P xor P'):")
    print(f"  C [{off}:{off+4}]   = {ct[seg].hex()}")
    print(f"  C'[{off}:{off+4}]   = {ct_mod[seg].hex()}")
    print(f"  C xor C'        = {xor(ct, ct_mod)[seg].hex()}")
    print(f"  P xor P'        = {xor(COMMAND, p_mod)[seg].hex()}"
          f"   ('READ' xor 'WIPE')")
    assert xor(ct, ct_mod) == xor(COMMAND, p_mod)
    print("  full-length check C xor C' == P xor P' : True")
    print(f"  bytes outside the action unchanged     : "
          f"{all(b == 0 for i, b in enumerate(xor(ct, ct_mod)) if not off <= i < off + 4)}")

    # ---- Attack 2: replay
    print("\n--- Attack 2: replay of the original ciphertext ---")
    receiver.executed.clear()
    receiver.receive(nonce, ct)
    receiver.receive(nonce, ct)   # relay sends the captured bytes again
    for i, c in enumerate(receiver.executed, 1):
        print(f"  processed #{i}: {json.dumps(c, separators=(',', ':'))}")
    print(f"receiver executed the same command {len(receiver.executed)} times")


if __name__ == "__main__":
    main()
