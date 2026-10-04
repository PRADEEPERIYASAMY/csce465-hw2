#!/usr/bin/env python3
"""Task 3 - Encrypt-then-MAC record layer.

Run:  python secure_record.py

Wire format (all integers big-endian):

  header     = version(1) || direction(1) || sequence(8) || message_type(1) || ct_len(4)
  iv         = session_id(8) || sequence(8)
  ciphertext = AES-256-CTR(K_enc, iv, plaintext)
  tag        = HMAC-SHA-256(K_mac, header || iv || ciphertext)
  record     = header || ciphertext || tag

The IV is not sent: both sides rebuild it from session_id and the sequence
number, so it is still covered by the MAC.

Receive order: framing -> version -> direction -> expected sequence ->
HMAC (constant-time, library) -> decrypt -> advance sequence.
No plaintext is returned unless every check passed.
"""
from __future__ import annotations

import struct

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VERSION = 1
DIR_G2N = 0x01   # gateway -> node
DIR_N2G = 0x02   # node -> gateway
HEADER_FMT = ">BBQBI"
HEADER_LEN = struct.calcsize(HEADER_FMT)   # 15
TAG_LEN = 32
MAX_SEQ = 2**64 - 1
MAX_PLAINTEXT = 2**24                      # 16 MiB sanity cap

MSG_DATA = 0x17
MSG_TOOL_CALL = 0x20
MSG_TOOL_RESULT = 0x21


# ------------------------------------------------------------------- errors
class RecordError(Exception):
    """Base class. Caller gets no plaintext."""


class MalformedRecord(RecordError):
    """Too short, wrong length field, or unsupported version."""


class WrongDirection(RecordError):
    """Header direction is not the one this receiver accepts."""


class ReplayOrReorder(RecordError):
    """Sequence number is not exactly the next expected one."""


class BadMAC(RecordError):
    """HMAC verification failed (tampered header, IV, or ciphertext)."""


class SequenceExhausted(RecordError):
    """Sender would have to reuse an IV; session must be re-keyed."""


class ChannelClosed(RecordError):
    """Channel failed earlier and is permanently closed."""


# ------------------------------------------------------------------ states
class _DirState:
    def __init__(self, enc_key: bytes, mac_key: bytes, session_id: bytes, direction: int):
        if len(enc_key) != 32 or len(mac_key) != 32:
            raise ValueError("keys must be 32 bytes")
        if len(session_id) != 8:
            raise ValueError("session_id must be 8 bytes")
        if direction not in (DIR_G2N, DIR_N2G):
            raise ValueError("bad direction")
        if enc_key == mac_key:
            raise ValueError("encryption and MAC keys must be independent")
        self.enc_key, self.mac_key = enc_key, mac_key
        self.session_id, self.direction = session_id, direction
        self.seq = 0          # starts at zero in each direction
        self.closed = False


class SendState(_DirState):
    pass


class RecvState(_DirState):
    pass


def channel_states(keys, role: str) -> tuple[SendState, RecvState]:
    """Build (send, recv) states from handshake.SessionKeys for 'gateway'/'node'."""
    g2n = (keys.g2n_enc, keys.g2n_mac, keys.session_id, DIR_G2N)
    n2g = (keys.n2g_enc, keys.n2g_mac, keys.session_id, DIR_N2G)
    if role == "gateway":
        return SendState(*g2n), RecvState(*n2g)
    if role == "node":
        return SendState(*n2g), RecvState(*g2n)
    raise ValueError("role must be 'gateway' or 'node'")


# ------------------------------------------------------------------ helpers
def _iv(session_id: bytes, seq: int) -> bytes:
    return session_id + struct.pack(">Q", seq)


def _ctr(key: bytes, iv: bytes, data: bytes) -> bytes:
    c = Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()
    return c.update(data) + c.finalize()


def _mac(key: bytes, header: bytes, iv: bytes, ct: bytes) -> hmac.HMAC:
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(header + iv + ct)
    return h


# ---------------------------------------------------------------------- API
def seal(state: SendState, message_type: int, plaintext: bytes) -> bytes:
    if not isinstance(state, SendState):
        raise TypeError("seal() needs a SendState")
    if state.closed:
        raise ChannelClosed("send channel closed")
    if not 0 <= message_type <= 0xFF:
        raise ValueError("message_type must fit in one byte")
    if len(plaintext) > MAX_PLAINTEXT:
        raise ValueError("plaintext too large")
    if state.seq > MAX_SEQ:   # all 2^64 IVs used -> never wrap around
        state.closed = True
        raise SequenceExhausted("sequence space exhausted; re-key")

    seq = state.seq
    header = struct.pack(HEADER_FMT, VERSION, state.direction, seq,
                         message_type, len(plaintext))
    iv = _iv(state.session_id, seq)
    ct = _ctr(state.enc_key, iv, plaintext)
    tag = _mac(state.mac_key, header, iv, ct).finalize()
    state.seq += 1            # commit only after the record is built
    return header + ct + tag


def open_record(state: RecvState, record: bytes) -> tuple[int, bytes]:
    """Return (message_type, plaintext) or raise a RecordError subclass."""
    if not isinstance(state, RecvState):
        raise TypeError("open_record() needs a RecvState")
    if state.closed:
        raise ChannelClosed("receive channel closed")

    if len(record) < HEADER_LEN + TAG_LEN:
        raise MalformedRecord("record too short")
    header = record[:HEADER_LEN]
    version, direction, seq, mtype, ct_len = struct.unpack(HEADER_FMT, header)
    if len(record) != HEADER_LEN + ct_len + TAG_LEN:
        raise MalformedRecord("ciphertext_length does not match record size")
    if version != VERSION:
        raise MalformedRecord(f"unsupported version {version}")
    if direction != state.direction:
        raise WrongDirection(f"got direction {direction}, expected {state.direction}")
    if seq != state.seq:
        raise ReplayOrReorder(f"got sequence {seq}, expected {state.seq}")

    ct = record[HEADER_LEN:HEADER_LEN + ct_len]
    tag = record[HEADER_LEN + ct_len:]
    iv = _iv(state.session_id, seq)
    try:
        _mac(state.mac_key, header, iv, ct).verify(tag)   # constant-time
    except InvalidSignature:
        raise BadMAC("record authentication failed") from None

    plaintext = _ctr(state.enc_key, iv, ct)   # only reached after MAC passes
    state.seq += 1
    return mtype, plaintext


def main() -> None:
    from handshake import make_pair, run_handshake

    print("=== Task 3: encrypt-then-MAC record layer ===")
    gw, nd = make_pair()
    kg, kn = run_handshake(gw, nd)
    g_send, g_recv = channel_states(kg, "gateway")
    n_send, n_recv = channel_states(kn, "node")

    r0 = seal(g_send, MSG_TOOL_CALL, b'{"action":"READ","path":"notes.txt"}')
    print(f"G->N record #0: {len(r0)} bytes, header={r0[:HEADER_LEN].hex()}")
    print(f"  node opened : {open_record(n_recv, r0)}")
    r1 = seal(n_send, MSG_TOOL_RESULT, b'{"ok":true,"data":"hello"}')
    print(f"N->G record #0: {len(r1)} bytes, header={r1[:HEADER_LEN].hex()}")
    print(f"  gateway opened: {open_record(g_recv, r1)}")

    for name, fn in [
        ("replay G->N #0", lambda: open_record(n_recv, r0)),
        ("reflect N->G record back to node", lambda: open_record(n_recv, r1)),
    ]:
        try:
            fn()
            print(f"  {name}: ACCEPTED (bug!)")
        except RecordError as e:
            print(f"  {name}: rejected -> {type(e).__name__}: {e}")

    r2 = bytearray(seal(g_send, MSG_TOOL_CALL, b'{"action":"READ","path":"notes.txt"}'))
    r2[HEADER_LEN + 11] ^= ord("R") ^ ord("W")   # CTR bit-flip from Task 1
    try:
        open_record(n_recv, bytes(r2))
    except RecordError as e:
        print(f"  Task-1 bit-flip on protected record: rejected -> {type(e).__name__}")


if __name__ == "__main__":
    main()
