"""Task 4 - adversarial tests for the encrypt-then-MAC record layer (Task 3)."""
import hashlib
import hmac
import struct

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import handshake as hs
import secure_record as sr

CMD = b'{"action":"READ","path":"notes.txt"}'
H = sr.HEADER_LEN


@pytest.fixture
def chan(pair):
    gw, nd = pair
    kg, kn = hs.run_handshake(gw, nd)
    g_send, g_recv = sr.channel_states(kg, "gateway")
    n_send, n_recv = sr.channel_states(kn, "node")
    return dict(g_send=g_send, g_recv=g_recv, n_send=n_send, n_recv=n_recv, keys=kg)


def flip(record, idx):
    r = bytearray(record)
    r[idx] ^= 0x01
    return bytes(r)


# ---------------------------------------------- 1. valid bidirectional
def test_valid_handshake_and_bidirectional_messages(chan):
    for i in range(3):
        r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD + bytes([i]))
        assert struct.unpack(">Q", r[2:10])[0] == i            # seq starts at 0
        assert sr.open_record(chan["n_recv"], r) == (sr.MSG_TOOL_CALL, CMD + bytes([i]))
        r = sr.seal(chan["n_send"], sr.MSG_TOOL_RESULT, b"ok %d" % i)
        assert struct.unpack(">Q", r[2:10])[0] == i            # independent counter
        assert sr.open_record(chan["g_recv"], r) == (sr.MSG_TOOL_RESULT, b"ok %d" % i)
    assert chan["g_send"].seq == chan["n_recv"].seq == 3


def test_empty_plaintext_roundtrip(chan):
    r = sr.seal(chan["g_send"], sr.MSG_DATA, b"")
    assert sr.open_record(chan["n_recv"], r) == (sr.MSG_DATA, b"")


def test_wire_format_matches_spec(chan):
    """Rebuild IV, ciphertext and tag with independent code."""
    k = chan["keys"]
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    header, ct, tag = r[:H], r[H:-32], r[-32:]
    assert header == struct.pack(">BBQBI", 1, sr.DIR_G2N, 0, sr.MSG_TOOL_CALL, len(CMD))
    iv = k.session_id + (0).to_bytes(8, "big")
    d = Cipher(algorithms.AES(k.g2n_enc), modes.CTR(iv)).decryptor()
    assert d.update(ct) + d.finalize() == CMD
    assert hmac.compare_digest(tag, hmac.new(k.g2n_mac, header + iv + ct, hashlib.sha256).digest())


# ------------------------------------------------- 2. modified ciphertext
def test_modified_ciphertext_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    with pytest.raises(sr.BadMAC):
        sr.open_record(chan["n_recv"], flip(r, H + 11))
    assert chan["n_recv"].seq == 0            # state not advanced
    assert sr.open_record(chan["n_recv"], r)[1] == CMD   # genuine one still ok


def test_task1_bitflip_attack_rejected(chan):
    r = bytearray(sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD))
    for i, d in enumerate(bytes(a ^ b for a, b in zip(b"READ", b"WIPE"))):
        r[H + 11 + i] ^= d
    with pytest.raises(sr.BadMAC):
        sr.open_record(chan["n_recv"], bytes(r))


def test_modified_tag_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    with pytest.raises(sr.BadMAC):
        sr.open_record(chan["n_recv"], flip(r, len(r) - 1))


# --------------------------------------------- 3. modified header
def test_modified_message_type_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_RESULT, CMD)
    r = r[:10] + bytes([sr.MSG_TOOL_CALL]) + r[11:]          # upgrade to tool call
    with pytest.raises(sr.BadMAC):
        sr.open_record(chan["n_recv"], r)


def test_modified_version_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    with pytest.raises(sr.MalformedRecord, match="version"):
        sr.open_record(chan["n_recv"], b"\x02" + r[1:])


def test_modified_length_field_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    with pytest.raises(sr.MalformedRecord, match="length"):
        sr.open_record(chan["n_recv"], flip(r, 14))


def test_modified_sequence_field_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    with pytest.raises(sr.ReplayOrReorder):
        sr.open_record(chan["n_recv"], flip(r, 9))


def test_truncated_record_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    for bad in (r[:10], r[:-1], r + b"\x00"):
        with pytest.raises(sr.MalformedRecord):
            sr.open_record(chan["n_recv"], bad)


# ---------------------------------------------------- 4. replay
def test_replayed_record_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    assert sr.open_record(chan["n_recv"], r)[1] == CMD
    with pytest.raises(sr.ReplayOrReorder, match="expected 1"):
        sr.open_record(chan["n_recv"], r)


def test_reordered_or_dropped_record_rejected(chan):
    sr.seal(chan["g_send"], sr.MSG_DATA, b"first")              # dropped by attacker
    r1 = sr.seal(chan["g_send"], sr.MSG_DATA, b"second")
    with pytest.raises(sr.ReplayOrReorder, match="expected 0"):
        sr.open_record(chan["n_recv"], r1)


def test_record_from_other_session_rejected(chan, params, rsa_keys):
    gw2, nd2 = hs.make_pair(params, rsa_keys["gateway"], rsa_keys["node"])
    kg2, _ = hs.run_handshake(gw2, nd2)
    other_send, _ = sr.channel_states(kg2, "gateway")
    r = sr.seal(other_send, sr.MSG_TOOL_CALL, CMD)              # seq 0, valid elsewhere
    with pytest.raises(sr.BadMAC):
        sr.open_record(chan["n_recv"], r)


# ------------------------------------------------ 5. reflection
def test_reflected_record_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    with pytest.raises(sr.WrongDirection):
        sr.open_record(chan["g_recv"], r)                       # back to gateway


def test_reflected_record_with_rewritten_direction_rejected(chan):
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    r = r[:1] + bytes([sr.DIR_N2G]) + r[2:]
    with pytest.raises(sr.BadMAC):                              # different MAC key
        sr.open_record(chan["g_recv"], r)


# ------------------------------- implementation-property tests
def test_verify_before_decrypt_and_no_plaintext_on_error(chan, monkeypatch):
    calls = []
    real = sr._ctr
    monkeypatch.setattr(sr, "_ctr", lambda *a: calls.append(1) or real(*a))
    r = sr.seal(chan["g_send"], sr.MSG_TOOL_CALL, CMD)
    calls.clear()
    with pytest.raises(sr.BadMAC):
        sr.open_record(chan["n_recv"], flip(r, H))
    assert calls == [], "AES-CTR must not run before the MAC is verified"


def test_ivs_unique_and_sequence_never_wraps(chan):
    s = chan["g_send"]
    seen = set()
    for _ in range(500):
        r = sr.seal(s, sr.MSG_DATA, b"x")
        seen.add(r[2:10])
    assert len(seen) == 500
    s.seq = sr.MAX_SEQ
    sr.seal(s, sr.MSG_DATA, b"last one")                        # seq 2^64-1 ok
    with pytest.raises(sr.SequenceExhausted):
        sr.seal(s, sr.MSG_DATA, b"would reuse IV")
    with pytest.raises(sr.ChannelClosed):
        sr.seal(s, sr.MSG_DATA, b"still closed")


def test_states_cannot_be_swapped(chan):
    with pytest.raises(TypeError):
        sr.seal(chan["n_recv"], sr.MSG_DATA, b"x")
    with pytest.raises(TypeError):
        sr.open_record(chan["g_send"], b"x" * 64)


def test_spec_iv_layout_counter_overlap_is_documented(chan):
    """Known limitation of the *assigned* IV layout (see report, Task 3).

    AES-CTR increments the whole 128-bit counter block, and the sequence
    number sits in the low 64 bits. So block 1 of record n uses the same
    counter block as block 0 of record n+1: keystream overlap for records
    longer than 16 bytes. This test pins the behaviour so it is visible.
    """
    k = chan["keys"]
    ks = lambda seq, n: Cipher(algorithms.AES(k.g2n_enc), modes.CTR(  # noqa: E731
        k.session_id + seq.to_bytes(8, "big"))).encryptor().update(bytes(n))
    assert ks(0, 32)[16:] == ks(1, 16)
