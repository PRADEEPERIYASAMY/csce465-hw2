#!/usr/bin/env python3
"""Task 2 - Authenticated finite-field Diffie-Hellman handshake (in-process).

Run:  python handshake.py

Message flow (gateway = initiator, node = responder):

  1. G -> N : TLV("HS1", ID_G, gY_G, nonce_G)
  2. N -> G : TLV("HS2", ID_N, gY_N, nonce_N, Sig_N("node"    || TH))
  3. G -> N : TLV("HS3",                     Sig_G("gateway" || TH))

  transcript = LP(label) || LP(group) || LP(ID_G) || LP(ID_N)
               || LP(gY_G) || LP(gY_N) || LP(nonce_G) || LP(nonce_N)
  LP(x)      = len(x) as 4-byte big-endian || x
  TH         = SHA-256(transcript)

The transcript is ordered by *role* (gateway fields first), not by who sent
what, so both sides build byte-identical transcripts.

Every cryptographic primitive (RSA-PSS, SHA-256, HMAC, DH) comes from the
`cryptography` library. Nothing is implemented by hand.
"""
from __future__ import annotations

import hashlib
import hmac as std_hmac
import os
import struct
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives import hmac as c_hmac
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa

# ------------------------------------------------------------------ constants
PROTOCOL_LABEL = b"CSCE465-HS-v2"
GROUP_ID = b"ffdhe3072"
KDF_LABEL = b"CSCE465-KDF-v1"
DH_BYTES = 384          # 3072-bit modulus
NONCE_BYTES = 16
RSA_BITS = 3072
ROLE_GATEWAY = b"gateway"
ROLE_NODE = b"node"
MSG1, MSG2, MSG3 = b"HS1", b"HS2", b"HS3"
TRANSCRIPT_FIELDS = 8

DEFAULT_GROUP_FILE = Path(__file__).with_name("ffdhe3072.pem")
# SHA-256 of the RFC 7919 ffdhe3072 prime (384-byte big-endian). Guards against
# someone swapping in a weak or attacker-chosen group file.
FFDHE3072_P_SHA256 = "0eaf67db3a839156d5013494a5318a772b5697d270d721f37f092efc69ea5a17"

PSS_PADDING = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                          salt_length=padding.PSS.DIGEST_LENGTH)


# ------------------------------------------------------------------- errors
class HandshakeError(Exception):
    """Base class. Any of these means: do NOT accept the session."""


class MalformedMessage(HandshakeError):
    """Bad TLV framing, wrong field count/size, or wrong message type."""


class InvalidPublicValue(HandshakeError):
    """DH public value outside [2, p-2]."""


class UnexpectedIdentity(HandshakeError):
    """Peer claimed an identity other than the one we expect."""


class ReflectionDetected(HandshakeError):
    """Peer echoed our own nonce / DH value back to us."""


class BadSignature(HandshakeError):
    """RSA-PSS signature over role || TH did not verify."""


class ProtocolStateError(HandshakeError):
    """Message received in the wrong state."""


# --------------------------------------------------------- TLV / transcript
def encode_fields(fields: list[bytes]) -> bytes:
    """Length-prefixed encoding: each field = 4-byte big-endian length || bytes."""
    out = bytearray()
    for f in fields:
        if not isinstance(f, (bytes, bytearray)):
            raise TypeError("fields must be bytes")
        out += struct.pack(">I", len(f)) + f
    return bytes(out)


def decode_fields(data: bytes, expected_count: int) -> list[bytes]:
    """Strict inverse of encode_fields.

    Rejects: truncated length prefix, declared length running past the end,
    trailing bytes, or the wrong number of fields.
    """
    fields, i, n = [], 0, len(data)
    while i < n:
        if n - i < 4:
            raise MalformedMessage("truncated length prefix")
        (ln,) = struct.unpack(">I", data[i:i + 4])
        i += 4
        if ln > n - i:
            raise MalformedMessage("declared field length exceeds remaining data")
        fields.append(bytes(data[i:i + ln]))
        i += ln
    if len(fields) != expected_count:
        raise MalformedMessage(f"expected {expected_count} fields, got {len(fields)}")
    return fields


def build_transcript(gateway_id: bytes, node_id: bytes,
                     gateway_pub: bytes, node_pub: bytes,
                     gateway_nonce: bytes, node_nonce: bytes) -> bytes:
    return encode_fields([PROTOCOL_LABEL, GROUP_ID, gateway_id, node_id,
                          gateway_pub, node_pub, gateway_nonce, node_nonce])


def transcript_hash(transcript: bytes) -> bytes:
    """Parse and validate the transcript, *then* hash it.

    A transcript with a wrongly declared length (or wrong label/group/sizes)
    is rejected before SHA-256 is ever computed.
    """
    f = decode_fields(transcript, TRANSCRIPT_FIELDS)
    if f[0] != PROTOCOL_LABEL:
        raise MalformedMessage("wrong protocol label")
    if f[1] != GROUP_ID:
        raise MalformedMessage("wrong group identifier")
    if not f[2] or not f[3]:
        raise MalformedMessage("empty identity")
    if len(f[4]) != DH_BYTES or len(f[5]) != DH_BYTES:
        raise MalformedMessage("DH public value must be 384 bytes")
    if len(f[6]) != NONCE_BYTES or len(f[7]) != NONCE_BYTES:
        raise MalformedMessage("nonce must be 16 bytes")
    h = hashes.Hash(hashes.SHA256())
    h.update(transcript)
    return h.finalize()


# ------------------------------------------------------------------ DH group
def load_group(path: Path | str = DEFAULT_GROUP_FILE) -> dh.DHParameters:
    params = serialization.load_pem_parameters(Path(path).read_bytes())
    pn = params.parameter_numbers()
    if pn.g != 2 or pn.p.bit_length() != 3072:
        raise ValueError("group file is not ffdhe3072")
    if hashlib.sha256(pn.p.to_bytes(DH_BYTES, "big")).hexdigest() != FFDHE3072_P_SHA256:
        raise ValueError("prime does not match RFC 7919 ffdhe3072")
    return params


def int_to_fixed(x: int) -> bytes:
    """384-byte big-endian, zero-padded on the left."""
    return x.to_bytes(DH_BYTES, "big")


def parse_public(params: dh.DHParameters, raw: bytes) -> dh.DHPublicKey:
    if len(raw) != DH_BYTES:
        raise MalformedMessage("DH public value must be 384 bytes")
    pn = params.parameter_numbers()
    y = int.from_bytes(raw, "big")
    # ffdhe3072 is a safe-prime group: rejecting 0, 1, p-1 and >= p removes the
    # only small-subgroup elements.
    if not 2 <= y <= pn.p - 2:
        raise InvalidPublicValue("DH public value out of range")
    return dh.DHPublicNumbers(y, pn).public_key()


# ----------------------------------------------------------------- RSA-PSS
def generate_identity_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def sign(key: rsa.RSAPrivateKey, role: bytes, th: bytes) -> bytes:
    return key.sign(role + th, PSS_PADDING, hashes.SHA256())


def verify(pub: rsa.RSAPublicKey, sig: bytes, role: bytes, th: bytes) -> None:
    try:
        pub.verify(sig, role + th, PSS_PADDING, hashes.SHA256())
    except InvalidSignature as e:
        raise BadSignature(f"peer signature over {role.decode()}||TH invalid") from e


# --------------------------------------------------------------------- KDF
def _hmac(key: bytes, data: bytes) -> bytes:
    h = c_hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


@dataclass(frozen=True)
class SessionKeys:
    g2n_enc: bytes
    g2n_mac: bytes
    n2g_enc: bytes
    n2g_mac: bytes
    session_id: bytes
    th: bytes = field(repr=False)

    def __eq__(self, other):  # constant-time compare (only used in tests/demo)
        return isinstance(other, SessionKeys) and all(
            std_hmac.compare_digest(getattr(self, n), getattr(other, n))
            for n in ("g2n_enc", "g2n_mac", "n2g_enc", "n2g_mac", "session_id", "th"))

    __hash__ = None


def derive_keys(z: bytes, th: bytes) -> SessionKeys:
    """Assignment-specified derivation (do not change)."""
    if len(z) != DH_BYTES or len(th) != 32:
        raise ValueError("bad KDF input sizes")
    h = hashes.Hash(hashes.SHA256())
    h.update(KDF_LABEL + z + th)
    k_master = h.finalize()
    return SessionKeys(
        g2n_enc=_hmac(k_master, b"gateway-to-node encryption" + th),
        g2n_mac=_hmac(k_master, b"gateway-to-node MAC" + th),
        n2g_enc=_hmac(k_master, b"node-to-gateway encryption" + th),
        n2g_mac=_hmac(k_master, b"node-to-gateway MAC" + th),
        session_id=_hmac(k_master, b"session identifier" + th)[:8],
        th=th,
    )


# ------------------------------------------------------------------- party
class _Party:
    role: bytes

    def __init__(self, identity: bytes, signing_key: rsa.RSAPrivateKey,
                 peer_identity: bytes, peer_public_key: rsa.RSAPublicKey,
                 params: dh.DHParameters | None = None):
        self.identity = identity
        self.signing_key = signing_key
        self.peer_identity = peer_identity
        self.peer_public_key = peer_public_key
        self.params = params or load_group()
        self.keys: SessionKeys | None = None
        self._reset()

    def _reset(self):
        # Fresh per session -> forward secrecy once these are discarded.
        self._dh_priv = None
        self._my_pub = self._my_nonce = None
        self._th = None
        self._z = None
        self.state = "idle"

    def _new_ephemeral(self):
        self._dh_priv = self.params.generate_private_key()
        self._my_pub = int_to_fixed(self._dh_priv.public_key().public_numbers().y)
        self._my_nonce = os.urandom(NONCE_BYTES)

    def _shared_secret(self, peer_pub: dh.DHPublicKey) -> bytes:
        raw = self._dh_priv.exchange(peer_pub)
        return int_to_fixed(int.from_bytes(raw, "big"))  # force 384-byte left pad

    def _check_peer(self, peer_id: bytes, peer_pub: bytes, peer_nonce: bytes):
        if not std_hmac.compare_digest(peer_id, self.peer_identity):
            raise UnexpectedIdentity(f"expected {self.peer_identity!r}, got {peer_id!r}")
        if peer_pub == self._my_pub or peer_nonce == self._my_nonce:
            raise ReflectionDetected("peer echoed our own DH value or nonce")
        if len(peer_nonce) != NONCE_BYTES:
            raise MalformedMessage("nonce must be 16 bytes")

    def _fail(self):
        self._reset()
        self.state = "failed"

    def _forget_ephemeral(self):
        self._dh_priv = None
        self._z = None


class Gateway(_Party):
    role = ROLE_GATEWAY

    def start(self) -> bytes:
        self._reset()
        self._new_ephemeral()
        self.state = "sent_hs1"
        return encode_fields([MSG1, self.identity, self._my_pub, self._my_nonce])

    def finish(self, msg2: bytes) -> bytes:
        if self.state != "sent_hs1":
            raise ProtocolStateError("not expecting HS2")
        try:
            mtype, node_id, node_pub_raw, node_nonce, sig = decode_fields(msg2, 5)
            if mtype != MSG2:
                raise MalformedMessage(f"expected HS2, got {mtype!r}")
            self._check_peer(node_id, node_pub_raw, node_nonce)
            node_pub = parse_public(self.params, node_pub_raw)
            transcript = build_transcript(self.identity, node_id, self._my_pub,
                                          node_pub_raw, self._my_nonce, node_nonce)
            th = transcript_hash(transcript)
            verify(self.peer_public_key, sig, ROLE_NODE, th)   # node proved itself
            z = self._shared_secret(node_pub)
            self.keys = derive_keys(z, th)
            my_sig = sign(self.signing_key, ROLE_GATEWAY, th)
        except HandshakeError:
            self._fail()
            raise
        self._forget_ephemeral()
        self.state = "established"
        return encode_fields([MSG3, my_sig])


class Node(_Party):
    role = ROLE_NODE

    def respond(self, msg1: bytes) -> bytes:
        self._reset()
        try:
            mtype, gw_id, gw_pub_raw, gw_nonce = decode_fields(msg1, 4)
            if mtype != MSG1:
                raise MalformedMessage(f"expected HS1, got {mtype!r}")
            self._new_ephemeral()
            self._check_peer(gw_id, gw_pub_raw, gw_nonce)
            gw_pub = parse_public(self.params, gw_pub_raw)
            transcript = build_transcript(gw_id, self.identity, gw_pub_raw,
                                          self._my_pub, gw_nonce, self._my_nonce)
            self._th = transcript_hash(transcript)
            self._z = self._shared_secret(gw_pub)
            sig = sign(self.signing_key, ROLE_NODE, self._th)
        except HandshakeError:
            self._fail()
            raise
        self.state = "sent_hs2"
        return encode_fields([MSG2, self.identity, self._my_pub, self._my_nonce, sig])

    def finish(self, msg3: bytes) -> None:
        if self.state != "sent_hs2":
            raise ProtocolStateError("not expecting HS3")
        try:
            mtype, sig = decode_fields(msg3, 2)
            if mtype != MSG3:
                raise MalformedMessage(f"expected HS3, got {mtype!r}")
            verify(self.peer_public_key, sig, ROLE_GATEWAY, self._th)
            self.keys = derive_keys(self._z, self._th)
        except HandshakeError:
            self._fail()
            raise
        self._forget_ephemeral()
        self.state = "established"


def run_handshake(gateway: Gateway, node: Node, relay=None) -> tuple[SessionKeys, SessionKeys]:
    """Drive the 3 messages in-process. `relay(name, msg) -> msg` may tamper."""
    relay = relay or (lambda name, m: m)
    m1 = relay("HS1", gateway.start())
    m2 = relay("HS2", node.respond(m1))
    m3 = relay("HS3", gateway.finish(m2))
    node.finish(m3)
    return gateway.keys, node.keys


def make_pair(params=None, gw_key=None, node_key=None,
              gw_id=b"gateway-01", node_id=b"node-07"):
    params = params or load_group()
    gw_key = gw_key or generate_identity_key()
    node_key = node_key or generate_identity_key()
    gw = Gateway(gw_id, gw_key, node_id, node_key.public_key(), params)
    nd = Node(node_id, node_key, gw_id, gw_key.public_key(), params)
    return gw, nd


def main() -> None:
    print("=== Task 2: authenticated ffdhe3072 handshake ===")
    params = load_group()
    print(f"group: ffdhe3072, p bits = {params.parameter_numbers().p.bit_length()}, "
          f"g = {params.parameter_numbers().g}")
    gw, nd = make_pair(params)
    log = []
    kg, kn = run_handshake(gw, nd, relay=lambda n, m: (log.append((n, len(m))), m)[1])
    for name, ln in log:
        print(f"  {name}: {ln} bytes on the wire")
    print(f"gateway state={gw.state}, node state={nd.state}")
    print(f"TH         = {kg.th.hex()}")
    print(f"session_id = {kg.session_id.hex()}")
    print(f"both sides derived identical keys: {kg == kn}")
    print(f"4 traffic keys pairwise distinct : "
          f"{len({kg.g2n_enc, kg.g2n_mac, kg.n2g_enc, kg.n2g_mac}) == 4}")

    gw2, nd2 = make_pair(params, gw.signing_key, nd.signing_key)
    kg2, _ = run_handshake(gw2, nd2)
    print(f"second session (same RSA keys) -> new session_id {kg2.session_id.hex()}, "
          f"keys differ: {kg2.g2n_enc != kg.g2n_enc}")


if __name__ == "__main__":
    main()
