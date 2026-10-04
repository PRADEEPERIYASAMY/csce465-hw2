"""Task 4 - adversarial tests for the authenticated DH handshake (Task 2)."""
import hashlib
import hmac

import pytest

import handshake as hs


def fields(msg, n):
    return hs.decode_fields(msg, n)


def assert_not_established(*parties):
    for p in parties:
        assert p.keys is None
        assert p.state != "established"


# ------------------------------------------------------------ happy path
def test_valid_handshake_both_sides_agree(pair):
    gw, nd = pair
    kg, kn = hs.run_handshake(gw, nd)
    assert gw.state == nd.state == "established"
    assert kg == kn
    assert len(kg.session_id) == 8
    assert len({kg.g2n_enc, kg.g2n_mac, kg.n2g_enc, kg.n2g_mac}) == 4  # key separation


def test_every_session_uses_fresh_dh_and_nonces(params, rsa_keys):
    seen = []
    for _ in range(2):
        gw, nd = hs.make_pair(params, rsa_keys["gateway"], rsa_keys["node"])
        m1 = gw.start()
        _, _, pub, nonce = fields(m1, 4)
        seen.append((pub, nonce))
        m2 = nd.respond(m1)
        nd.finish(gw.finish(m2))
        assert gw._dh_priv is None and nd._dh_priv is None   # ephemeral discarded
    assert seen[0][0] != seen[1][0] and seen[0][1] != seen[1][1]


def test_kdf_matches_assignment_spec_independently(pair):
    """Recompute K_master and every derived key with stdlib hashlib/hmac."""
    gw, nd = pair
    m1 = gw.start()
    m2 = nd.respond(m1)
    z = nd._z
    gw.finish(m2)
    th = gw.keys.th
    km = hashlib.sha256(b"CSCE465-KDF-v1" + z + th).digest()
    H = lambda label: hmac.new(km, label + th, hashlib.sha256).digest()  # noqa: E731
    assert len(z) == 384
    assert gw.keys.g2n_enc == H(b"gateway-to-node encryption")
    assert gw.keys.g2n_mac == H(b"gateway-to-node MAC")
    assert gw.keys.n2g_enc == H(b"node-to-gateway encryption")
    assert gw.keys.n2g_mac == H(b"node-to-gateway MAC")
    assert gw.keys.session_id == H(b"session identifier")[:8]


def test_values_are_384_byte_left_padded():
    assert hs.int_to_fixed(5) == b"\x00" * 383 + b"\x05"


def test_transcript_is_length_prefixed_and_unambiguous():
    pub, n = b"\x02" * 384, b"\x03" * 16
    t1 = hs.build_transcript(b"gw", b"node1", pub, pub, n, n)
    t2 = hs.build_transcript(b"gwn", b"ode1", pub, pub, n, n)
    assert b"gw" + b"node1" == b"gwn" + b"ode1"   # plain concat would collide
    assert t1 != t2 and hs.transcript_hash(t1) != hs.transcript_hash(t2)
    assert t1.startswith(b"\x00\x00\x00\x0dCSCE465-HS-v2\x00\x00\x00\x09ffdhe3072")


# ------------------------------------------------- 6. bad keys / signatures
def test_incorrect_rsa_public_key_rejected(params, rsa_keys):
    # Gateway is configured with the WRONG public key for the node.
    gw = hs.Gateway(b"gateway-01", rsa_keys["gateway"], b"node-07",
                    rsa_keys["mallory"].public_key(), params)
    nd = hs.Node(b"node-07", rsa_keys["node"], b"gateway-01",
                 rsa_keys["gateway"].public_key(), params)
    with pytest.raises(hs.BadSignature, match="node"):
        hs.run_handshake(gw, nd)
    assert_not_established(gw, nd)


def test_invalid_pss_signature_rejected(pair):
    gw, nd = pair

    def flip_sig(name, m):
        if name == "HS2":
            f = fields(m, 5)
            f[4] = bytes([f[4][0] ^ 1]) + f[4][1:]
            return hs.encode_fields(f)
        return m

    with pytest.raises(hs.BadSignature):
        hs.run_handshake(gw, nd, relay=flip_sig)
    assert gw.state == "failed" and gw.keys is None


def test_mitm_with_own_rsa_key_rejected(params, rsa_keys, pair):
    """Mallory substitutes her DH value and signs with her own RSA key."""
    gw, nd = pair
    m1 = gw.start()
    mallory = hs.Node(b"node-07", rsa_keys["mallory"], b"gateway-01",
                      rsa_keys["gateway"].public_key(), params)
    forged_m2 = mallory.respond(m1)    # correct format, wrong signer
    with pytest.raises(hs.BadSignature):
        gw.finish(forged_m2)
    assert gw.keys is None


@pytest.mark.parametrize("msg,idx", [("HS1", 3), ("HS2", 3)])
def test_changed_nonce_rejected(pair, msg, idx):
    gw, nd = pair
    n_fields = 4 if msg == "HS1" else 5

    def tamper(name, m):
        if name == msg:
            f = fields(m, n_fields)
            f[idx] = bytes(16)
            return hs.encode_fields(f)
        return m

    with pytest.raises(hs.BadSignature):   # transcripts diverge -> sig fails
        hs.run_handshake(gw, nd, relay=tamper)
    assert gw.keys is None and nd.keys is None


@pytest.mark.parametrize("msg", ["HS1", "HS2"])
def test_changed_dh_public_value_rejected(params, pair, msg):
    gw, nd = pair
    attacker_pub = hs.int_to_fixed(params.generate_private_key()
                                   .public_key().public_numbers().y)
    n_fields = 4 if msg == "HS1" else 5

    def tamper(name, m):
        if name == msg:
            f = fields(m, n_fields)
            f[2] = attacker_pub
            return hs.encode_fields(f)
        return m

    with pytest.raises(hs.BadSignature):
        hs.run_handshake(gw, nd, relay=tamper)
    assert gw.keys is None and nd.keys is None


@pytest.mark.parametrize("y", [0, 1, "p-1", "p"])
def test_degenerate_dh_public_value_rejected(params, pair, y):
    gw, nd = pair
    p = params.parameter_numbers().p
    val = {"p-1": p - 1, "p": p}.get(y, y)
    f = fields(gw.start(), 4)
    f[2] = hs.int_to_fixed(val)
    with pytest.raises(hs.InvalidPublicValue):
        nd.respond(hs.encode_fields(f))
    assert nd.state == "failed"


def test_unexpected_peer_identity_rejected(pair):
    gw, nd = pair

    def rename(name, m):
        if name == "HS2":
            f = fields(m, 5)
            f[1] = b"node-99"
            return hs.encode_fields(f)
        return m

    with pytest.raises(hs.UnexpectedIdentity, match="node-99"):
        hs.run_handshake(gw, nd, relay=rename)
    assert gw.keys is None


# ------------------------------------------------------- reflection
def test_reflected_signature_rejected_by_role_binding(pair):
    """Node's own HS2 signature is reflected back to it as the HS3 signature."""
    gw, nd = pair
    m2 = nd.respond(gw.start())
    node_sig = fields(m2, 5)[4]
    with pytest.raises(hs.BadSignature, match="gateway"):
        nd.finish(hs.encode_fields([hs.MSG3, node_sig]))
    assert nd.keys is None and nd.state == "failed"


def test_reflection_with_shared_identity_key_rejected(params, rsa_keys):
    """Role binding matters when ONE RSA key can act in either role
    (e.g. a host that runs both a gateway and a node under the same identity).
    Then the peer key check alone cannot tell the two signatures apart:
    only the signed role string ("gateway" vs "node") does.
    """
    k = rsa_keys["gateway"]
    gw = hs.Gateway(b"host-A", k, b"host-A", k.public_key(), params)
    nd = hs.Node(b"host-A", k, b"host-A", k.public_key(), params)
    m2 = nd.respond(gw.start())
    node_sig = hs.decode_fields(m2, 5)[4]
    # Attacker reflects the node's own signature back to it as the HS3 signature.
    with pytest.raises(hs.BadSignature, match="gateway"):
        nd.finish(hs.encode_fields([hs.MSG3, node_sig]))
    assert nd.keys is None


def test_reflected_dh_value_and_nonce_rejected(pair):
    """Attacker answers the gateway with the gateway's own DH value and nonce."""
    gw, nd = pair
    _, _, gw_pub, gw_nonce = fields(gw.start(), 4)
    reflected = hs.encode_fields([hs.MSG2, b"node-07", gw_pub, gw_nonce, b"x" * 384])
    with pytest.raises(hs.ReflectionDetected):
        gw.finish(reflected)
    assert gw.keys is None


def test_reflected_hs1_back_to_gateway_rejected(pair):
    gw, nd = pair
    m1 = gw.start()
    with pytest.raises(hs.MalformedMessage):
        gw.finish(m1)                      # wrong field count / message type
    assert gw.keys is None


# ---------------------------------------------------- malformed input
def test_transcript_with_bad_declared_length_rejected_before_hashing(monkeypatch):
    pub, n = b"\x02" * 384, b"\x03" * 16
    t = bytearray(hs.build_transcript(b"gateway-01", b"node-07", pub, pub, n, n))
    t[3] += 1                              # label length 13 -> 14
    calls = []
    real_hash = hs.hashes.Hash
    monkeypatch.setattr(hs.hashes, "Hash", lambda *a, **k: calls.append(1) or real_hash(*a, **k))
    with pytest.raises(hs.MalformedMessage):
        hs.transcript_hash(bytes(t))
    assert calls == [], "SHA-256 must not run on a malformed transcript"


@pytest.mark.parametrize("cut", [1, 3, 50])
def test_truncated_handshake_message_rejected(pair, cut):
    gw, nd = pair
    with pytest.raises(hs.MalformedMessage):
        nd.respond(gw.start()[:-cut])
    assert nd.state == "failed"


def test_trailing_bytes_rejected(pair):
    gw, nd = pair
    with pytest.raises(hs.MalformedMessage):
        nd.respond(gw.start() + b"\x00")


def test_out_of_order_message_rejected(pair):
    gw, nd = pair
    with pytest.raises(hs.ProtocolStateError):
        nd.finish(hs.encode_fields([hs.MSG3, b"sig"]))
