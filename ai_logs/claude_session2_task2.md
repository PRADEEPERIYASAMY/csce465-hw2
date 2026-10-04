# Claude Session 2 — Task 2: Authenticated ffdhe3072 Handshake
## CSCE 465/765 HW2 — Oct 2–3, 2026

> **Note:** Prompts are verbatim.  Claude responses are summarized.
> Personal account details removed.

---

### Exchange 1

**My prompt:**
> For Task 2 I need to implement a 3-message authenticated Diffie-Hellman
> handshake using the RFC 7919 ffdhe3072 group and RSA-PSS signatures.
>
> The message flow is:
>   HS1: gateway -> node: ID_G, gY_G, nonce_G
>   HS2: node -> gateway: ID_N, gY_N, nonce_N, Sig_N("node" || TH)
>   HS3: gateway -> node: Sig_G("gateway" || TH)
>
> where TH = SHA-256 of the transcript.  My question: why order the transcript
> as (protocol_label, group, ID_G, ID_N, gY_G, gY_N, nonce_G, nonce_N) by
> *role* rather than by message arrival order?

**Claude's response (summary):**
Claude explained that both sides must derive a byte-identical transcript hash
to verify each other's signatures.  If the transcript were ordered by arrival
order, the node (who receives HS1 first) and the gateway (who sends HS1 first)
would assemble fields in different orders, producing different hashes.  By
fixing the order to "gateway fields first, node fields second" both parties
build the same byte sequence regardless of who is computing it.

---

### Exchange 2

**My prompt:**
> OK.  What does a reflection attack look like on this protocol if the gateway
> doesn't check that the nonce in HS2 is different from the nonce it sent in HS1?

**Claude's response (summary):**
Claude described the classic reflection scenario: an active attacker intercepts
HS1, crafts HS2 by echoing the gateway's own nonce and DH value back, and
replays the gateway's signature as the "node" signature.  Without checking
`peer_nonce != my_nonce`, the gateway would derive the same shared secret as
the attacker and believe it had authenticated the node.  The check
`peer_pub == self._my_pub or peer_nonce == self._my_nonce` blocks this.

---

### Exchange 3

**My prompt:**
> Generate a Gateway and Node class skeleton (both subclassing a _Party base)
> with methods: Gateway.start(), Gateway.finish(msg2), Node.respond(msg1),
> Node.finish(msg3).  Also a derive_keys function using this KDF:
>   k_master = SHA-256(b"CSCE465-KDF-v1" || z || TH)
>   g2n_enc = HMAC-SHA-256(k_master, b"gateway-to-node encryption" || TH)
>   ... (same pattern for g2n_mac, n2g_enc, n2g_mac, session_id[:8])
>
> Use the cryptography library only.  RSA-PSS with SHA-256, salt length =
> digest length.  Encode all fields as length-prefixed (4-byte big-endian
> length || bytes).

**Claude's response (summary):**
Claude produced a full draft including:
- `encode_fields` / `decode_fields` for the TLV framing
- `_Party._check_peer()` calling `sign()` / `verify()` as methods of `_Party`
- `derive_keys()` using HKDF from the cryptography library (not the
  assignment's HMAC chain)
- No bounds check on the DH public value

---

### Exchange 4

**My prompt:**
> Two issues with the draft:
> 1. derive_keys uses HKDF but the assignment specifies a simpler HMAC chain.
>    Please rewrite it to match the spec I quoted above.
> 2. The sign/verify methods are inside _Party.  I want them as module-level
>    functions so I can test them independently without constructing a party.

**Claude's response (summary):**
Claude rewrote `derive_keys` to use `hashlib.sha256` for `k_master` and
`hmac.HMAC` from the cryptography library for each traffic key, matching the
assignment KDF exactly.  It also extracted `sign(key, role, th)` and
`verify(pub, sig, role, th)` to module level.

---

### Exchange 5

**My prompt:**
> What is the correct way to validate the DH public value for the ffdhe3072
> safe-prime group to reject small-subgroup elements?

**Claude's response (summary):**
Claude explained that for a safe prime `p = 2q + 1`, the only small subgroup
has order 2 (elements 1 and `p-1`), so rejecting values outside `[2, p-2]`
removes all dangerous inputs.  It also noted that 0 and `p` would fail modular
arithmetic and should be rejected.  The resulting check is
`if not 2 <= y <= pn.p - 2`.

---

### Exchange 6

**My prompt:**
> I noticed your decode_fields doesn't raise an error if there are trailing
> bytes after parsing all the expected fields.  Is that a problem?

**Claude's response (summary):**
Claude confirmed this is a real issue: an attacker who can append bytes to a
message can craft subtly different byte strings that parse identically, which
could be exploited in certain contexts (length-extension-style confusion).  It
provided the fix: after the parsing loop, if `i != len(data)` raise
`MalformedMessage("trailing bytes")`.  I added this and a corresponding
test `test_trailing_bytes`.

---

### Changes I made independently

- Added `FFDHE3072_P_SHA256` constant (suggested by Claude as a safeguard
  against swapped group files; I computed the hex value myself with Python).
- Added `_forget_ephemeral()` to zero out `_dh_priv` and `_z` after key
  derivation — Claude's draft kept these as live attributes.
- Wrote `make_pair()` and `run_handshake()` convenience functions for tests;
  Claude had not included them.

### What was rejected

- Claude's initial `_check_peer` compared identities with `==`.  I changed this
  to `hmac.compare_digest` to make the comparison constant-time (avoids timing
  side-channel on identity comparison).
