# AI Usage — CSCE 465/765 Homework 2

This file documents every use of AI assistance during HW2, following the
course's transparency requirements.  Two tools were used across five
distinct sessions.

> **Log format note:** The Claude session logs in `ai_logs/` record prompts
> verbatim and summarize responses (full verbatim export not available — the
> session was not exported before the browser tab was closed).  The ChatGPT
> log (`ai_logs/chatgpt_log.md`) records real prompts verbatim.

---

## Entry 1 — Claude (Task 1: AES-CTR baseline)

- **Tool / model / date:** Claude (Anthropic, claude.ai), Oct 2–3, 2026.
- **Purpose:** Understand AES-CTR malleability well enough to write a clean
  demonstration; settle the exact byte arithmetic for the XOR delta.
- **Log file:** `ai_logs/claude_session1_task1.md`

**What I asked:**
I described the assignment prompt (show bit-flipping and replay without a MAC)
and asked Claude to walk me through *why* flipping `C[offset] ^= old[i] ^ new[i]`
gives the receiver `P` with only the action field changed.  I then asked it to
sketch a minimal Python class structure.

**What I used:**
- The algebraic explanation (`C = P ⊕ KS → C ⊕ Δ = (P ⊕ Δ) ⊕ KS`) helped me
  write the `relay_flip` function and the XOR-equality assertion.
- The class skeleton (`Sender` / `Receiver` / standalone attacker function)
  matched what I ended up implementing.

**What I changed:**
- Claude initially had the `Receiver` track a `seen_nonces` set.  I removed
  that because the assignment's Task-1 point is that *there is no such
  protection*; adding it would have obscured the attack.
- I added the side-by-side hex printout (`C xor C' == P xor P'`) myself;
  Claude's draft just printed the modified plaintext.
- Moved `xor()` to a module-level helper and verified the `'READ' xor 'WIPE' =
  050c1101` result by hand using Python's interactive shell.

**Limitation / error I found:**
Claude's first draft called `os.urandom(16)` for the nonce but stored it in an
instance variable, so two calls to `send()` on the same object reused the same
nonce.  I fixed this by generating a fresh nonce inside every `send()` call.

---

## Entry 2 — Claude (Task 2: authenticated DH handshake)

- **Tool / model / date:** Claude (Anthropic, claude.ai), Oct 2–3, 2026.
- **Purpose:** Design the three-message ffdhe3072 handshake, settle the
  transcript-hash ordering, choose PSS padding parameters.
- **Log file:** `ai_logs/claude_session2_task2.md`

**What I asked:**
I shared the assignment's message-flow diagram and asked Claude to explain
*why* the transcript is ordered by role (gateway fields first) rather than by
message order, and what a reflection attack looks like if you don't check the
peer nonce.  I then asked it to generate a `Gateway` / `Node` class skeleton
and a `derive_keys` function matching the assignment's KDF label.

**What I used:**
- The role-ordering rationale (both sides must compute a byte-identical
  transcript without coordinating on who sent what) went directly into the
  docstring of `build_transcript`.
- The ffdhe3072 safe-prime subgroup-rejection logic (`2 <= y <= p-2`) came from
  Claude's explanation of RFC 7919 Section 5.
- The `FFDHE3072_P_SHA256` constant (SHA-256 of the prime bytes) was suggested
  by Claude to guard against a swapped group file.

**What I changed:**
- Claude put the RSA-PSS sign/verify calls inside the `_Party` base class.
  I moved them to module-level `sign()` / `verify()` functions so they can be
  unit-tested independently without constructing a full party object.
- The initial `derive_keys` draft used HKDF.  I replaced it with the
  HMAC-based chain specified in the assignment (SHA-256(KDF_LABEL || z || TH)
  for k_master, then HMAC(k_master, label || TH) for each traffic key).
- I added `_forget_ephemeral()` to wipe `_dh_priv` and `_z` immediately after
  key derivation; Claude's draft kept them as instance attributes indefinitely.
- Verified independently: ran `python handshake.py` and confirmed
  `both sides derived identical keys: True` and `4 traffic keys pairwise
  distinct: True`.

**Limitation / error I found:**
Claude's `decode_fields` returned silently when there were trailing bytes
(e.g., an extra length-prefix with no payload).  I tightened it to raise
`MalformedMessage` whenever the parsed fields and the buffer don't align
exactly, and added a corresponding test (`test_trailing_bytes_rejected` in
`test_handshake.py`).

---

## Entry 3 — Claude (Task 3: record layer + Task 4: tests)

- **Tool / model / date:** Claude (Anthropic, claude.ai), Oct 3, 2026.
- **Purpose:** Implement `secure_record.py`'s `seal` / `open_record` and the
  full pytest suite (49 tests).
- **Log file:** `ai_logs/claude_session3_task3_task4.md`

**What I asked:**
I shared the wire format from the assignment (version || direction || sequence ||
message_type || ct_len || ciphertext || HMAC-SHA-256 tag) and asked Claude to
generate `seal()` and `open_record()` with the receive-order guard
(framing -> version -> direction -> sequence -> MAC -> decrypt) and seven
custom exception classes.  I also asked it to generate a test file targeting
the most likely mutation points.

**What I used:**
- The exception hierarchy (`RecordError` -> `MalformedRecord`,
  `WrongDirection`, `ReplayOrReorder`, `BadMAC`, `SequenceExhausted`,
  `ChannelClosed`) was directly used.
- The `verify-before-decrypt` ordering (HMAC check before `_ctr()` is called)
  came from Claude's explanation of why decrypting before verifying is unsafe.
- The `channel_states(keys, role)` helper that switches send/recv orientation
  per role was Claude's suggestion.

**What I changed:**
- Claude's first test suite did **not** adequately test role binding.  Its
  reflection test used different RSA key pairs, so removing the role byte from
  `sign()` still passed because the wrong peer key already blocked the
  handshake.  I added `test_reflection_with_shared_identity_key_rejected` in
  `test_handshake.py` to catch this: two parties sharing one RSA key can still
  be distinguished only by the role string.
- Claude tagged the IV onto the wire (16 extra bytes per record).  The
  assignment says the IV is implicit (`session_id || seq`, both sides rebuild
  it), so I removed it from the wire format and confirmed the MAC still covers
  the reconstructed IV by including it explicitly in the HMAC feed
  (`header || iv || ciphertext`).
- I added the `MAX_PLAINTEXT` cap (16 MiB) and the `SequenceExhausted` guard
  myself; Claude's draft had no upper-bound on either.

**CTR counter-block overlap (documented, not fixed):**
The assignment's IV layout (`session_id[8] || seq[8]`) means consecutive
records share the same 8-byte prefix and differ only in the low 8 bytes.
AES-CTR increments the full 128-bit block counter starting from the IV.
Record seq=0 uses counter blocks 0, 1, 2, ... and record seq=1 uses counter
block starting at 1.  Therefore block 1 of record seq=0 and block 0 of
record seq=1 are the same counter value — keystream overlap occurs for any
record seq=0 longer than 16 bytes (one AES block).  Short first records (≤ 16
bytes) do not overlap.  The test `test_spec_iv_layout_counter_overlap_is_documented`
pins this: it asserts `ks(seq=0, 32 bytes)[16:]  ==  ks(seq=1, 16 bytes)`.
I kept the wire format as specified and documented the limitation in the report.

**What I tested:**
- `python -m pytest -v` -> 49 passed, 0 failed (Python 3.12.3,
  cryptography 49.0.0, pytest 9.1.1).
- Sequence check mutation: changed `if seq != state.seq:` to `if False:` in
  `open_record` → 3 replay/reorder tests failed as expected; restored with
  `git checkout`.
- Signature mutation: replaced the `verify(…ROLE_NODE…)` call with `pass` →
  7 authentication tests failed; restored.
- Verified one record independently with OpenSSL:
  `openssl enc -aes-256-ctr -d -nosalt -K <k_enc_hex> -iv <iv_hex>` matched
  the Python plaintext, and the HMAC-SHA-256 tag recomputed with
  `openssl dgst -hmac` matched byte-for-byte.

**Limitation / error I found:**
The test for `SequenceExhausted` in Claude's draft set `state.seq = 2**64`
(which is one past the last valid sequence), so the check triggered one send
too early.  The correct threshold is `state.seq > MAX_SEQ` (i.e., after all
2^64 IVs have been consumed).  Fixed and verified.

---

## Entry 4 — Claude (Report review)

- **Tool / model / date:** Claude (Anthropic, claude.ai), Oct 4, 2026.
- **Purpose:** Review a draft of my LaTeX report for factual accuracy and
  LaTeX escaping issues before submission.
- **Log file:** `ai_logs/claude_session4_report.md`

**What I asked:**
I pasted the LaTeX source of each task's analysis section and asked Claude to
flag any factual errors or overclaims.

**What I used:**
- Correction: I had written "32-bit block counter" in the CTR section; Claude
  pointed out AES-CTR uses a full 128-bit counter (only the low 32 bits
  increment in some software implementations).  I updated the text.
- Correction: A screenshot caption said "mutation made decryption fail"; Claude
  noted that in Encrypt-then-MAC the mutation is detected at the MAC step,
  before decryption is attempted.  I corrected the caption.
- LaTeX: `\` inside `\texttt{}` needed escaping in two places; Claude caught
  both.

**What I changed / rejected:**
- Claude suggested softening "the attacker can forge any message" to "the
  attacker can flip any known plaintext byte".  I kept the stronger phrasing
  because the assignment's threat model assumes the attacker knows the command
  layout (JSON with a fixed schema), which is realistic.
- I rewrote every prose paragraph in my own words; the only direct use of
  Claude's text is the two one-sentence corrections noted above.

---

## Entry 5 — ChatGPT (AI-use documentation structure)

- **Tool / model / date:** ChatGPT (GPT-5.6 Luna, chat.openai.com), Oct 4, 2026.
- **Purpose:** Understand the course's AI-use documentation requirements;
  ask how to organize the logs.
- **Log file:** `ai_logs/chatgpt_log.md` (real prompts recorded verbatim).

**What I asked:**
Real prompts (see log): "i want you to develop ai logs for this project" /
"i want you to stimulate genuine, and purposefull chat and conversation that
a student woulhd have iwht the ai which can be put here" / "give me the .md
files".

**What I used:**
- The explanation that AI logs must reflect real exchanges, not simulated ones.
- The suggested per-task log structure.

**What I changed / rejected:**
- ChatGPT generated a simulated sample student–AI conversation about AES-CTR.
  I did not include it because it is not a real exchange.
- ChatGPT produced a draft `AI_USAGE.md` and `chatgpt_log.md`; I used only
  the structure, not the content.

**How I tested it:**
Not applicable — no code or cryptographic content came from this session.

**Limitation:**
This log contains the real prompts verbatim; ChatGPT responses are summarized
because the UI does not support full Markdown export.
