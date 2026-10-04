# Claude Session 4 — Report Review
## CSCE 465/765 HW2 — Oct 4, 2026

> **Note:** Prompts are verbatim.  Claude responses are summarized.
> LaTeX source excerpts are included where relevant to the correction.
> Personal account details removed.

---

### Exchange 1

**My prompt:**
> I have a draft of my HW2 report.  I'll paste each section and ask you to
> flag factual errors or overclaims before I submit.  Starting with the Task 1
> section:
>
> [pasted LaTeX section for Task 1]
>
> One sentence says: "AES-CTR uses a 32-bit block counter that wraps around
> after 2^32 blocks."  Is that accurate?

**Claude's response (summary):**
Claude flagged this as inaccurate.  AES-CTR uses a 128-bit counter block (the
full AES block width).  The 32-bit figure comes from software implementations
(e.g., RFC 3686, OpenSSL's CTR mode with a 32-bit increment) but is not a
property of AES itself.  The cryptography library in Python uses a full 128-bit
counter.  Claude suggested: "AES-CTR treats the IV as a 128-bit counter block
and increments it for each 16-byte keystream block."

**My action:** Updated the sentence.  Also double-checked in the cryptography
library docs that `modes.CTR(nonce)` indeed uses the full 128-bit nonce as the
starting counter value with a big-endian increment.

---

### Exchange 2

**My prompt:**
> Section for Task 3, screenshot caption reads:
> "Figure 3: bit-flip on ciphertext byte 11 of a sealed record causes
> decryption to produce garbled output."
> Is this accurate for Encrypt-then-MAC?

**Claude's response (summary):**
Claude flagged it as misleading.  In Encrypt-then-MAC the receiver verifies the
HMAC *before* attempting decryption.  A ciphertext mutation is caught at the
HMAC step and `open_record` raises `BadMAC` without ever calling the decryption
function.  The caption should say the mutation is *detected at the MAC
verification step, before decryption*.

**My action:** Changed the caption to: "Figure 3: bit-flip in ciphertext byte
11 is caught at HMAC verification (BadMAC raised) — decryption is never
reached."

---

### Exchange 3

**My prompt:**
> Here's the LaTeX for the security note about CTR block overlap.  Does it
> accurately describe the problem?
>
>   \texttt{IV = session\_id[8] || seq[8]} means record seq=0
>   occupies counter blocks 0 \ldots \lceil |P_0|/16 \rceil - 1, and
>   record seq=1 starts at counter block 1, potentially overlapping with
>   seq=0 if the first record is longer than 16 bytes.

**Claude's response (summary):**
Claude confirmed the analysis was correct.  If `|P_0| > 16` bytes then seq=0
uses counter blocks 0 and 1, and seq=1 starts counter block 1 — overlap.  It
suggested clarifying with the word "strictly": "seq=1 *always* overlaps with
seq=0 if the first record contains more than 16 bytes of plaintext."

**My action:** Adopted the suggested wording.

---

### Exchange 4

**My prompt:**
> Please check these two LaTeX snippets for escaping issues:
>
>   1. \texttt{K_enc} and \texttt{K_mac}
>   2. \texttt{session_id \| seq}

**Claude's response (summary):**
Claude identified that underscores inside `\texttt{}` in plain LaTeX (not
`lstlisting`) need to be escaped as `\_` to prevent subscript interpretation.
The `\|` in the second snippet renders as a double-bar symbol (‖) in math mode
but not in text mode — it should be `\texttt{session\_id || seq}` or use
`\textbar\textbar` for a literal double bar.

**My action:** Fixed both occurrences.

---

### What was rejected

- Claude suggested changing "an attacker who knows the plaintext layout can
  forge any message" to "flip any known byte".  I kept the original because
  within the assignment's threat model (fixed JSON schema), flipping a known
  byte is equivalent to choosing the new plaintext value, which is
  indistinguishable from forging.
- Claude offered to rewrite the entire introduction paragraph.  I declined;
  I rewrote it myself and only used Claude for the four factual/LaTeX
  corrections above.
