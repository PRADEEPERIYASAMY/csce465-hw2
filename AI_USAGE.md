# AI Usage — HW2

Two AI tools were used. Entry 1 covers almost all of the assistance.

## Entry 1 — Claude

<!-- Review every line. Keep it accurate; edit the "What I changed" / "How I tested" parts to match what YOU did. -->

- **Tool/model and date:** Claude (Anthropic, claude.ai; model id claude-opus-5-5), Oct 3–4, 2026.
- **Purpose:** Help implementing and testing Tasks 1–4, understanding the protocol, and organizing the report.
- **AI Conversation Log files:** `ai_logs/claude_hw2_conversation.pdf` (full exported conversation; personal details removed).
- **What I used:**
  - Generated a first version of `baseline_ctr.py`, `handshake.py`, `secure_record.py`, the pytest suite, `README.md`, `inspect_record.py` and `capture_evidence.sh`.
  - Explanations of the design (CTR malleability, signed transcript, role binding, key separation, verify-before-decrypt) and a step-by-step verification guide.
  - A report skeleton (LaTeX) containing my screenshots/evidence and bullet-point notes. I wrote the explanation sections; the AI then reviewed my draft, corrected factual errors (32-bit vs 32-byte block counter, wrong mutation screenshot, overclaim about purging DH keys, framing vs. ordering), fixed LaTeX escaping, and simplified some wording. I checked every change.
- **What I changed:** <!-- e.g. moved repo to ~/csce465-agentsec/hw2, fixed venv setup (python3.12-venv), re-ran everything on my VM, rewrote all report text in my own words, ... -->
- **How I tested it:**
  - Ran all three programs and `python -m pytest -v` (49 passed) on my course VM with Python 3.12.3, cryptography 49.0.0, pytest 9.1.1.
  - Verified one record independently with the OpenSSL CLI (AES-256-CTR decrypt + HMAC-SHA-256 tag matched).
  - Checked the XOR relation 'READ' ⊕ 'WIPE' = 050c1101 by hand.
  - Mutation check: disabled the sequence check (3 tests failed) and the signature verification (7 tests failed), then restored with git checkout.
- **One error, limitation, or rejected suggestion:**
  - The AI's first test suite did not actually test role binding: removing the role from the signature still passed all tests, because with different RSA keys the peer-key check already blocks reflection. A test with a shared identity key was added so that mutation now fails.
  - The assigned IV layout (session_id ‖ seq) makes CTR counter blocks of consecutive records overlap; kept the spec format and documented it in the report instead of silently changing the wire format.

## Entry 2 — ChatGPT

- **Tool/model and date:** ChatGPT (GPT-5.6 Luna), Oct 4, 2026.
- **Purpose:** Understanding the assignment's AI-use documentation requirements and how to organize the logs.
- **AI Conversation Log files:** `ai_logs/chatgpt_log.md`.
- **What I used:** The suggested way of organizing the AI-use record by task.
- **What I changed / rejected:** ChatGPT offered a simulated "sample" student–AI conversation. I did not submit it, because it is not a real conversation; only the actual exchange is logged.
- **How I tested it:** Not applicable (no code or technical content came from this session).
- **Limitation:** The ChatGPT log contains my exact prompts and summaries of the responses rather than a full verbatim export.
