# CSCE 465/765 HW2 — Protect Agent Messages with Classic Cryptography

## Setup (course VM, Ubuntu 24.04)
```bash
cd "$HOME/csce465-agentsec"
python3 -m venv .venv && source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1
cd hw2
# group file (already included; regenerate if you like)
openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem
openssl dhparam -in ffdhe3072.pem -text -noout | head -3
```
`handshake.load_group()` refuses any group file whose prime is not the RFC 7919 ffdhe3072 prime.

## Run
| Task | Command | What it shows |
|---|---|---|
| 1 | `python baseline_ctr.py` | READ→WIPE bit-flip without the key, XOR relation, replay processed twice |
| 2 | `python handshake.py` | RSA-PSS-authenticated ffdhe3072 handshake, identical keys on both sides |
| 3 | `python secure_record.py` | encrypt-then-MAC records both ways; replay / reflection / bit-flip rejected |
| 4 | `python -m pytest -v` | 49 adversarial tests, each asserting a specific exception |

## Files
- `baseline_ctr.py` — Task 1, AES-CTR with no MAC (intentionally insecure).
- `handshake.py` — Task 2. `Gateway`, `Node`, `run_handshake()`, `transcript_hash()`, `derive_keys()`.
- `secure_record.py` — Task 3. `seal()`, `open_record()`, `channel_states()`.
- `tests/` — Task 4. `test_handshake.py`, `test_record.py`, `test_baseline.py`.
- `capture_evidence.sh` — regenerates `evidence/` (all program/test output for the report) on the VM.
- `screenshots/` — terminal screenshots from the course VM used in report.pdf.
- `inspect_record.py` — dumps one record + keys so OpenSSL can verify it independently.

## Error types (each test asserts one of these)
Handshake: `MalformedMessage`, `InvalidPublicValue`, `UnexpectedIdentity`, `ReflectionDetected`, `BadSignature`, `ProtocolStateError`.
Record: `MalformedRecord`, `WrongDirection`, `ReplayOrReorder`, `BadMAC`, `SequenceExhausted`, `ChannelClosed`.
On any error no keys / no plaintext are returned and receiver state does not advance.
