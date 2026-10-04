"""Task 1 regression tests: the *unprotected* baseline really is attackable."""
import json
import os

import baseline_ctr as b


def test_bitflip_changes_action_without_key():
    key = os.urandom(32)
    s, r = b.Sender(key), b.Receiver(key)
    nonce, ct = s.send(b.COMMAND)
    off = b.COMMAND.index(b"READ")
    _, ct2 = b.relay_flip(nonce, ct, off, b"READ", b"WIPE")
    assert r.receive(nonce, ct2) == {"action": "WIPE", "path": "notes.txt"}
    p2 = json.dumps(r.executed[-1], separators=(",", ":")).encode()
    assert b.xor(ct, ct2) == b.xor(b.COMMAND, p2)


def test_replay_is_processed_twice():
    key = os.urandom(32)
    s, r = b.Sender(key), b.Receiver(key)
    nonce, ct = s.send(b.COMMAND)
    r.receive(nonce, ct)
    r.receive(nonce, ct)
    assert len(r.executed) == 2 and r.executed[0] == r.executed[1]
