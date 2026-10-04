#!/usr/bin/env python3
"""Print one G->N record and its keys as shell vars, for checking with openssl (see VERIFY.md)."""
import handshake as hs, secure_record as sr
gw, nd = hs.make_pair(); k, _ = hs.run_handshake(gw, nd)
s, _ = sr.channel_states(k, "gateway")
r = sr.seal(s, sr.MSG_TOOL_CALL, b'{"action":"READ","path":"notes.txt"}')
H = sr.HEADER_LEN
print("ENC=" + k.g2n_enc.hex()); print("MAC=" + k.g2n_mac.hex())
print("IV="  + (k.session_id + (0).to_bytes(8, "big")).hex())
print("HDR=" + r[:H].hex()); print("CT=" + r[H:-32].hex()); print("TAG=" + r[-32:].hex())
