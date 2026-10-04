#!/usr/bin/env bash
# Regenerate every piece of report evidence on YOUR VM, with a timestamp + hostname header.
# Usage (venv active, inside hw2/):  bash capture_evidence.sh
set -u
cd "$(dirname "$0")"
OUT=evidence; rm -rf "$OUT"; mkdir -p "$OUT"
hdr(){ echo "# $(date '+%F %T %Z') | $(whoami)@$(hostname) | $(pwd)"; echo "\$ $*"; echo; }
run(){ f=$1; shift; { hdr "$@"; "$@" 2>&1; } > "$OUT/$f"; echo "wrote $OUT/$f"; }

# 0. Lab preparation
{ hdr "env"; python3 --version; openssl version; pip show cryptography pytest | grep -E '^(Name|Version)';
  echo; echo "\$ openssl dhparam -in ffdhe3072.pem -text -noout | head -3";
  openssl dhparam -in ffdhe3072.pem -text -noout | head -3; } > "$OUT/task0_lab_prep.txt" 2>&1; echo "wrote $OUT/task0_lab_prep.txt"

# 1-3. Demos
run task1_baseline_ctr.txt   python baseline_ctr.py
run task2_handshake.txt      python handshake.py
run task3_secure_record.txt  python secure_record.py

# 3b. Independent check of one record with OpenSSL
{ hdr "inspect_record.py + openssl"
  eval "$(python inspect_record.py)"
  hex2bin(){ python3 -c "import sys;sys.stdout.buffer.write(bytes.fromhex(sys.argv[1]))" "$1"; }
  echo "header      = $HDR"
  echo "  version=${HDR:0:2} direction=${HDR:2:2} seq=${HDR:4:16} type=${HDR:20:2} ct_len=${HDR:22:8}"
  echo "iv          = $IV  (session_id || seq)"
  echo -n "openssl decrypt -> "; hex2bin "$CT" | openssl enc -d -aes-256-ctr -K "$ENC" -iv "$IV"; echo
  M=$(hex2bin "$HDR$IV$CT" | openssl dgst -sha256 -mac HMAC -macopt hexkey:"$MAC" | awk '{print $NF}')
  echo "openssl HMAC    = $M"; echo "record tag      = $TAG"
  [ "$M" = "$TAG" ] && echo "MATCH: tag verified independently" || echo "MISMATCH"
} > "$OUT/task3_openssl_check.txt" 2>&1; echo "wrote $OUT/task3_openssl_check.txt"

# 4. Tests
run task4_pytest.txt python -m pytest -v
echo; grep -h -E "passed|failed" "$OUT/task4_pytest.txt" | tail -1
