#!/usr/bin/env bash
# Differential test: cross-check the Zig krb5 implementation against gokrb5
# byte-for-byte. Requires Go + the gokrb5 module (tools/godiff) and Zig.
#
# Most of these checks are also baked into the Zig unit tests (zig build test);
# this script regenerates the gokrb5 reference values and exercises the one
# direction the Zig tests can't (Zig-encrypt -> gokrb5-decrypt).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== gokrb5 AS-REQ reference (compare to kdc_req.zig test expectations) =="
(cd tools/godiff && go run . asreq)

echo
echo "== gokrb5 EncryptedData KVNO handling (compare to encrypted_data.zig) =="
(cd tools/godiff && go run . encdata)

echo
echo "== Zig-encrypt -> gokrb5-decrypt (etype 18 & 23) =="
zig build-exe --dep krb5 -Mroot=tools/enc_probe.zig -Mkrb5=krb5/krb5.zig -femit-bin=/tmp/kerbrutez_enc_probe >/dev/null
out=$(/tmp/kerbrutez_enc_probe)
ct18=$(echo "$out" | awk '/ETYPE18/{print $2}')
ct23=$(echo "$out" | awk '/ETYPE23/{print $2}')
key18="0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
key23="0102030405060708090a0b0c0d0e0f10"
echo -n "etype18 -> "; (cd tools/godiff && go run . decrypt 18 "$key18" "$ct18" 1)
echo -n "etype23 -> "; (cd tools/godiff && go run . decrypt 23 "$key23" "$ct23" 1)
echo "(both should print \"hello kerberos preauth\")"
