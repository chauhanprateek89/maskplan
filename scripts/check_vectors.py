#!/usr/bin/env python3
"""Independent check of testdata/vectors.json using Python's hmac module.

The vectors are generated from the Go reference implementation. This script
recomputes every token and fake index from docs/token-spec.md without sharing
any code with it, so a bug in the Go code cannot hide in the vectors.

Usage: python3 scripts/check_vectors.py [testdata/vectors.json]
"""
import hashlib
import hmac
import json
import sys

TRIM = " \t\r\n"


def normalize(normalizer, value):
    if normalizer == "trim":
        return value.strip(TRIM)
    if normalizer == "email":
        trimmed = value.strip(TRIM)
        return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in trimmed)
    if normalizer == "phone":
        return "".join(c for c in value if c in "0123456789")
    raise ValueError(f"unknown normalizer {normalizer!r}")


def main(path):
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    size = data["fake_dictionary_size"]
    failures = 0
    for v in data["vectors"]:
        if v["input"] is None:
            want_token, want_index = None, None
        else:
            message = (v["label"] + ":" + normalize(v["normalizer"], v["input"])).encode("utf-8")
            mac = hmac.new(bytes.fromhex(v["key"]), message, hashlib.sha256).digest()
            want_token = "tok_" + mac.hex()[: v["token_hex_len"]]
            want_index = (int.from_bytes(mac[:4], "big") & 0x7FFFFFFF) % size
        if (v["token"], v["fake_index"]) != (want_token, want_index):
            failures += 1
            print(f"MISMATCH {v['name']}: file has {v['token']}/{v['fake_index']}, "
                  f"python computes {want_token}/{want_index}")
    print(f"{len(data['vectors'])} vectors checked, {failures} mismatches")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "testdata/vectors.json"))
