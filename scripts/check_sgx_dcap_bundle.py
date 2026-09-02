#!/usr/bin/env python3
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
"""Locate and validate the PR-9 Quote3 bundle in captured TEEP messages."""

import argparse
import hashlib
from pathlib import Path


class CBORError(ValueError):
    pass


def item(data, off=0):
    if off >= len(data):
        raise CBORError("truncated item")
    first, off = data[off], off + 1
    major, ai = first >> 5, first & 31
    if ai < 24:
        value = ai
    elif ai in (24, 25, 26, 27):
        width = 1 << (ai - 24)
        if off + width > len(data):
            raise CBORError("truncated argument")
        value = int.from_bytes(data[off:off + width], "big")
        if value < (24, 256, 65536, 4294967296)[ai - 24]:
            raise CBORError("non-canonical argument")
        off += width
    else:
        raise CBORError("indefinite/reserved item")
    if major in (0, 1):
        return (value if major == 0 else -1 - value), off
    if major in (2, 3):
        if off + value > len(data):
            raise CBORError("truncated string")
        raw = data[off:off + value]
        return (raw if major == 2 else raw.decode()), off + value
    if major == 4:
        out = []
        for _ in range(value):
            child, off = item(data, off)
            out.append(child)
        return out, off
    if major == 5:
        out = {}
        for _ in range(value):
            key, off = item(data, off)
            child, off = item(data, off)
            try:
                out[key] = child
            except TypeError as exc:
                raise CBORError("non-hashable map key") from exc
        return out, off
    if major == 6:
        child, off = item(data, off)
        return ("tag", value, child), off
    if major == 7 and value in (20, 21, 22):
        return (False, True, None)[value - 20], off
    raise CBORError("unsupported simple value")


def candidates(value):
    if (isinstance(value, list) and len(value) == 2
            and all(isinstance(v, bytes) for v in value)):
        yield value
    children = value if isinstance(value, (list, tuple)) else (
        value.values() if isinstance(value, dict) else ())
    for child in children:
        yield from candidates(child)
        if isinstance(child, bytes):
            try:
                nested, end = item(child)
                if end == len(child):
                    yield from candidates(nested)
            except (CBORError, UnicodeDecodeError):
                pass


def find_bundle(paths):
    found = []
    for path in paths:
        data = path.read_bytes()
        # The initial TEEP-over-HTTP POST has an intentionally empty body.
        if not data:
            continue
        if len(data) > 32 * 1024:
            raise SystemExit(f"{path}: signed QueryResponse exceeds 32 KiB")
        try:
            value, end = item(data)
            if end != len(data):
                raise CBORError("extra CBOR")
        except (CBORError, UnicodeDecodeError) as exc:
            raise SystemExit(f"{path}: malformed captured CBOR: {exc}") from exc
        for quote, raw in candidates(value):
            if len(quote) >= 436 and quote[:2] == b"\x03\x00":
                found.append((path, quote, raw))
    if len(found) != 1:
        raise SystemExit(f"expected one Quote3 bundle, found {len(found)}")
    return found[0]


def validate_quote(quote, raw):
    if len(quote) > 28 * 1024:
        raise SystemExit("Quote3 exceeds 28 KiB")
    if not 72 <= len(raw) <= 128:
        raise SystemExit("raw binding must be x || y || 8..64-byte challenge")
    signature_len = int.from_bytes(quote[432:436], "little")
    if signature_len != len(quote) - 436:
        raise SystemExit("Quote3 signature length mismatch")
    digest = hashlib.sha384(raw).digest()
    if quote[368:416] != digest or quote[416:432] != bytes(16):
        raise SystemExit("Quote3 report_data binding mismatch")
    return raw[:32], raw[32:64], raw[64:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--capture-dir", required=True, type=Path)
    parser.add_argument("--bundle-out", required=True, type=Path)
    args = parser.parse_args()
    path, quote, raw = find_bundle(sorted(args.capture_dir.glob("request-*.cbor")))
    _, _, challenge = validate_quote(quote, raw)
    bundle = bytes([0x82]) + encode_bytes(quote) + encode_bytes(raw)
    if len(bundle) > 30 * 1024:
        raise SystemExit("Evidence bundle exceeds 30 KiB")
    args.bundle_out.write_bytes(bundle)
    print(f"quote-length={len(quote)}")
    print(f"bundle-length={len(bundle)}")
    print(f"challenge-id={hashlib.sha256(challenge).hexdigest()[:16]}")
    print(f"evidence-capture={path.name}")
    print("quote3-report-data-binding-valid=true")
    print("attestam-challenge-completed=true")
    print("target-environment-appraised=false")
    print("final-verified=false")


def encode_bytes(value):
    length = len(value)
    if length < 24:
        return bytes([0x40 | length]) + value
    if length <= 255:
        return b"\x58" + bytes([length]) + value
    return b"\x59" + length.to_bytes(2, "big") + value


if __name__ == "__main__":
    main()
