#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
set -eu

usage() {
    echo "usage: $0 [--reset] STATE_DIR" >&2
}

reset=false
case "$#" in
    1) state_dir=$1 ;;
    2)
        test "$1" = --reset || {
            usage
            exit 2
        }
        reset=true
        state_dir=$2
        ;;
    *)
        usage
        exit 2
        ;;
esac

: "${TMPDIR:=/tmp}"
export TMPDIR

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"

test -f build/teep-agent.wasm || {
    echo "error: missing build/teep-agent.wasm; run make build first" >&2
    exit 1
}
test -f build/catalog.dev.cbor || {
    echo "error: missing build/catalog.dev.cbor; run make build first" >&2
    exit 1
}

if [ "$reset" = true ]; then
    case "$TMPDIR" in
        /*) ;;
        *) echo "error: TMPDIR must be an absolute path: $TMPDIR" >&2; exit 1 ;;
    esac
    reset_root=$(realpath -m -- "$TMPDIR") || {
        echo "error: cannot resolve TMPDIR: $TMPDIR" >&2
        exit 1
    }
    test "$reset_root" != / || {
        echo "error: refusing reset with TMPDIR=/" >&2
        exit 1
    }
    test -n "$state_dir" && test "$state_dir" != / || {
        echo "error: unsafe reset state directory: $state_dir" >&2
        exit 1
    }
    lexical_state_dir=$(realpath -ms -- "$state_dir") || {
        echo "error: cannot resolve reset state directory: $state_dir" >&2
        exit 1
    }
    case "$lexical_state_dir" in
        "$reset_root"/*) ;;
        *)
            echo "error: reset state directory must be below $reset_root: $state_dir" >&2
            exit 1
            ;;
    esac
    canonical_reset_root=$(realpath -m -- "$reset_root")
    relative_state_dir=${lexical_state_dir#"$reset_root"/}
    canonical_state_dir=$(realpath -m -- "$state_dir") || {
        echo "error: cannot resolve reset state directory: $state_dir" >&2
        exit 1
    }
    expected_state_dir=$(realpath -ms -- \
        "$canonical_reset_root/$relative_state_dir")
    test "$canonical_state_dir" = "$expected_state_dir" || {
        echo "error: reset state path must not contain a symlink: $state_dir" >&2
        exit 1
    }
    if [ -e "$canonical_state_dir" ]; then
        test -d "$canonical_state_dir" || {
            echo "error: state path is not a directory: $state_dir" >&2
            exit 1
        }
        rm -rf -- "$canonical_state_dir"
    fi
    state_dir=$canonical_state_dir
fi

if [ -e "$state_dir" ]; then
    test -d "$state_dir" || {
        echo "error: state path is not a directory: $state_dir" >&2
        exit 1
    }
    test -z "$(find "$state_dir" -mindepth 1 -print -quit)" || {
        echo "error: state directory is not empty: $state_dir" >&2
        exit 1
    }
fi

mkdir -p "$TMPDIR"
fixture_dir=$(mktemp -d "$TMPDIR/twep-sgx-personalization.XXXXXX")
cleanup() {
    rm -rf -- "$fixture_dir"
}
trap cleanup 0 HUP INT TERM

go run ./cmd/twep-attestam-fixture-gen --catalog \
    --catalog-payload build/catalog.dev.cbor \
    --out "$fixture_dir/catalog.envelope.cbor" --sequence 1 \
    --protected-store-out "$fixture_dir/protected-credential-store.cbor" \
    --issuer-allowlist-out "$fixture_dir/protected-issuer-allowlist.cbor"

mkdir -p "$state_dir/teep-agent" "$state_dir/catalog" "$state_dir/apps" \
    "$state_dir/platform/sgx-sealed" "$state_dir/personalization"
chmod 0755 "$state_dir"
cp build/teep-agent.wasm "$state_dir/teep-agent/teep-agent.wasm"
cp "$fixture_dir/protected-credential-store.cbor" \
    "$state_dir/personalization/protected-credential-store.cbor"
cp "$fixture_dir/protected-issuer-allowlist.cbor" \
    "$state_dir/personalization/protected-issuer-allowlist.cbor"
printf '%s' 'a0' | xxd -r -p \
    >"$state_dir/personalization/protected-sequence-freshness.cbor"
printf '%s' \
    'a26e736368656d615f76657273696f6e016f6d61785f73746f72655f65706f636801' |
    xxd -r -p >"$state_dir/personalization/protected-store-freshness.cbor"
printf '%s' \
    'a26e736368656d615f76657273696f6e01717265766f6b65645f656e7472795f696473814d7265766f6b65642d656e747279' |
    xxd -r -p >"$state_dir/personalization/protected-revocation-state.cbor"

echo "prepared SGX demo state: $state_dir"
