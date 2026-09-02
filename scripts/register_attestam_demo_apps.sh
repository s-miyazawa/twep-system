#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
set -eu

usage() {
    echo "usage: $0 <RegisterManifest URL>" >&2
}

if [ "$#" -ne 1 ]; then
    usage
    exit 2
fi

register_url=$1
case "$register_url" in
http://*|https://*) ;;
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

mkdir -p "$TMPDIR"
make build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm \
    build/catalog.dev.cbor
mkdir -p build/attestam

registration_started=false
report_failure() {
    status=$?
    if [ "$status" -ne 0 ] && [ "$registration_started" = true ]; then
        echo "error: demo manifest registration failed" >&2
        echo "registration is non-transactional; if any request succeeded, retry with a fresh AttesTAM DB/cache" >&2
    fi
    exit "$status"
}
trap report_failure 0
registration_started=true

go run ./cmd/twep-attestam-fixture-gen --catalog \
    --catalog-payload build/catalog.dev.cbor \
    --out build/attestam/catalog-apps.envelope.cbor --sequence 1 \
    --register-url "$register_url"

for app in helloworld calcadd negaposi; do
    go run ./cmd/twep-attestam-fixture-gen --command "$app" \
        --wasm "build/$app.wasm" --wasm-file "$app.wasm" \
        --out "build/attestam/$app.envelope.cbor" --sequence 1 \
        --register-url "$register_url"
done

registration_started=false
echo "registered default Catalog, helloworld, calcadd, and negaposi"
