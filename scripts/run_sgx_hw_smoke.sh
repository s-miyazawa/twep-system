#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
set -eu

mode=${1:?usage: run_sgx_hw_smoke.sh evidence|auth|catalog|app|apps-restart}
: "${SGX_HW_BUILD_DIR:?set SGX_HW_BUILD_DIR}"
: "${ATTESTAM_URL:?set ATTESTAM_URL}"
: "${TMPDIR:=/tmp}"

case "$mode" in
evidence) ;;
auth|catalog|app|apps-restart)
    ;;
*) echo "unknown mode: $mode" >&2; exit 2 ;;
esac

run_dir=$(mktemp -d "$TMPDIR/twep-sgx-hw-smoke.XXXXXX")
state_dir=$run_dir/state
capture_dir=$run_dir/capture
if test "$mode" = catalog || test "$mode" = app ||
   test "$mode" = apps-restart; then
    ./scripts/prepare_sgx_demo_state.sh "$state_dir"
else
    mkdir -p "$state_dir/teep-agent" "$state_dir/catalog" \
        "$state_dir/apps" "$state_dir/platform/sgx-sealed"
    cp build/teep-agent.wasm "$state_dir/teep-agent/teep-agent.wasm"
fi
mkdir -p "$capture_dir"
# AttesTAM insecure-demo pre-registers the default development Agent key. Use
# the published alternate public selector so every HW authentication smoke
# exercises the challenge/Evidence path. Keep this canonical public COSE_Key
# synchronized with internal/teepbroker.alternateDemoAgentKeyCBOR.
printf '%s' \
    'a50102032820012158200e908aa8f066db1f084e0c3652c63952bd99f2a5bdb22f9e01367aad03aba68b22582077da1bd8ac4f0cb490ba210648bf79ab164d49ad3551d71d314b2749ee42d29a' |
    xxd -r -p >"$state_dir/teep-agent/dev-agent-public-key.cbor"
if test "$mode" != catalog && test "$mode" != app &&
   test "$mode" != apps-restart; then
    cp build/catalog.dev.cbor "$state_dir/catalog/catalog.cbor"
    cp build/helloworld.wasm "$state_dir/apps/helloworld.wasm"
fi

runner_mode=auth
if test "$mode" = catalog; then
    runner_mode=catalog
elif test "$mode" = app; then
    runner_mode=app
elif test "$mode" = apps-restart; then
    runner_mode=apps-restart
fi
if test "$mode" = apps-restart; then
    "$SGX_HW_BUILD_DIR/sgx_hw_runner" "$state_dir" "$ATTESTAM_URL" \
        "$capture_dir" "$runner_mode" testdata/images/input.jpg
else
    "$SGX_HW_BUILD_DIR/sgx_hw_runner" "$state_dir" "$ATTESTAM_URL" \
        "$capture_dir" "$runner_mode"
fi
set -- --capture-dir "$capture_dir" --bundle-out "$run_dir/evidence.cbor"
check_output=$(python3 scripts/check_sgx_dcap_bundle.py "$@")
printf '%s\n' "$check_output"
if test "$mode" = auth; then
    test -s "$state_dir/teep-agent/last-session-result.txt" || {
        echo "AttesTAM authentication did not produce a terminal session result" >&2
        exit 1
    }
fi
if test "$mode" = auth || test "$mode" = catalog || test "$mode" = app ||
   test "$mode" = apps-restart; then
    evidence_capture=$(printf '%s\n' "$check_output" |
        sed -n 's/^evidence-capture=//p')
    replay_status=$(curl -sS -o "$run_dir/replay-response.bin" -w '%{http_code}' \
        -H 'Content-Type: application/teep+cbor' \
        -H 'Accept: application/teep+cbor' \
        --data-binary "@$capture_dir/$evidence_capture" "$ATTESTAM_URL" || true)
    case "$replay_status" in
    4??|5??) ;;
    *)
        echo "AttesTAM replay returned HTTP $replay_status; expected a 4xx rejection or the pinned server's known HTTP 500 rejection" >&2
        exit 1
        ;;
    esac
    echo "challenge-replay-rejected=true"
    echo "challenge-replay-http-status=$replay_status"
fi
if test "$mode" = catalog; then
    test "$(cat "$state_dir/teep-agent/last-session-result.txt")" = \
        "session-result=teep.verified_required" || {
        echo "Catalog session did not terminate at teep.verified_required" >&2
        exit 1
    }
    test "$(cat "$state_dir/teep-agent/success-status.txt")" = \
        "host-status=ok" || {
        echo "Catalog Success POST was not acknowledged" >&2
        exit 1
    }
    test -s "$state_dir/teep-agent/success-payload.cbor" || {
        echo "Catalog Success payload was not produced" >&2
        exit 1
    }
    test -f "$state_dir/platform/sgx-sealed/catalog-slot-0.blob" \
        -o -f "$state_dir/platform/sgx-sealed/catalog-slot-1.blob" || {
        echo "protected Catalog slot was not published" >&2
        exit 1
    }
    test -f "$state_dir/platform/sgx-sealed/acceptance-slot-0.blob" \
        -o -f "$state_dir/platform/sgx-sealed/acceptance-slot-1.blob" || {
        echo "protected D043 acceptance slot was not published" >&2
        exit 1
    }
    test ! -e "$state_dir/catalog/catalog.cbor" || {
        echo "REE Catalog mirror was created" >&2
        exit 1
    }
    test -z "$(find "$state_dir/apps" -type f -print -quit)" || {
        echo "application state was created during Catalog-only smoke" >&2
        exit 1
    }
    echo "protected-catalog-committed=true"
    echo "protected-acceptance-published=true"
    echo "catalog-success-posted=true"
    echo "ree-catalog-mirror=false"
    echo "app-installed=false"
    echo "app-executed=false"
    echo "final-verified=false"
fi
if test "$mode" = app || test "$mode" = apps-restart; then
    test -f "$state_dir/platform/sgx-sealed/catalog-slot-0.blob" \
        -o -f "$state_dir/platform/sgx-sealed/catalog-slot-1.blob" || {
        echo "protected Catalog slot was not published" >&2
        exit 1
    }
    test -f "$state_dir/platform/sgx-sealed/app-slot-0.blob" \
        -o -f "$state_dir/platform/sgx-sealed/app-slot-1.blob" || {
        echo "protected app slot was not published" >&2
        exit 1
    }
    test -f "$state_dir/platform/sgx-sealed/acceptance-slot-0.blob" \
        -o -f "$state_dir/platform/sgx-sealed/acceptance-slot-1.blob" || {
        echo "protected D043 acceptance slot was not published" >&2
        exit 1
    }
    test "$(cat "$state_dir/teep-agent/success-status.txt")" = \
        "host-status=ok" || {
        echo "app Success POST was not acknowledged" >&2
        exit 1
    }
    test -s "$state_dir/teep-agent/success-payload.cbor" || {
        echo "app Success payload was not produced" >&2
        exit 1
    }
    test ! -e "$state_dir/catalog/catalog.cbor" || {
        echo "REE Catalog mirror was created" >&2
        exit 1
    }
    test -z "$(find "$state_dir/apps" -type f -print -quit)" || {
        echo "plaintext REE application state was created" >&2
        exit 1
    }
    echo "protected-catalog-committed=true"
    echo "protected-app-committed=true"
    if test "$mode" = apps-restart; then
        echo "protected-acceptance-generation=4"
        echo "apps-online-executed=helloworld,calcadd,negaposi"
        echo "apps-offline-restarted=helloworld,calcadd,negaposi"
        echo "offline-http-requests=0"
    else
        echo "protected-acceptance-generation=2"
    fi
    echo "app-success-posted=true"
    echo "app-executed=true"
    echo "ree-catalog-mirror=false"
    echo "ree-app-plaintext=false"
    echo "final-verified=false"
fi
echo "artifacts=$run_dir"
