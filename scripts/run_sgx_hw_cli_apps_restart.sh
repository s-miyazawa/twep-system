#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
set -eu

: "${SGX_HW_BUILD_DIR:?set SGX_HW_BUILD_DIR}"
: "${ATTESTAM_URL:?set ATTESTAM_URL}"
: "${TMPDIR:=/tmp}"

run_dir=$(mktemp -d "$TMPDIR/twep-sgx-cli-pr10.XXXXXX")
state_dir=$run_dir/state
./scripts/prepare_sgx_demo_state.sh "$state_dir"

run_cli() {
    phase=$1
    url=$2
    app=$3
    sock=$run_dir/$phase-$app.sock
    daemon_log=$run_dir/$phase-$app.twepd.log
    cli_out=$run_dir/$phase-$app.cli.out
    LD_LIBRARY_PATH="$SGX_HW_BUILD_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
        ./bin/twepd --socket "$sock" --state-dir "$state_dir" \
        --resolver-mode attestam-verified --attestam-url "$url" \
        --insecure-demo-agent-key alternate --once \
        >"$daemon_log" 2>&1 &
    pid=$!
    ready=false
    for ignored in 1 2 3 4 5 6 7 8 9 10; do
        if test -S "$sock"; then ready=true; break; fi
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep 1
    done
    if test "$ready" != true; then
        wait "$pid" || true
        sed 's/^/twepd: /' "$daemon_log" >&2
        echo "$phase $app daemon did not become ready" >&2
        return 1
    fi
    cli_status=0
    case "$app" in
    helloworld)
        ./bin/twep-cli --socket "$sock" helloworld >"$cli_out" || cli_status=$?
        ;;
    calcadd)
        ./bin/twep-cli --socket "$sock" calcadd 3 4 5 >"$cli_out" || cli_status=$?
        ;;
    negaposi)
        ./bin/twep-cli --socket "$sock" negaposi \
            -i testdata/images/input.jpg -o "$run_dir/$phase-negaposi.jpg" \
            >"$cli_out" || cli_status=$?
        ;;
    esac
    daemon_status=0
    wait "$pid" || daemon_status=$?
    if test "$cli_status" -ne 0 || test "$daemon_status" -ne 0; then
        sed 's/^/twepd: /' "$daemon_log" >&2
        test "$cli_status" -ne 0 && return "$cli_status"
        return "$daemon_status"
    fi
    case "$app" in
    helloworld) test "$(cat "$cli_out")" = 'Hello, World!!' ;;
    calcadd) test "$(cat "$cli_out")" = '12' ;;
    negaposi)
        test "$(cat "$cli_out")" = 'Saving a Reversed Color Image'
        test -s "$run_dir/$phase-negaposi.jpg"
        ! cmp -s testdata/images/input.jpg "$run_dir/$phase-negaposi.jpg"
        ;;
    esac
    printf '%s-%s-cli-output=%s\n' "$phase" "$app" "$(cat "$cli_out")"
}

# The first request publishes the Catalog and deliberately terminates at the
# bounded verified-required checkpoint. A retry then installs the first app.
if run_cli catalog "$ATTESTAM_URL" helloworld; then
    echo "initial Catalog request unexpectedly executed an app" >&2
    exit 1
fi
test "$(cat "$state_dir/teep-agent/last-session-result.txt")" = \
    'session-result=teep.verified_required'

for app in helloworld calcadd negaposi; do
    run_cli online "$ATTESTAM_URL" "$app"
    run_cli offline 'http://127.0.0.1:1/tam' "$app"
done

test -f "$state_dir/platform/sgx-sealed/catalog-slot-0.blob" \
    -o -f "$state_dir/platform/sgx-sealed/catalog-slot-1.blob"
test -f "$state_dir/platform/sgx-sealed/app-slot-0.blob" \
    -o -f "$state_dir/platform/sgx-sealed/app-slot-1.blob"
test -f "$state_dir/platform/sgx-sealed/acceptance-slot-0.blob" \
    -o -f "$state_dir/platform/sgx-sealed/acceptance-slot-1.blob"
test ! -e "$state_dir/catalog/catalog.cbor"
test -z "$(find "$state_dir/apps" -type f -print -quit)"
echo 'protected-acceptance-generation=4'
echo 'cli-apps-online-executed=helloworld,calcadd,negaposi'
echo 'cli-apps-offline-restarted=helloworld,calcadd,negaposi'
echo 'ree-catalog-mirror=false'
echo 'ree-app-plaintext=false'
echo 'final-verified=false'
echo "artifacts=$run_dir"
