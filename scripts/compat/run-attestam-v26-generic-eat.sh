#!/bin/sh
# Run the Linux Generic EAT checkpoint against an isolated pinned AttesTAM.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
revisions="$repo_root/testdata/compat/upstream-revisions.env"

: "${ATTESTAM_ROOT:?set ATTESTAM_ROOT to an AttesTAM Git checkout}"
: "${WAMR_DIR:?set WAMR_DIR to the WAMR checkout used to build TWEP}"
: "${VERAISON_PROVISION_URL:?set VERAISON_PROVISION_URL to a disposable Veraison provisioning endpoint}"

ATTESTAM_CONFORMANCE_ADDR=${ATTESTAM_CONFORMANCE_ADDR:-127.0.0.1:18080}
VERAISON_CHALLENGE_URL=${VERAISON_CHALLENGE_URL:-https://127.0.0.1:8443}

case "$ATTESTAM_CONFORMANCE_ADDR" in
	127.0.0.1:[0-9]*) ;;
	*) echo "ATTESTAM_CONFORMANCE_ADDR must be a 127.0.0.1:port loopback address" >&2; exit 2 ;;
esac
port=${ATTESTAM_CONFORMANCE_ADDR#127.0.0.1:}
case "$port" in
	''|*[!0-9]*) echo "invalid AttesTAM port: $port" >&2; exit 2 ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
	echo "invalid AttesTAM port: $port" >&2
	exit 2
fi

if [ ! -f "$revisions" ]; then
	echo "missing pinned revision file: $revisions" >&2
	exit 2
fi
# This repository-owned file contains reviewed KEY=value revision pins only.
. "$revisions"
: "${ATTESTAM_REV:?ATTESTAM_REV is missing from $revisions}"

if ! git -C "$ATTESTAM_ROOT" cat-file -e "$ATTESTAM_REV^{commit}" 2>/dev/null; then
	echo "pinned AttesTAM revision $ATTESTAM_REV is unavailable in $ATTESTAM_ROOT" >&2
	exit 2
fi

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/twep-attestam-v26.XXXXXX")
attestam_pid=
attestam_log="$tmp_dir/attestam.log"
cleanup() {
	status=$?
	trap - EXIT HUP INT TERM
	if [ -n "$attestam_pid" ] && kill -0 "$attestam_pid" 2>/dev/null; then
		kill "$attestam_pid" 2>/dev/null || true
		wait "$attestam_pid" 2>/dev/null || true
	fi
	if [ "$status" -ne 0 ] && [ -s "$attestam_log" ]; then
		echo "AttesTAM log:" >&2
		sed 's/^/  /' "$attestam_log" >&2
	fi
	rm -rf "$tmp_dir"
	exit "$status"
}
trap cleanup EXIT HUP INT TERM

if ! python3 - "$port" <<'PY'
import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError as exc:
    print(f"AttesTAM address 127.0.0.1:{sys.argv[1]} is unavailable: {exc}", file=sys.stderr)
    raise SystemExit(1)
finally:
    s.close()
PY
then
	exit 2
fi

source_dir="$tmp_dir/attestam-src"
mkdir -p "$source_dir" "$tmp_dir/intel-collateral"
git -C "$ATTESTAM_ROOT" archive "$ATTESTAM_REV" | tar -x -C "$source_dir"

echo "AttesTAM revision: $ATTESTAM_REV"
(cd "$source_dir" && go test ./internal/tam ./internal/server)
(cd "$source_dir" && go build -buildvcs=false -o "$tmp_dir/attestam" ./cmd/attestam)

"$tmp_dir/attestam" \
	-addr "$ATTESTAM_CONFORMANCE_ADDR" \
	-db-path "$tmp_dir/tam_state.db" \
	-intel-collateral-cache-dir "$tmp_dir/intel-collateral" \
	-challenge-server "$VERAISON_CHALLENGE_URL" \
	-insecure-demo-mode \
	>"$attestam_log" 2>&1 &
attestam_pid=$!

ready_url="http://$ATTESTAM_CONFORMANCE_ADDR/SUITManifestService/ListManifests"
ready=false
attempt=0
while [ "$attempt" -lt 100 ]; do
	if ! kill -0 "$attestam_pid" 2>/dev/null; then
		echo "AttesTAM exited before becoming ready at $ready_url" >&2
		exit 1
	fi
	if curl -fsS --max-time 1 -H 'Accept: application/cbor' "$ready_url" >/dev/null 2>&1; then
		ready=true
		break
	fi
	attempt=$((attempt + 1))
	sleep 0.2
done
if [ "$ready" != true ]; then
	echo "AttesTAM did not become ready at $ready_url" >&2
	exit 1
fi

ATTESTAM_URL="http://$ATTESTAM_CONFORMANCE_ADDR/tam" \
ATTESTAM_REGISTER_URL="http://$ATTESTAM_CONFORMANCE_ADDR/SUITManifestService/RegisterManifest" \
VERAISON_PROVISION_URL="$VERAISON_PROVISION_URL" \
WAMR_DIR="$WAMR_DIR" \
	make -C "$repo_root" e2e-attestam-live

echo "AttesTAM v26 Generic EAT conformance checkpoint passed"
