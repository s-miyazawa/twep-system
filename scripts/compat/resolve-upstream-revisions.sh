#!/bin/sh
# Read-only compatibility helper. Network access is required for remote HEADs.
set -eu

TWEP_URL=${TWEP_URL:-https://github.com/s-miyazawa/twep-system.git}
ATTESTAM_URL=${ATTESTAM_URL:-https://github.com/kentakayama/AttesTAM.git}
TAWS_URL=${TAWS_URL:-https://github.com/yuma-nishi/taws.git}
: "${WAMR_DIR:?set WAMR_DIR to the clean WAMR checkout used to build TWEP}"

resolve_head() {
	git ls-remote "$1" HEAD | awk 'NR == 1 { print $1 }'
}

TWEP_SYSTEM_REV=$(resolve_head "$TWEP_URL")
ATTESTAM_REV=$(resolve_head "$ATTESTAM_URL")
TAWS_REV=$(resolve_head "$TAWS_URL")
TWEP_WAMR_REV=$(git -C "$WAMR_DIR" rev-parse HEAD)
TWEP_WAMR_DIRTY=false
test -z "$(git -C "$WAMR_DIR" status --porcelain)" || TWEP_WAMR_DIRTY=true
compat_tmp=$(mktemp -d)
trap 'rm -rf "$compat_tmp"' EXIT HUP INT TERM
git -C "$compat_tmp" init -q
git -C "$compat_tmp" fetch -q --depth=1 "$TAWS_URL" "$TAWS_REV"
TAWS_WAMR_REV=$(git -C "$compat_tmp" ls-tree FETCH_HEAD third_party/wasm-micro-runtime | awk 'NR == 1 { print $3 }')

test -n "$TWEP_SYSTEM_REV" && test -n "$ATTESTAM_REV" && test -n "$TAWS_REV"
test -n "$TAWS_WAMR_REV" && test -n "$TWEP_WAMR_REV"
printf '%s\n' \
	"TWEP_SYSTEM_REV=$TWEP_SYSTEM_REV" \
	"ATTESTAM_REV=$ATTESTAM_REV" \
	"TAWS_REV=$TAWS_REV" \
	"TAWS_WAMR_REV=$TAWS_WAMR_REV" \
	"TWEP_WAMR_REV=$TWEP_WAMR_REV" \
	"TWEP_WAMR_DIRTY=$TWEP_WAMR_DIRTY"
