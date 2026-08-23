#!/usr/bin/env bash
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause
set -Eeuo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RISCV_OPTEE_ROOT="${RISCV_OPTEE_ROOT:-$(cd "$REPO_ROOT/../riscv-optee" && pwd)}"
BUILDROOT="${RISCV_OPTEE_BUILDROOT:-$RISCV_OPTEE_ROOT/buildroot}"
WAMR_DIR="${RISCV_OPTEE_WAMR_DIR:-$RISCV_OPTEE_ROOT/workspace/wasm-micro-runtime}"
OUT_DIR="${RISCV_OPTEE_OUT:-$REPO_ROOT/build/riscv-optee-v9}"
EXPECTED_BUILDROOT_REV="${RISCV_OPTEE_BUILDROOT_REV:-b5e20ca925d0784473c854fae92c3fc5931802ee}"
EXPECTED_WAMR_REV="${RISCV_OPTEE_WAMR_REV:-25bd7eb63e828e4bd242cc9b38d260b4b31c6605}"
JOBS="${JOBS:-6}"

BUILDROOT="$(realpath "$BUILDROOT")"
WAMR_DIR="$(realpath "$WAMR_DIR")"
mkdir -p -- "$OUT_DIR"
OUT_DIR="$(realpath "$OUT_DIR")"

case "$OUT_DIR" in
	/|"$REPO_ROOT"|"$RISCV_OPTEE_ROOT")
		echo "refusing unsafe output directory: $OUT_DIR" >&2
		exit 2
		;;
esac

HOST_DIR="$BUILDROOT/output/host"
HOST_CROSS="$HOST_DIR/bin/riscv64-buildroot-linux-gnu-"
HOST_CC="${HOST_CROSS}gcc"
TOOLCHAIN_FILE="$HOST_DIR/share/buildroot/toolchainfile.cmake"
TEEC_EXPORT="$BUILDROOT/output/staging/usr"
TA_DEV_KIT="$HOST_DIR/riscv64-buildroot-linux-gnu/sysroot/lib/optee/export-ta_rv64"
CMAKE="$HOST_DIR/bin/cmake"
TA_OUT="$OUT_DIR/ta"
WAMR_OUT="$OUT_DIR/wamr-ta"
GUEST_DIR="$OUT_DIR/guest"
OVERLAY="$OUT_DIR/rootfs-overlay"
TWEP_LIB_BUILD="$REPO_ROOT/build/riscv64"
TA_UUID="6b9f4d2a-2f3e-4c7b-9d21-5a6f0e3c8b10"

[[ -d "$BUILDROOT/.git" ]] || { echo "missing Buildroot checkout: $BUILDROOT" >&2; exit 2; }
[[ -d "$WAMR_DIR/.git" ]] || { echo "missing WAMR checkout: $WAMR_DIR" >&2; exit 2; }
[[ "$(git -C "$BUILDROOT" rev-parse HEAD)" == "$EXPECTED_BUILDROOT_REV" ]] || {
	echo "riscv-optee v9 Buildroot revision mismatch" >&2
	exit 2
}
[[ "$(git -C "$WAMR_DIR" rev-parse HEAD)" == "$EXPECTED_WAMR_REV" ]] || {
	echo "WAMR revision mismatch" >&2
	exit 2
}
[[ -z "$(git -C "$BUILDROOT" status --short)" ]] || {
	echo "Buildroot source tree has local modifications" >&2
	exit 2
}
[[ -z "$(git -C "$WAMR_DIR" status --short)" ]] || {
	echo "WAMR source tree has local modifications" >&2
	exit 2
}
[[ -x "$HOST_CC" && -x "$CMAKE" && -f "$TOOLCHAIN_FILE" ]] || {
	echo "Buildroot cross SDK is incomplete; build riscv-optee v9 first" >&2
	exit 2
}
[[ -f "$TEEC_EXPORT/include/tee_client_api.h" ]] || { echo "libteec SDK is missing" >&2; exit 2; }
[[ -f "$TA_DEV_KIT/mk/ta_dev_kit.mk" ]] || { echo "RV64 TA dev kit is missing" >&2; exit 2; }
command -v cargo >/dev/null 2>&1 || {
	echo "cargo is missing; install Rust with the wasm32-unknown-unknown target" >&2
	exit 2
}
command -v go >/dev/null 2>&1 || {
	echo "go is missing; install Go 1.22 or newer" >&2
	exit 2
}
command -v wat2wasm >/dev/null 2>&1 || {
	echo "wat2wasm is missing; install WABT" >&2
	exit 2
}

echo "[1/5] enabling target crypto dependencies"
(
	cd "$BUILDROOT"
	CONFIG_=BR2_ support/kconfig/merge_config.sh -m .config \
		"$REPO_ROOT/scripts/riscv_optee_v9_buildroot.fragment"
	make olddefconfig
	make -j"$JOBS" libopenssl ca-certificates
)

echo "[2/5] building RISC-V public ABI library and guest tools"
TARGET_GOARCH=riscv64 \
TEEC_EXPORT="$TEEC_EXPORT" \
TEEC_LIB_DIR="$TEEC_EXPORT/lib" \
HOST_CC="$HOST_CC" \
WAMR_ROOT_DIR="$WAMR_DIR" \
CMAKE="$CMAKE" \
CMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE" \
CMAKE_FRESH=1 \
TWEP_TRUSTZONE_BUILD_DIR="$TWEP_LIB_BUILD" \
TWEP_GUEST_DIR="$GUEST_DIR" \
	"$REPO_ROOT/optee/twep-wr-ta/prepare-diagnose-smoke.sh"

echo "[3/5] building the RV64 WAMR-enabled TA and host diagnostic"
mkdir -p -- "$TA_OUT" "$WAMR_OUT"
make -C "$REPO_ROOT/optee/twep-wr-ta" clean \
	OPTEE_CLIENT_EXPORT="$TEEC_EXPORT" \
	HOST_CROSS_COMPILE="$HOST_CROSS" \
	TA_CROSS_COMPILE="$HOST_CROSS" \
	TA_DEV_KIT_DIR="$TA_DEV_KIT" \
	TA_OUT_DIR="$TA_OUT"
make -C "$REPO_ROOT/optee/twep-wr-ta" -j"$JOBS" \
	CMAKE="$CMAKE" \
	OPTEE_CLIENT_EXPORT="$TEEC_EXPORT" \
	HOST_CROSS_COMPILE="$HOST_CROSS" \
	TA_CROSS_COMPILE="$HOST_CROSS" \
	TA_DEV_KIT_DIR="$TA_DEV_KIT" \
	TA_OUT_DIR="$TA_OUT" \
	WAMR_ROOT_DIR="$WAMR_DIR" \
	WAMR_TA_BUILD_DIR="$WAMR_OUT" \
	WAMR_SPIKE_IWASM_LIB_DIR="$WAMR_OUT" \
	TWEP_TA_WAMR_LINK=1 \
	TWEP_TA_WAMR_TARGET=RISCV64_LP64D

echo "[4/5] staging the root filesystem overlay"
rm -rf -- "$OVERLAY"
mkdir -p -- "$OVERLAY/usr/bin" "$OVERLAY/usr/lib" \
	"$OVERLAY/lib/optee_armtz" "$OVERLAY/opt/twep/guest"
install -m 0755 "$REPO_ROOT/optee/twep-wr-ta/host/optee_example_twep_wr_ta" \
	"$OVERLAY/usr/bin/optee_example_twep_wr_ta"
install -m 0755 "$GUEST_DIR/bin/twepd" "$OVERLAY/usr/bin/twepd"
install -m 0755 "$GUEST_DIR/bin/twep-cli" "$OVERLAY/usr/bin/twep-cli"
install -m 0755 "$GUEST_DIR/bin/twep_wr_public_abi_smoke" \
	"$OVERLAY/usr/bin/twep_wr_public_abi_smoke"
install -m 0755 "$TWEP_LIB_BUILD/libtwep_wr.so" "$OVERLAY/usr/lib/libtwep_wr.so"
install -m 0444 "$TA_OUT/$TA_UUID.ta" "$OVERLAY/lib/optee_armtz/$TA_UUID.ta"
cp -a -- "$GUEST_DIR/." "$OVERLAY/opt/twep/guest/"
for helper in run_trustzone_smokes.sh diagnose_verified_trustzone.sh \
	provision_and_diagnose_trustzone.sh protected_storage_failure_smoke.sh; do
	install -m 0755 "$REPO_ROOT/optee/twep-wr-ta/$helper" "$OVERLAY/opt/twep/$helper"
done

file "$OVERLAY/usr/bin/optee_example_twep_wr_ta" \
	"$OVERLAY/usr/bin/twepd" "$OVERLAY/usr/lib/libtwep_wr.so" | tee "$OUT_DIR/file.txt"
grep -q 'RISC-V' "$OUT_DIR/file.txt"

echo "[5/5] rebuilding the riscv-optee v9 root filesystem"
BASE_OVERLAY="board/qemu/riscv64-virt-optee/rootfs_overlay"
make -C "$BUILDROOT" -j"$JOBS" \
	BR2_ROOTFS_OVERLAY="$BASE_OVERLAY $OVERLAY"

sha256sum \
	"$OVERLAY/usr/bin/optee_example_twep_wr_ta" \
	"$OVERLAY/usr/bin/twepd" \
	"$OVERLAY/usr/bin/twep-cli" \
	"$OVERLAY/usr/lib/libtwep_wr.so" \
	"$OVERLAY/lib/optee_armtz/$TA_UUID.ta" \
	"$BUILDROOT/output/images/sdcard.img" >"$OUT_DIR/SHA256SUMS"

echo "TWEP RISC-V OP-TEE v9 image is ready: $BUILDROOT/output/images/sdcard.img"
