#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
set -eu

OPTEE_ROOT=${OPTEE_ROOT:-${HOME}/opt/optee}
OPTEE_GO_ROOT=${OPTEE_GO_ROOT:-${HOME}/opt/go-optee}
WAMR_ROOT_DIR=${WAMR_ROOT_DIR:-${HOME}/opt/wasm-micro-runtime}
WAMR_COMMIT=${WAMR_COMMIT:-25bd7eb63e828e4bd242cc9b38d260b4b31c6605}
OPTEE_CONF=${OPTEE_ROOT}/optee_os/out/arm/export-ta_arm64/host_include/conf.mk

require_file()
{
	[ -f "$1" ] || {
		echo "missing ARM OP-TEE environment artifact: $1" >&2
		exit 1
	}
}

require_executable()
{
	[ -x "$1" ] || {
		echo "missing ARM OP-TEE executable: $1" >&2
		exit 1
	}
}

if [ -x "${OPTEE_ROOT}/toolchains/aarch64/bin/aarch64-linux-gcc" ]; then
	AARCH64_CC=${OPTEE_ROOT}/toolchains/aarch64/bin/aarch64-linux-gcc
else
	AARCH64_CC=${OPTEE_ROOT}/toolchains/aarch64/bin/aarch64-linux-gnu-gcc
fi
if [ -x "${OPTEE_ROOT}/out-br/host/bin/aarch64-linux-gcc" ]; then
	BUILDROOT_CC=${OPTEE_ROOT}/out-br/host/bin/aarch64-linux-gcc
else
	BUILDROOT_CC=${OPTEE_ROOT}/out-br/host/bin/aarch64-buildroot-linux-gnu-gcc
fi
if [ -x "${OPTEE_ROOT}/qemu/build/qemu-system-aarch64" ]; then
	QEMU=${OPTEE_ROOT}/qemu/build/qemu-system-aarch64
else
	QEMU=${OPTEE_ROOT}/qemu/build/aarch64-softmmu/qemu-system-aarch64
fi

require_executable "${AARCH64_CC}"
require_executable "${OPTEE_ROOT}/toolchains/aarch32/bin/arm-linux-gnueabihf-gcc"
require_executable "${BUILDROOT_CC}"
require_executable "${QEMU}"
require_file "${OPTEE_ROOT}/out-br/host/share/buildroot/toolchainfile.cmake"
require_file "${OPTEE_ROOT}/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr/include/tee_client_api.h"
require_file "${OPTEE_ROOT}/optee_os/out/arm/export-ta_arm64/mk/ta_dev_kit.mk"
require_file "${OPTEE_CONF}"
require_file "${OPTEE_ROOT}/out-br/images/rootfs.cpio.gz"
require_file "${OPTEE_ROOT}/out/bin/bl1.bin"
[ -d "${OPTEE_GO_ROOT}/src/runtime/cgo" ] || {
	echo "missing safe Go cross-build root: ${OPTEE_GO_ROOT}" >&2
	exit 1
}

grep -Eq '^CFG_REE_FS=y$' "${OPTEE_CONF}" || {
	echo "OP-TEE was not built with CFG_REE_FS=y" >&2
	exit 1
}
grep -Eq '^CFG_RPMB_FS=n$' "${OPTEE_CONF}" || {
	echo "OP-TEE was not built with CFG_RPMB_FS=n" >&2
	exit 1
}

[ -d "${WAMR_ROOT_DIR}/.git" ] || {
	echo "missing WAMR checkout: ${WAMR_ROOT_DIR}" >&2
	exit 1
}
[ "$(git -C "${WAMR_ROOT_DIR}" rev-parse HEAD)" = "${WAMR_COMMIT}" ] || {
	echo "unexpected WAMR revision in ${WAMR_ROOT_DIR}" >&2
	exit 1
}

env \
	CARGO_HOME="${OPTEE_ROOT}/toolchains/rust/.cargo" \
	RUSTUP_HOME="${OPTEE_ROOT}/toolchains/rust/.rustup" \
	"${OPTEE_ROOT}/toolchains/rust/.cargo/bin/rustup" \
	target list --installed | grep -qx wasm32-unknown-unknown || {
	echo "Rust wasm32-unknown-unknown target is not installed" >&2
	exit 1
}
python3 -c 'import pexpect'

"${AARCH64_CC}" --version | sed -n '1p'
"${BUILDROOT_CC}" --version | sed -n '1p'
"${QEMU}" --version | sed -n '1p'
echo "ARM_OPTEE_V8_ENV_OK"
