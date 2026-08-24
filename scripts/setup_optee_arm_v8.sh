#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
set -eu

OPTEE_ROOT=${OPTEE_ROOT:-${HOME}/opt/optee}
OPTEE_GO_ROOT=${OPTEE_GO_ROOT:-${HOME}/opt/go-optee}
OPTEE_VERSION=${OPTEE_VERSION:-4.8.0}
WAMR_ROOT_DIR=${WAMR_ROOT_DIR:-${HOME}/opt/wasm-micro-runtime}
WAMR_COMMIT=${WAMR_COMMIT:-25bd7eb63e828e4bd242cc9b38d260b4b31c6605}
DEFAULT_BUILD_JOBS=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
if [ "${DEFAULT_BUILD_JOBS}" -gt 4 ]; then
	DEFAULT_BUILD_JOBS=4
fi
BUILD_JOBS=${BUILD_JOBS:-${DEFAULT_BUILD_JOBS}}
INSTALL_DEPS=0

usage()
{
	echo "usage: $0 [--install-deps]" >&2
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--install-deps) INSTALL_DEPS=1 ;;
		-h|--help) usage; exit 0 ;;
		*) usage; exit 2 ;;
	esac
	shift
done

if [ "${INSTALL_DEPS}" = "1" ]; then
	sudo apt-get update
	sudo apt-get install -y \
		acpica-tools autoconf automake bc bison build-essential ccache \
		cmake cscope curl device-tree-compiler e2tools expect flex ftp-upload \
		gdisk git golang-go gperf libattr1-dev libcap-ng-dev libfdt-dev libftdi1-dev \
		libglib2.0-dev libgmp3-dev libhidapi-dev libmpc-dev libmpfr-dev \
		libncurses5-dev libpixman-1-dev libssl-dev libtool make mtools \
		ninja-build python3-cryptography python3-kerberos python3-pip python3-pexpect \
		python3-pyelftools python3-serial python3-tomli repo rsync swig \
		unzip uuid-dev wget xdg-utils xterm xz-utils zlib1g-dev
fi

for command in git go make repo python3; do
	command -v "${command}" >/dev/null 2>&1 || {
		echo "missing prerequisite: ${command}" >&2
		exit 1
	}
done
python3 -c 'import pexpect' >/dev/null 2>&1 || {
	echo "missing prerequisite: python3-pexpect" >&2
	exit 1
}

HOST_GO_ROOT=$(go env GOROOT)
if [ -L "${OPTEE_GO_ROOT}" ]; then
	[ "$(readlink -f "${OPTEE_GO_ROOT}")" = "$(readlink -f "${HOST_GO_ROOT}")" ] || {
		echo "${OPTEE_GO_ROOT} points to a different Go installation" >&2
		exit 1
	}
elif [ -e "${OPTEE_GO_ROOT}" ]; then
	echo "${OPTEE_GO_ROOT} exists and is not a symbolic link" >&2
	exit 1
else
	mkdir -p "$(dirname "${OPTEE_GO_ROOT}")"
	ln -s "${HOST_GO_ROOT}" "${OPTEE_GO_ROOT}"
fi

mkdir -p "${OPTEE_ROOT}"
(
	cd "${OPTEE_ROOT}"
	repo init -u https://github.com/OP-TEE/manifest.git \
		-m qemu_v8.xml -b "${OPTEE_VERSION}"
	repo sync -j"${BUILD_JOBS}" --no-clone-bundle --current-branch
	repo manifest -r -o pinned-manifest.xml
)

make -C "${OPTEE_ROOT}/build" -j"${BUILD_JOBS}" toolchains
env \
	CARGO_HOME="${OPTEE_ROOT}/toolchains/rust/.cargo" \
	RUSTUP_HOME="${OPTEE_ROOT}/toolchains/rust/.rustup" \
	"${OPTEE_ROOT}/toolchains/rust/.cargo/bin/rustup" \
	target add wasm32-unknown-unknown
make -C "${OPTEE_ROOT}/build" -j"${BUILD_JOBS}" \
	QEMU_VIRTFS_AUTOMOUNT=y

if [ ! -d "${WAMR_ROOT_DIR}/.git" ]; then
	mkdir -p "$(dirname "${WAMR_ROOT_DIR}")"
	git clone https://github.com/wasm-micro-runtime/wasm-micro-runtime.git \
		"${WAMR_ROOT_DIR}"
fi
[ -z "$(git -C "${WAMR_ROOT_DIR}" status --porcelain)" ] || {
	echo "refusing to replace a WAMR checkout with local changes: ${WAMR_ROOT_DIR}" >&2
	exit 1
}
git -C "${WAMR_ROOT_DIR}" fetch --tags origin
git -C "${WAMR_ROOT_DIR}" checkout --detach "${WAMR_COMMIT}"

echo "OP-TEE ARM QEMU v8 environment is ready at ${OPTEE_ROOT}"
echo "WAMR is pinned at ${WAMR_ROOT_DIR} (${WAMR_COMMIT})"
echo "Go cross-build root is available at ${OPTEE_GO_ROOT}"
