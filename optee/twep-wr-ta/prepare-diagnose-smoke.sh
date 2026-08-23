#!/bin/sh
# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "${PROJECT_DIR}/../.." && pwd)
TEEP_AGENT_WASM=${TWEP_TEEP_AGENT_WASM:-${REPO_ROOT}/build/teep-agent.wasm}
GUEST_DIR=${TWEP_GUEST_DIR:-${PROJECT_DIR}/guest}
TRUSTZONE_BUILD_DIR=${TWEP_TRUSTZONE_BUILD_DIR:-${REPO_ROOT}/build/twep-wr-trustzone}
TARGET_GOARCH=${TARGET_GOARCH:-arm64}
TEEC_EXPORT=${TEEC_EXPORT:-${HOME}/opt/optee/out-br/host/aarch64-buildroot-linux-gnu/sysroot/usr}
TEEC_LIB_DIR=${TEEC_LIB_DIR:-${HOME}/opt/optee/out-br/build/optee_client_ext-1.0/libteec}
HOST_CC=${HOST_CC:-${HOME}/opt/optee/out-br/host/bin/aarch64-buildroot-linux-gnu-gcc}
WAMR_ROOT_DIR=${WAMR_ROOT_DIR:-${HOME}/opt/wasm-micro-runtime}
CMAKE=${CMAKE:-cmake}
CMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE:-}
CMAKE_FRESH=${CMAKE_FRESH:-0}

make -C "${REPO_ROOT}" build/teep-agent.wasm build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm build/catalog.dev.json build/catalog.dev.cbor
set -- "${CMAKE}" -S "${REPO_ROOT}/lib/twep-wr" -B "${TRUSTZONE_BUILD_DIR}" \
	-DWAMR_ROOT_DIR="${WAMR_ROOT_DIR}" \
	-DTWEP_WR_PLATFORM_BACKEND=trustzone \
	-DTWEP_WR_TEEC_EXPORT="${TEEC_EXPORT}" \
	-DTWEP_WR_TEEC_LIB_DIR="${TEEC_LIB_DIR}"
if [ "${CMAKE_FRESH}" = "1" ]; then
	set -- "$@" --fresh
fi
if [ -n "${CMAKE_TOOLCHAIN_FILE}" ]; then
	set -- "$@" -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}"
fi
"$@"
"${CMAKE}" --build "${TRUSTZONE_BUILD_DIR}"

rm -rf "${GUEST_DIR}"
mkdir -p "${GUEST_DIR}/bin" "${GUEST_DIR}/build"
mkdir -p "${GUEST_DIR}/fixtures"
GOOS=linux GOARCH="${TARGET_GOARCH}" CGO_ENABLED=1 CC="${HOST_CC}" \
	CGO_CFLAGS="-I${REPO_ROOT}/lib/twep-wr/include" \
	CGO_LDFLAGS="-L${TRUSTZONE_BUILD_DIR} -ltwep_wr -Wl,-rpath,/usr/lib -L${TEEC_LIB_DIR} -lteec" \
	go build -o "${GUEST_DIR}/bin/twepd" "${REPO_ROOT}/cmd/twepd"
GOOS=linux GOARCH="${TARGET_GOARCH}" CGO_ENABLED=0 \
	go build -o "${GUEST_DIR}/bin/twep-cli" "${REPO_ROOT}/cmd/twep-cli"
"${HOST_CC}" -Wall -Wextra -Werror \
	-I"${REPO_ROOT}/lib/twep-wr/include" \
	-I"${PROJECT_DIR}/ta/include" \
	-I"${TEEC_EXPORT}/include" \
	-o "${GUEST_DIR}/bin/twep_wr_public_abi_smoke" \
	"${PROJECT_DIR}/host/public_abi_smoke.c" \
	-L"${TRUSTZONE_BUILD_DIR}" -ltwep_wr \
	-L"${TEEC_LIB_DIR}" -lteec \
	-Wl,-rpath,/usr/lib -Wl,--allow-shlib-undefined
cp "${TEEP_AGENT_WASM}" "${GUEST_DIR}/build/teep-agent.wasm"
cp "${REPO_ROOT}/build/helloworld.wasm" "${GUEST_DIR}/build/helloworld.wasm"
cp "${REPO_ROOT}/build/calcadd.wasm" "${GUEST_DIR}/build/calcadd.wasm"
cp "${REPO_ROOT}/build/negaposi.wasm" "${GUEST_DIR}/build/negaposi.wasm"
cp "${REPO_ROOT}/build/catalog.dev.json" "${GUEST_DIR}/build/catalog.dev.json"
cp "${REPO_ROOT}/build/catalog.dev.cbor" "${GUEST_DIR}/build/catalog.dev.cbor"
cp "${REPO_ROOT}/testdata/images/input.jpg" "${GUEST_DIR}/fixtures/input.jpg"
cp "${REPO_ROOT}/testdata/abi/vectors.hex" "${GUEST_DIR}/fixtures/abi-vectors.hex"
cp "${TRUSTZONE_BUILD_DIR}/libtwep_wr.so" "${GUEST_DIR}/build/libtwep_wr.so"
wat2wasm "${PROJECT_DIR}/wasm/infinite-app.wat" \
	-o "${GUEST_DIR}/build/infinite-app.wasm"
printf '%s' '0061736d01000000010401600000021a0103656e7612666f7262696464656e5f686f737463616c6c0000' | xxd -r -p >"${GUEST_DIR}/build/unsupported-import.wasm"
printf '%s' '0061736d010000000104016000000215010d747765705f746565705f656e76036c6f670000' | xxd -r -p >"${GUEST_DIR}/build/teep-env-import.wasm"
printf '%s' '0061736d01000000010d0260037f7f7f017f60027f7f0003030200010503010001072a03066d656d6f727902000d747765705f6170705f6d61696e00000d747765705f6170705f6672656500010a1802130020024110360200200241810136020441000b02000b' | xxd -r -p >"${GUEST_DIR}/build/oversized-output.wasm"
printf '%s' '0061736d01000000010d0260037f7f7f017f60027f7f0003030200010503010001072a03066d656d6f727902000d747765705f6170705f6d61696e00000d747765705f6170705f6672656500010a0902040041070b02000b' | xxd -r -p >"${GUEST_DIR}/build/nonzero-status.wasm"
printf '%s' '0061736d010000000111036000017f60037f7f7f017f60027f7f000304030001020503010001072a03066d656d6f727902000d747765705f6170705f6d61696e00010d747765705f6170705f6672656500020a0e03040010000b040010000b02000b' | xxd -r -p >"${GUEST_DIR}/build/trap.wasm"
printf '%s' '0061736d010000000111036000017f60037f7f7f017f60027f7f000304030001020503010001074104066d656d6f7279020014747765705f6170705f6162695f76657273696f6e00000d747765705f6170705f6d61696e00010d747765705f6170705f6672656500020a0e03040041010b040041070b02000b' | xxd -r -p >"${GUEST_DIR}/build/production-nonzero-status.wasm"
printf '%s' '0061736d010000000111036000017f60037f7f7f017f60027f7f000304030001020503010001074104066d656d6f7279020014747765705f6170705f6162695f76657273696f6e00000d747765705f6170705f6d61696e00010d747765705f6170705f6672656500020a0d03040041010b0300000b02000b' | xxd -r -p >"${GUEST_DIR}/build/production-trap.wasm"
printf '%s' '0061736d010000000111036000017f60037f7f7f017f60027f7f000304030001020503010001074104066d656d6f7279020014747765705f6170705f6162695f76657273696f6e00000d747765705f6170705f6d61696e00010d747765705f6170705f6672656500020a2103040041010b170020024110360200200241046a41a09c0136020041000b02000b' | xxd -r -p >"${GUEST_DIR}/build/production-oversized-output.wasm"

go run "${REPO_ROOT}/cmd/twep-attestam-fixture-gen" \
	--command remotehello \
	--wasm "${REPO_ROOT}/build/helloworld.wasm" \
	--wasm-file remotehello.wasm \
	--out "${GUEST_DIR}/fixtures/verified-remotehello.envelope.cbor" \
	--sequence 8 \
	--verified-update-out "${GUEST_DIR}/fixtures/verified-input.cose" \
	--verified-token-out "${GUEST_DIR}/fixtures/verified-expected-token.bin" \
	--protected-store-out "${GUEST_DIR}/fixtures/protected-credential-store.cbor" \
	--issuer-allowlist-out "${GUEST_DIR}/fixtures/protected-issuer-allowlist.cbor" \
	--issuer-allowlist-id issuer
go run "${REPO_ROOT}/cmd/twep-attestam-fixture-gen" \
	--command remotehello \
	--wasm "${REPO_ROOT}/build/helloworld.wasm" \
	--wasm-file remotehello.wasm \
	--out "${GUEST_DIR}/fixtures/mismatched-issuer.envelope.cbor" \
	--issuer-allowlist-out "${GUEST_DIR}/fixtures/protected-issuer-allowlist-mismatch.cbor" \
	--issuer-allowlist-id other-issuer
printf '%s' 'a26e736368656d615f76657273696f6e016f6d61785f73746f72655f65706f636801' | xxd -r -p >"${GUEST_DIR}/fixtures/protected-store-freshness.cbor"
printf '%s' 'a26e736368656d615f76657273696f6e016f6d61785f73746f72655f65706f636802' | xxd -r -p >"${GUEST_DIR}/fixtures/protected-store-freshness-stale.cbor"
printf '%s' 'a26e736368656d615f76657273696f6e01717265766f6b65645f656e7472795f696473814d7265766f6b65642d656e747279' | xxd -r -p >"${GUEST_DIR}/fixtures/protected-revocation-state.cbor"
printf '%s' 'a26e736368656d615f76657273696f6e01717265766f6b65645f656e7472795f696473814974616d2d656e747279' | xxd -r -p >"${GUEST_DIR}/fixtures/protected-revocation-state-revoked.cbor"
printf '%s' 'a56e736368656d615f76657273696f6e016f76657269666965725f726573756c746961666669726d696e676b6e6f6e63655f6d61746368f56d636e665f6b65795f6d61746368f56e706c6174666f726d5f6d61746368f5' | xxd -r -p >"${GUEST_DIR}/fixtures/verified-evidence-result.cbor"
printf '%s' 'a56e736368656d615f76657273696f6e026f6465636973696f6e5f736f7572636576617474657374616d2d7369676e65642d7570646174657574616d5f726573706f6e73655f7665726966696564f578186368616c6c656e67655f726573706f6e73655f626f756e64f575616363657074616e63655f67656e65726174696f6e01' | xxd -r -p >"${GUEST_DIR}/fixtures/verified-evidence-result-stale-generation.cbor"
printf '%s' 'a56e736368656d615f76657273696f6e026f6465636973696f6e5f736f7572636576617474657374616d2d7369676e65642d7570646174657574616d5f726573706f6e73655f7665726966696564f578186368616c6c656e67655f726573706f6e73655f626f756e64f575616363657074616e63655f67656e65726174696f6e02' | xxd -r -p >"${GUEST_DIR}/fixtures/verified-evidence-result-current-generation.cbor"
printf '%s' 'a26e736368656d615f76657273696f6e016f76657269666965725f726573756c746961666669726d696e67' | xxd -r -p >"${GUEST_DIR}/fixtures/verified-evidence-result-optional-missing.cbor"
printf '%s' 'a0' | xxd -r -p >"${GUEST_DIR}/fixtures/verified-evidence-result-malformed.cbor"
printf '%s' 'a0' | xxd -r -p >"${GUEST_DIR}/fixtures/protected-credential-store-malformed.cbor"
printf '%s' 'a46a67656e65726174696f6e026e736368656d615f76657273696f6e0173636f6d706f6e656e745f73657175656e636573a078236c6173745f636f6e73756d65645f71756572795f726573706f6e73655f73686132353658200000000000000000000000000000000000000000000000000000000000000000' | xxd -r -p >"${GUEST_DIR}/fixtures/teep-acceptance-state-current-generation-2.cbor"
teep_agent_sha256=$(sha256sum "${GUEST_DIR}/build/teep-agent.wasm" | awk '{print $1}')
printf '%s%s%s' \
	'a56e736368656d615f76657273696f6e0170706c6174666f726d5f6261636b656e646974727573747a6f6e657072756e74696d655f6c6f636174696f6e6c74727573747a6f6e652d746173746565705f6167656e745f6c6f636174696f6e6c74727573747a6f6e652d7461726d6561737572656d656e745f736861323536' \
	'5820' \
	"${teep_agent_sha256}" | xxd -r -p >"${GUEST_DIR}/fixtures/protected-agent-identity.cbor"
printf '%s' 'a26e736368656d615f76657273696f6e0170706c6174666f726d5f6261636b656e646974727573747a6f6e65' | xxd -r -p >"${GUEST_DIR}/fixtures/protected-agent-identity-optional-missing.cbor"
printf '%s%s%s' \
	'a56e736368656d615f76657273696f6e0170706c6174666f726d5f6261636b656e646974727573747a6f6e657072756e74696d655f6c6f636174696f6e6c74727573747a6f6e652d746173746565705f6167656e745f6c6f636174696f6e6c74727573747a6f6e652d7461726d6561737572656d656e745f736861323536' \
	'5820' \
	'0000000000000000000000000000000000000000000000000000000000000000' | xxd -r -p >"${GUEST_DIR}/fixtures/protected-agent-identity-mismatch.cbor"

echo "prepared TrustZone diagnose smoke assets in ${GUEST_DIR}"
