# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
# SPDX-License-Identifier: BSD-2-Clause

SGX_BACKEND_TEST_BUILD_DIR ?= build/twep-wr-sgx-backend-tests
SGX_BACKEND_HOOKS_BUILD_DIR ?= build/twep-wr-sgx-backend-test-hooks
SGX_BACKEND_TEST_FIXTURE_DIR := build/sgx-backend-test-fixtures
SGX_TEST_HOOK_ARTIFACT_DIR ?= build/sgx-test-hook-artifacts
SGX_HW_TWEP_WR_BUILD_DIR ?= build/twep-wr-sgx-hw
SGX_HW_DEBUG ?= ON
SGX_HW_SIGNED_ENCLAVE ?=
SGX_BACKEND_TEST_FIXTURES := $(SGX_BACKEND_TEST_FIXTURE_DIR)/env-import.wasm \
	$(SGX_BACKEND_TEST_FIXTURE_DIR)/teep-env-import.wasm \
	$(SGX_BACKEND_TEST_FIXTURE_DIR)/nonzero-status.wasm \
	$(SGX_BACKEND_TEST_FIXTURE_DIR)/trap.wasm \
	$(SGX_BACKEND_TEST_FIXTURE_DIR)/oversized-output.wasm \
	$(SGX_BACKEND_TEST_FIXTURE_DIR)/infinite-loop.wasm \
	$(SGX_BACKEND_TEST_FIXTURE_DIR)/helloworld-agent-role.wasm \
	$(SGX_BACKEND_TEST_FIXTURE_DIR)/teep-agent-app-role.wasm

.PHONY: build-sgx-backend-tests test-sgx-backend build-sgx-backend-test-hooks
.PHONY: test-sgx-backend-hooks build-sgx-heap-diagnostics
.PHONY: check-sgx-test-hook-boundary build-sgx-hw clean-sgx
.PHONY: smoke-sgx-hw-dcap-evidence smoke-sgx-hw-attestam-auth
.PHONY: smoke-sgx-hw-attestam-catalog smoke-sgx-hw-attestam-app
.PHONY: smoke-sgx-hw-attestam-apps-restart smoke-sgx-hw-attestam-cli-apps-restart

build-sgx-backend-tests: build/teep-agent.wasm build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm build/catalog.dev.cbor $(SGX_BACKEND_TEST_FIXTURES)
	$(CMAKE) -S lib/twep-wr -B $(SGX_BACKEND_TEST_BUILD_DIR) \
		-DWAMR_ROOT_DIR=$(WAMR_DIR) -DTWEP_WR_PLATFORM_BACKEND=sgx \
		-DTWEP_WR_SGX_BACKEND_TESTS=ON -DTWEP_WR_SGX_TEST_HOOKS=OFF
	$(CMAKE) --build $(SGX_BACKEND_TEST_BUILD_DIR)

test-sgx-backend: build-sgx-backend-tests
	ctest --test-dir $(SGX_BACKEND_TEST_BUILD_DIR) --output-on-failure
	! nm -D $(SGX_BACKEND_TEST_BUILD_DIR)/libtwep_wr.so | grep -q 'wasm_runtime_'

build-sgx-backend-test-hooks: build-sgx-heap-diagnostics build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm build/catalog.dev.cbor $(SGX_BACKEND_TEST_FIXTURES)
	$(CMAKE) -S lib/twep-wr -B $(SGX_BACKEND_HOOKS_BUILD_DIR) \
		-DWAMR_ROOT_DIR=$(WAMR_DIR) -DTWEP_WR_PLATFORM_BACKEND=sgx \
		-DTWEP_WR_SGX_BACKEND_TESTS=ON \
		-DTWEP_WR_TEST_ARTIFACT_DIR=$(abspath $(SGX_TEST_HOOK_ARTIFACT_DIR)) \
		-DTWEP_WR_SGX_TEST_HOOKS=ON
	$(CMAKE) --build $(SGX_BACKEND_HOOKS_BUILD_DIR)

test-sgx-backend-hooks: build-sgx-backend-test-hooks
	ctest --test-dir $(SGX_BACKEND_HOOKS_BUILD_DIR) --output-on-failure \
		-R '^sgx_backend_(protected_offline|dcap_evidence|transcript_commit|agent_measurement)$$'

build-sgx-heap-diagnostics: build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm build/catalog.dev.cbor $(SGX_BACKEND_TEST_FIXTURES)
	TMPDIR="$(TMPDIR)" $(CARGO) build --manifest-path wasm/teep-agent/Cargo.toml \
	  --release --target wasm32-unknown-unknown --target-dir build/cargo-teep-agent-sgx-hooks \
	  --features sgx-test-hooks
	TMPDIR="$(TMPDIR)" $(CARGO) build --manifest-path wasm/teep-agent/Cargo.toml \
	  --release --target wasm32-unknown-unknown --target-dir build/cargo-teep-agent-sgx-512k \
	  --features sgx-test-hooks,heap-512k-diagnostic
	mkdir -p $(SGX_TEST_HOOK_ARTIFACT_DIR)/sgx-backend-test-fixtures
	cp build/cargo-teep-agent-sgx-hooks/wasm32-unknown-unknown/release/twep_teep_agent.wasm $(SGX_TEST_HOOK_ARTIFACT_DIR)/teep-agent.wasm
	$(GO) run ./cmd/twep-wasm-sign -role teep-agent -in $(SGX_TEST_HOOK_ARTIFACT_DIR)/teep-agent.wasm -out $(SGX_TEST_HOOK_ARTIFACT_DIR)/teep-agent.wasm
	cp build/cargo-teep-agent-sgx-512k/wasm32-unknown-unknown/release/twep_teep_agent.wasm $(SGX_TEST_HOOK_ARTIFACT_DIR)/teep-agent-512k.wasm
	$(GO) run ./cmd/twep-wasm-sign -role teep-agent -in $(SGX_TEST_HOOK_ARTIFACT_DIR)/teep-agent-512k.wasm -out $(SGX_TEST_HOOK_ARTIFACT_DIR)/teep-agent-512k.wasm
	cp build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm build/catalog.dev.cbor $(SGX_TEST_HOOK_ARTIFACT_DIR)/
	cp $(SGX_BACKEND_TEST_FIXTURES) $(SGX_TEST_HOOK_ARTIFACT_DIR)/sgx-backend-test-fixtures/

$(SGX_BACKEND_TEST_FIXTURE_DIR):
	mkdir -p $@

$(SGX_BACKEND_TEST_FIXTURE_DIR)/env-import.wasm: $(WASM_SIGNER_DEPS) | $(SGX_BACKEND_TEST_FIXTURE_DIR)
	printf '%s' '0061736d01000000010401600000021a0103656e7612666f7262696464656e5f686f737463616c6c0000' | xxd -r -p >$@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

$(SGX_BACKEND_TEST_FIXTURE_DIR)/teep-env-import.wasm: $(WASM_SIGNER_DEPS) | $(SGX_BACKEND_TEST_FIXTURE_DIR)
	printf '%s' '0061736d010000000104016000000215010d747765705f746565705f656e76036c6f670000' | xxd -r -p >$@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

$(SGX_BACKEND_TEST_FIXTURE_DIR)/nonzero-status.wasm: $(WASM_SIGNER_DEPS) | $(SGX_BACKEND_TEST_FIXTURE_DIR)
	printf '%s' '0061736d010000000111036000017f60037f7f7f017f60027f7f000304030001020503010001074104066d656d6f7279020014747765705f6170705f6162695f76657273696f6e00000d747765705f6170705f6d61696e00010d747765705f6170705f6672656500020a0e03040041010b040041070b02000b' | xxd -r -p >$@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

$(SGX_BACKEND_TEST_FIXTURE_DIR)/trap.wasm: $(WASM_SIGNER_DEPS) | $(SGX_BACKEND_TEST_FIXTURE_DIR)
	printf '%s' '0061736d010000000111036000017f60037f7f7f017f60027f7f000304030001020503010001074104066d656d6f7279020014747765705f6170705f6162695f76657273696f6e00000d747765705f6170705f6d61696e00010d747765705f6170705f6672656500020a0d03040041010b0300000b02000b' | xxd -r -p >$@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

$(SGX_BACKEND_TEST_FIXTURE_DIR)/oversized-output.wasm: $(WASM_SIGNER_DEPS) | $(SGX_BACKEND_TEST_FIXTURE_DIR)
	printf '%s' '0061736d010000000111036000017f60037f7f7f017f60027f7f000304030001020503010001074104066d656d6f7279020014747765705f6170705f6162695f76657273696f6e00000d747765705f6170705f6d61696e00010d747765705f6170705f6672656500020a2103040041010b170020024110360200200241046a41a09c0136020041000b02000b' | xxd -r -p >$@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

$(SGX_BACKEND_TEST_FIXTURE_DIR)/infinite-loop.wasm: $(WASM_SIGNER_DEPS) | $(SGX_BACKEND_TEST_FIXTURE_DIR)
	printf '%s' '0061736d010000000111036000017f60037f7f7f017f60027f7f000304030001020503010001074104066d656d6f7279020014747765705f6170705f6162695f76657273696f6e00000d747765705f6170705f6d61696e00010d747765705f6170705f6672656500020a1303040041010b090003400c000b41000b02000b' | xxd -r -p >$@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

$(SGX_BACKEND_TEST_FIXTURE_DIR)/helloworld-agent-role.wasm: build/helloworld.wasm $(WASM_SIGNER_DEPS) | $(SGX_BACKEND_TEST_FIXTURE_DIR)
	cp build/helloworld.wasm $@
	$(GO) run ./cmd/twep-wasm-sign -role teep-agent -in $@ -out $@

$(SGX_BACKEND_TEST_FIXTURE_DIR)/teep-agent-app-role.wasm: build/teep-agent.wasm $(WASM_SIGNER_DEPS) | $(SGX_BACKEND_TEST_FIXTURE_DIR)
	cp build/teep-agent.wasm $@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

check-sgx-test-hook-boundary: build-sgx-hw
	! $(CMAKE) -S lib/twep-wr -B "$(TMPDIR)/twep-sgx-hw-hooks-rejected" \
		-DTWEP_WR_PLATFORM_BACKEND=sgx -DTWEP_WR_SGX_TEST_HOOKS=ON
	! grep -q 'ecall_test_' lib/twep-wr/src/platform/sgx/enclave/twep_wr_sgx.edl
	! nm -D $(SGX_HW_TWEP_WR_BUILD_DIR)/libtwep_wr.so | grep -q 'ecall_test_'

build-sgx-hw: build/teep-agent.wasm build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm build/catalog.dev.cbor
	$(CMAKE) -S lib/twep-wr -B $(SGX_HW_TWEP_WR_BUILD_DIR) \
		-DWAMR_ROOT_DIR=$(WAMR_DIR) -DTWEP_WR_PLATFORM_BACKEND=sgx \
		-DTWEP_WR_SGX_BACKEND_TESTS=OFF -DTWEP_WR_SGX_TEST_HOOKS=OFF \
		-DTWEP_WR_SGX_HW_DEBUG=$(SGX_HW_DEBUG) \
		-DTWEP_WR_SGX_SIGNED_ENCLAVE=$(SGX_HW_SIGNED_ENCLAVE)
	$(CMAKE) --build $(SGX_HW_TWEP_WR_BUILD_DIR)

smoke-sgx-hw-dcap-evidence: build-sgx-hw
	@test -e /dev/sgx_enclave -a -e /dev/sgx_provision
	TMPDIR="$(TMPDIR)" SGX_HW_BUILD_DIR="$(SGX_HW_TWEP_WR_BUILD_DIR)" ATTESTAM_URL="$(ATTESTAM_URL)" ./scripts/run_sgx_hw_smoke.sh evidence

smoke-sgx-hw-attestam-auth: build-sgx-hw
	@test -e /dev/sgx_enclave -a -e /dev/sgx_provision
	TMPDIR="$(TMPDIR)" SGX_HW_BUILD_DIR="$(SGX_HW_TWEP_WR_BUILD_DIR)" ATTESTAM_URL="$(ATTESTAM_URL)" ./scripts/run_sgx_hw_smoke.sh auth

smoke-sgx-hw-attestam-catalog: build-sgx-hw
	@test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-sgx-hw-attestam-catalog ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest"; exit 2; }
	@test -e /dev/sgx_enclave -a -e /dev/sgx_provision
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --out build/attestam/catalog-default.envelope.cbor --sequence 1 --register-url "$(ATTESTAM_REGISTER_URL)"
	TMPDIR="$(TMPDIR)" SGX_HW_BUILD_DIR="$(SGX_HW_TWEP_WR_BUILD_DIR)" ATTESTAM_URL="$(ATTESTAM_URL)" ./scripts/run_sgx_hw_smoke.sh catalog

smoke-sgx-hw-attestam-app: build-sgx-hw
	@test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-sgx-hw-attestam-app ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest"; exit 2; }
	@test -e /dev/sgx_enclave -a -e /dev/sgx_provision
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --catalog-payload build/catalog.dev.cbor --out build/attestam/catalog-apps.envelope.cbor --sequence 1 --register-url "$(ATTESTAM_REGISTER_URL)"
	$(GO) run ./cmd/twep-attestam-fixture-gen --command helloworld --wasm build/helloworld.wasm --wasm-file helloworld.wasm --out build/attestam/helloworld.envelope.cbor --sequence 1 --register-url "$(ATTESTAM_REGISTER_URL)"
	TMPDIR="$(TMPDIR)" SGX_HW_BUILD_DIR="$(SGX_HW_TWEP_WR_BUILD_DIR)" ATTESTAM_URL="$(ATTESTAM_URL)" ./scripts/run_sgx_hw_smoke.sh app

smoke-sgx-hw-attestam-apps-restart: build-sgx-hw
	@test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-sgx-hw-attestam-apps-restart ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest"; exit 2; }
	@test -e /dev/sgx_enclave -a -e /dev/sgx_provision
	./scripts/register_attestam_demo_apps.sh "$(ATTESTAM_REGISTER_URL)"
	TMPDIR="$(TMPDIR)" SGX_HW_BUILD_DIR="$(SGX_HW_TWEP_WR_BUILD_DIR)" ATTESTAM_URL="$(ATTESTAM_URL)" ./scripts/run_sgx_hw_smoke.sh apps-restart

smoke-sgx-hw-attestam-cli-apps-restart: build bin/twep-cli build-sgx-hw
	@test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-sgx-hw-attestam-cli-apps-restart ATTESTAM_REGISTER_URL=http://127.0.0.1:8080/SUITManifestService/RegisterManifest"; exit 2; }
	@test -e /dev/sgx_enclave -a -e /dev/sgx_provision
	./scripts/register_attestam_demo_apps.sh "$(ATTESTAM_REGISTER_URL)"
	TMPDIR="$(TMPDIR)" SGX_HW_BUILD_DIR="$(SGX_HW_TWEP_WR_BUILD_DIR)" ATTESTAM_URL="$(ATTESTAM_URL)" ./scripts/run_sgx_hw_cli_apps_restart.sh

clean-sgx:
	rm -rf $(SGX_BACKEND_TEST_BUILD_DIR) $(SGX_BACKEND_HOOKS_BUILD_DIR) \
		$(SGX_BACKEND_TEST_FIXTURE_DIR) $(SGX_TEST_HOOK_ARTIFACT_DIR) \
		$(SGX_HW_TWEP_WR_BUILD_DIR) \
		build/cargo-teep-agent-sgx-hooks build/cargo-teep-agent-sgx-512k
