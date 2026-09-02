# Copyright (c) 2026 SECOM CO., LTD. All rights reserved.
#
# SPDX-License-Identifier: BSD-2-Clause
GO ?= go
CC ?= cc
.DELETE_ON_ERROR:
WAMR_DIR ?= $(HOME)/opt/wasm-micro-runtime
TMPDIR ?= /tmp
CMAKE ?= cmake
OPTEE_ROOT ?= $(HOME)/opt/optee
export OPTEE_ROOT
OPTEE_GO_ROOT ?= $(HOME)/opt/go-optee
export OPTEE_GO_ROOT
OPTEE_RUST_HOME ?= $(OPTEE_ROOT)/toolchains/rust
ifneq ($(wildcard $(OPTEE_RUST_HOME)/.cargo/bin/cargo),)
OPTEE_RUST_ENV := env CARGO_HOME=$(OPTEE_RUST_HOME)/.cargo RUSTUP_HOME=$(OPTEE_RUST_HOME)/.rustup PATH=$(OPTEE_RUST_HOME)/.cargo/bin:$(PATH)
CARGO ?= $(OPTEE_RUST_ENV) cargo
else
OPTEE_RUST_ENV :=
CARGO ?= cargo
endif
OPTEE_POSTRUN ?= $(CURDIR)/scripts/optee_postrun.py
VERAISON_PROVISION_URL ?= https://localhost:9443/endorsement-provisioning/v1/submit
OPTEE_BUILDROOT_TOOLCHAIN ?= $(OPTEE_ROOT)/out-br/host/share/buildroot/toolchainfile.cmake
export WAMR_ROOT_DIR = $(WAMR_DIR)
ARM_OPTEE_TWEP_WR_BUILD_DIR ?= build/twep-wr-arm-optee
RISCV_OPTEE_ROOT ?= $(abspath ../riscv-optee)
RISCV_OPTEE_BUILDROOT ?= $(RISCV_OPTEE_ROOT)/buildroot
RISCV_OPTEE_WAMR_DIR ?= $(RISCV_OPTEE_ROOT)/workspace/wasm-micro-runtime
RISCV_OPTEE_OUT ?= build/riscv-optee-v9
ATTESTAM_URL ?= http://127.0.0.1:8080/tam
ATTESTAM_ROOT ?=
WASM_SIGNER_DEPS := cmd/twep-wasm-sign/main.go internal/wasmsign/wasmsign.go internal/demokeys/keys.go
TEEP_AGENT_TEST_DEPS := $(wildcard wasm/teep-agent/src/verified/tests/*.rs)
RISCV_OPTEE_OFFLINE_NORMAL_MODES := \
	execute-helloworld execute-timeout-negative \
	execute-calcadd execute-negaposi execute-hostcall-negative execute-cleanup-negative execute-catalog-resource-negative \
	teep-agent-resolve teep-agent-signature-negative teep-agent-resolve-hash-negative teep-agent-resolve-catalog-negative teep-agent-resolve-wrapped-error-negative \
	public-abi-wrapped-error-negative public-abi-app-hash-negative public-abi-resource-limit-negative public-abi-execute-helloworld public-abi-execute-calcadd \
	public-abi-execute-negaposi teep-agent-transcript-limits teep-agent-hostcall-bridge teep-agent-acceptance teep-agent-hostcall-object-negative \
	wamr-spike-linked wamr-spike-linked-negative wamr-spike-input-negative wamr-spike-output-negative wamr-spike-cleanup-negative \
	wamr-spike-negatives
RISCV_OPTEE_OFFLINE_HOOK_MODES := teep-agent-acceptance-faults teep-agent-two-session-generation
RISCV_OPTEE_OFFLINE_UNLINKED_MODES := \
	all failures abi-vectors execute-abi-negative host-io-resume host-io-resume-negative \
	sha256-boundary-negative teep-agent-hostcall-http teep-agent-hostcall-evidence wamr-spike
ARM_OPTEE_OFFLINE_TARGETS := \
	smoke-optee-trustzone smoke-optee-trustzone-failures smoke-optee-trustzone-abi-vectors \
	smoke-optee-trustzone-execute-abi-negative smoke-optee-trustzone-execute-helloworld smoke-optee-trustzone-execute-timeout-negative \
	smoke-optee-trustzone-execute-calcadd smoke-optee-trustzone-execute-negaposi smoke-optee-trustzone-execute-hostcall-negative \
	smoke-optee-trustzone-execute-cleanup-negative smoke-optee-trustzone-execute-catalog-resource-negative smoke-optee-trustzone-teep-agent-resolve \
	smoke-optee-trustzone-teep-agent-signature-negative smoke-optee-trustzone-teep-agent-resolve-hash-negative smoke-optee-trustzone-teep-agent-resolve-catalog-negative \
	smoke-optee-trustzone-teep-agent-resolve-wrapped-error-negative smoke-optee-trustzone-public-abi-wrapped-error-negative smoke-optee-trustzone-public-abi-app-hash-negative \
	smoke-optee-trustzone-public-abi-resource-limit-negative smoke-optee-trustzone-public-abi-execute-helloworld smoke-optee-trustzone-public-abi-execute-calcadd \
	smoke-optee-trustzone-public-abi-execute-negaposi smoke-optee-trustzone-host-io-resume smoke-optee-trustzone-host-io-resume-negative \
	smoke-optee-trustzone-sha256-boundary-negative smoke-optee-trustzone-teep-agent-hostcall-http smoke-optee-trustzone-teep-agent-hostcall-evidence \
	smoke-optee-trustzone-teep-agent-transcript-limits smoke-optee-trustzone-teep-agent-hostcall-bridge smoke-optee-trustzone-teep-agent-acceptance \
	smoke-optee-trustzone-teep-agent-acceptance-faults smoke-optee-trustzone-teep-agent-two-session-generation smoke-optee-trustzone-teep-agent-hostcall-object-negative \
	smoke-optee-trustzone-wamr-spike smoke-optee-trustzone-wamr-spike-linked smoke-optee-trustzone-wamr-spike-linked-negative \
	smoke-optee-trustzone-wamr-spike-input-negative smoke-optee-trustzone-wamr-spike-output-negative smoke-optee-trustzone-wamr-spike-cleanup-negative \
	smoke-optee-trustzone-wamr-spike-negatives

.PHONY: fmt build setup-optee-arm-v8 check-optee-arm-v8-env build-optee-trustzone build-optee-riscv-v9 package-optee-riscv-v9 smoke-optee-riscv-v9 smoke-optee-riscv-v9-attestam-live smoke-optee-riscv-v9-attestam-verified-acceptance smoke-optee-riscv-v9-attestam-verified-catalog smoke-optee-riscv-v9-attestam-verified-app test check-optee-trustzone-smokes e2e e2e-attestam-insecure e2e-attestam-live attestam-remotehello-fixture register-attestam-remotehello-fixture attestam-helloworld-fixture register-attestam-helloworld-fixture attestam-catalog-fixture attestam-catalog-test-fixtures register-attestam-catalog-fixture register-attestam-app-catalog-fixture veraison-generic-eat-corim provision-veraison-generic-eat-fixture smoke-attestam-insecure smoke-attestam-challenge-observe m10-trustzone-checkpoint smoke-optee-trustzone smoke-optee-trustzone-failures smoke-optee-trustzone-abi-vectors smoke-optee-trustzone-execute-abi-negative smoke-optee-trustzone-execute-helloworld smoke-optee-trustzone-execute-timeout-negative smoke-optee-trustzone-execute-calcadd smoke-optee-trustzone-execute-negaposi smoke-optee-trustzone-execute-hostcall-negative smoke-optee-trustzone-execute-cleanup-negative smoke-optee-trustzone-execute-catalog-resource-negative smoke-optee-trustzone-teep-agent-resolve smoke-optee-trustzone-teep-agent-signature-negative smoke-optee-trustzone-teep-agent-resolve-hash-negative smoke-optee-trustzone-teep-agent-resolve-catalog-negative smoke-optee-trustzone-teep-agent-resolve-wrapped-error-negative smoke-optee-trustzone-public-abi-wrapped-error-negative smoke-optee-trustzone-public-abi-app-hash-negative smoke-optee-trustzone-public-abi-resource-limit-negative smoke-optee-trustzone-public-abi-execute-helloworld smoke-optee-trustzone-public-abi-execute-calcadd smoke-optee-trustzone-public-abi-execute-negaposi smoke-optee-trustzone-attestam-live smoke-optee-trustzone-attestam-verified-acceptance smoke-optee-trustzone-attestam-verified-catalog smoke-optee-trustzone-attestam-verified-app smoke-optee-trustzone-host-io-resume smoke-optee-trustzone-host-io-resume-negative smoke-optee-trustzone-sha256-boundary-negative smoke-optee-trustzone-teep-agent-hostcall-http smoke-optee-trustzone-teep-agent-hostcall-evidence smoke-optee-trustzone-teep-agent-hostcall-bridge smoke-optee-trustzone-teep-agent-hostcall-object-negative smoke-optee-trustzone-wamr-spike smoke-optee-trustzone-wamr-spike-linked smoke-optee-trustzone-wamr-spike-linked-negative smoke-optee-trustzone-wamr-spike-input-negative smoke-optee-trustzone-wamr-spike-output-negative smoke-optee-trustzone-wamr-spike-cleanup-negative smoke-optee-trustzone-wamr-spike-negatives clean
.PHONY: smoke-optee-trustzone-teep-agent-acceptance
.PHONY: smoke-optee-trustzone-teep-agent-acceptance-faults
.PHONY: smoke-optee-trustzone-teep-agent-transcript-limits
.PHONY: smoke-optee-trustzone-teep-agent-two-session-generation
.PHONY: smoke-optee-all-profiles
.PHONY: smoke-optee-arm-v8-offline-full smoke-optee-riscv-v9-offline-normal smoke-optee-riscv-v9-offline-unlinked smoke-optee-riscv-v9-offline-hooks smoke-optee-riscv-v9-offline-full smoke-optee-all-profiles-offline-full

.DEFAULT_GOAL := fmt
include make/sgx.mk

fmt:
	$(GO) fmt ./...

build: bin/twep-cli bin/twepd build/libtwep_wr.so build/teep-agent.wasm build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm build/catalog.dev.json build/catalog.dev.cbor

setup-optee-arm-v8:
	OPTEE_ROOT="$(OPTEE_ROOT)" WAMR_ROOT_DIR="$(WAMR_DIR)" ./scripts/setup_optee_arm_v8.sh

check-optee-arm-v8-env:
	OPTEE_ROOT="$(OPTEE_ROOT)" WAMR_ROOT_DIR="$(WAMR_DIR)" ./scripts/check_optee_arm_v8_env.sh

bin/twep-cli: cmd/twep-cli/main.go internal/cborcodec/types.go internal/cliargs/cliargs.go internal/ipc/ipc.go
	$(GO) build -o $@ ./cmd/twep-cli

bin/twepd: build/libtwep_wr.so build/teep-agent.wasm build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm build/catalog.dev.json build/catalog.dev.cbor cmd/twepd/main.go internal/cborcodec/types.go internal/ipc/ipc.go internal/twepwr/twepwr.go internal/teepbroker/teepbroker.go internal/tcinventory/inventory.go
	$(GO) build -o $@ ./cmd/twepd

build/libtwep_wr.so: lib/twep-wr/CMakeLists.txt lib/twep-wr/src/app_runtime.c lib/twep-wr/src/catalog_resolver.c lib/twep-wr/src/response_cbor.c lib/twep-wr/src/runtime.c lib/twep-wr/src/runtime_internal.h lib/twep-wr/src/teep_agent_runtime.c lib/twep-wr/src/wasm_signature.c lib/twep-wr/include/twep_wr.h
	$(CMAKE) -S lib/twep-wr -B build/twep-wr -DWAMR_ROOT_DIR=$(WAMR_DIR)
	$(CMAKE) --build build/twep-wr
	cp build/twep-wr/libtwep_wr.so $@

build-optee-trustzone: build/libtwep_wr_arm_optee.so

build-optee-riscv-v9:
	$(OPTEE_RUST_ENV) RISCV_OPTEE_ROOT="$(RISCV_OPTEE_ROOT)" \
	RISCV_OPTEE_BUILDROOT="$(RISCV_OPTEE_BUILDROOT)" \
	RISCV_OPTEE_WAMR_DIR="$(RISCV_OPTEE_WAMR_DIR)" \
	RISCV_OPTEE_OUT="$(abspath $(RISCV_OPTEE_OUT))" \
	./scripts/build_optee_riscv_v9.sh

package-optee-riscv-v9: build-optee-riscv-v9

smoke-optee-riscv-v9: build-optee-riscv-v9
	RISCV_OPTEE_ROOT="$(RISCV_OPTEE_ROOT)" \
	RISCV_OPTEE_OUT="$(abspath $(RISCV_OPTEE_OUT))" \
	./scripts/run_optee_riscv_v9_smoke.sh

smoke-optee-riscv-v9-attestam-live: build-optee-riscv-v9
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-optee-riscv-v9-attestam-live ATTESTAM_URL=http://10.0.2.2:8080/tam ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit"; exit 2; }
	$(MAKE) provision-veraison-generic-eat-fixture VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)"
	$(MAKE) register-attestam-helloworld-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	./scripts/run_optee_riscv_v9_phase.sh attestam-live "$(ATTESTAM_URL)"

smoke-optee-riscv-v9-attestam-verified-acceptance: build/teep-agent-m9-1-smoke.wasm
	TWEP_TEEP_AGENT_WASM="$(CURDIR)/build/teep-agent-m9-1-smoke.wasm" \
	TWEP_TA_WAMR_LINK=1 TWEP_TA_D043_TEST_HOOKS=0 $(MAKE) build-optee-riscv-v9
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-optee-riscv-v9-attestam-verified-acceptance ATTESTAM_URL=http://10.0.2.2:8080/tam ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit"; exit 2; }
	$(MAKE) provision-veraison-generic-eat-fixture VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)"
	$(MAKE) register-attestam-helloworld-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	./scripts/run_optee_riscv_v9_phase.sh attestam-verified-acceptance "$(ATTESTAM_URL)"

smoke-optee-riscv-v9-attestam-verified-catalog:
	TWEP_TA_D043_TEST_HOOKS=1 $(MAKE) build-optee-riscv-v9
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-optee-riscv-v9-attestam-verified-catalog ATTESTAM_URL=http://10.0.2.2:8080/tam ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit"; exit 2; }
	$(MAKE) provision-veraison-generic-eat-fixture VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)"
	$(MAKE) register-attestam-catalog-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	./scripts/run_optee_riscv_v9_phase.sh attestam-verified-catalog "$(ATTESTAM_URL)"

smoke-optee-riscv-v9-attestam-verified-app: build-optee-riscv-v9
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-optee-riscv-v9-attestam-verified-app ATTESTAM_URL=http://10.0.2.2:8080/tam ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit"; exit 2; }
	$(MAKE) provision-veraison-generic-eat-fixture VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)"
	$(MAKE) register-attestam-app-catalog-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	$(MAKE) register-attestam-helloworld-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	./scripts/run_optee_riscv_v9_phase.sh attestam-verified-app "$(ATTESTAM_URL)"

# Paired OP-TEE baseline. This aggregates existing profile-owned runners;
# docs/Testing.md defines what may be reported as complete coverage.
smoke-optee-all-profiles:
	$(MAKE) smoke-optee-trustzone
	$(MAKE) smoke-optee-riscv-v9

# Exhaustive offline OP-TEE gates. Live AttesTAM/Veraison phases remain
# separate because each profile requires independently fresh service state.
smoke-optee-arm-v8-offline-full:
	@set -eu; \
	for target in $(ARM_OPTEE_OFFLINE_TARGETS); do \
		echo "=== ARM OP-TEE offline: $$target ==="; \
		$(MAKE) "$$target"; \
	done; \
	echo TWEP_ARM_OPTEE_V8_OFFLINE_FULL_PASS

smoke-optee-riscv-v9-offline-normal:
	TWEP_TA_WAMR_LINK=1 TWEP_TA_D043_TEST_HOOKS=0 $(MAKE) build-optee-riscv-v9
	RISCV_OPTEE_ROOT="$(RISCV_OPTEE_ROOT)" \
	RISCV_OPTEE_OUT="$(abspath $(RISCV_OPTEE_OUT))" \
	./scripts/run_optee_riscv_v9_modes.sh offline-normal $(RISCV_OPTEE_OFFLINE_NORMAL_MODES)

smoke-optee-riscv-v9-offline-unlinked:
	TWEP_TA_WAMR_LINK=0 TWEP_TA_D043_TEST_HOOKS=0 $(MAKE) build-optee-riscv-v9
	RISCV_OPTEE_ROOT="$(RISCV_OPTEE_ROOT)" \
	RISCV_OPTEE_OUT="$(abspath $(RISCV_OPTEE_OUT))" \
	TWEP_RISCV_MODES_RUN_DAEMON=0 \
	./scripts/run_optee_riscv_v9_modes.sh offline-unlinked $(RISCV_OPTEE_OFFLINE_UNLINKED_MODES)

smoke-optee-riscv-v9-offline-hooks:
	TWEP_TA_WAMR_LINK=1 TWEP_TA_D043_TEST_HOOKS=1 $(MAKE) build-optee-riscv-v9
	RISCV_OPTEE_ROOT="$(RISCV_OPTEE_ROOT)" \
	RISCV_OPTEE_OUT="$(abspath $(RISCV_OPTEE_OUT))" \
	TWEP_RISCV_MODES_RUN_DAEMON=0 \
	./scripts/run_optee_riscv_v9_modes.sh offline-hooks $(RISCV_OPTEE_OFFLINE_HOOK_MODES)

smoke-optee-riscv-v9-offline-full:
	$(MAKE) smoke-optee-riscv-v9-offline-normal
	$(MAKE) smoke-optee-riscv-v9-offline-unlinked
	$(MAKE) smoke-optee-riscv-v9-offline-hooks
	TWEP_TA_WAMR_LINK=1 TWEP_TA_D043_TEST_HOOKS=0 $(MAKE) build-optee-riscv-v9
	@echo TWEP_RISCV_OPTEE_V9_OFFLINE_FULL_PASS

smoke-optee-all-profiles-offline-full:
	$(MAKE) smoke-optee-arm-v8-offline-full
	$(MAKE) smoke-optee-riscv-v9-offline-full
	@echo TWEP_OPTEE_ALL_PROFILES_OFFLINE_FULL_PASS

build/libtwep_wr_arm_optee.so: lib/twep-wr/CMakeLists.txt lib/twep-wr/src/app_runtime.c lib/twep-wr/src/catalog_resolver.c lib/twep-wr/src/response_cbor.c lib/twep-wr/src/runtime.c lib/twep-wr/src/runtime_internal.h lib/twep-wr/src/teep_agent_runtime.c lib/twep-wr/src/wasm_signature.c $(wildcard lib/twep-wr/src/platform/optee-common/*.[ch]) lib/twep-wr/src/platform/arm-optee/platform_arm_optee.c lib/twep-wr/include/twep_wr.h
	$(CMAKE) -S lib/twep-wr -B $(ARM_OPTEE_TWEP_WR_BUILD_DIR) -DCMAKE_TOOLCHAIN_FILE=$(OPTEE_BUILDROOT_TOOLCHAIN) -DWAMR_ROOT_DIR=$(WAMR_DIR) -DTWEP_WR_PLATFORM_BACKEND=arm-optee
	$(CMAKE) --build $(ARM_OPTEE_TWEP_WR_BUILD_DIR)
	cp $(ARM_OPTEE_TWEP_WR_BUILD_DIR)/libtwep_wr.so $@

build/helloworld.wasm: wasm/apps/helloworld/Cargo.toml wasm/apps/helloworld/src/lib.rs $(WASM_SIGNER_DEPS)
	$(CARGO) build --manifest-path wasm/apps/helloworld/Cargo.toml --release --target wasm32-unknown-unknown
	cp wasm/apps/helloworld/target/wasm32-unknown-unknown/release/twep_helloworld.wasm $@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

build/teep-agent.wasm: wasm/teep-agent/Cargo.toml wasm/teep-agent/src/lib.rs wasm/teep-agent/src/catalog_validator.rs wasm/teep-agent/src/cbor.rs wasm/teep-agent/src/cose.rs wasm/teep-agent/src/credential_management.rs wasm/teep-agent/src/evidence.rs wasm/teep-agent/src/freshness.rs wasm/teep-agent/src/host_io.rs wasm/teep-agent/src/probes.rs wasm/teep-agent/src/protected_credentials.rs wasm/teep-agent/src/session.rs wasm/teep-agent/src/session/exchange.rs wasm/teep-agent/src/session/insecure_install.rs wasm/teep-agent/src/session/live.rs wasm/teep-agent/src/session/observation.rs wasm/teep-agent/src/suit.rs wasm/teep-agent/src/teep.rs wasm/teep-agent/src/verified.rs wasm/teep-agent/src/verified/agent_identity.rs wasm/teep-agent/src/verified/credentials.rs wasm/teep-agent/src/verified/diagnostics.rs wasm/teep-agent/src/verified/dry_run.rs wasm/teep-agent/src/verified/evidence_status.rs wasm/teep-agent/src/verified/live_acceptance.rs wasm/teep-agent/src/verified/state.rs $(TEEP_AGENT_TEST_DEPS) wasm/teep-agent/src/wasm_signature.rs $(WASM_SIGNER_DEPS)
	TMPDIR="$(TMPDIR)" $(CARGO) build --manifest-path wasm/teep-agent/Cargo.toml --release --target wasm32-unknown-unknown
	cp wasm/teep-agent/target/wasm32-unknown-unknown/release/twep_teep_agent.wasm $@
	$(GO) run ./cmd/twep-wasm-sign -role teep-agent -in $@ -out $@

build/teep-agent-m9-1-smoke.wasm: wasm/teep-agent/Cargo.toml wasm/teep-agent/src/lib.rs wasm/teep-agent/src/catalog_validator.rs wasm/teep-agent/src/cbor.rs wasm/teep-agent/src/cose.rs wasm/teep-agent/src/credential_management.rs wasm/teep-agent/src/evidence.rs wasm/teep-agent/src/freshness.rs wasm/teep-agent/src/host_io.rs wasm/teep-agent/src/probes.rs wasm/teep-agent/src/protected_credentials.rs wasm/teep-agent/src/session.rs wasm/teep-agent/src/session/exchange.rs wasm/teep-agent/src/session/insecure_install.rs wasm/teep-agent/src/session/live.rs wasm/teep-agent/src/session/observation.rs wasm/teep-agent/src/suit.rs wasm/teep-agent/src/teep.rs wasm/teep-agent/src/verified.rs wasm/teep-agent/src/verified/agent_identity.rs wasm/teep-agent/src/verified/credentials.rs wasm/teep-agent/src/verified/diagnostics.rs wasm/teep-agent/src/verified/dry_run.rs wasm/teep-agent/src/verified/evidence_status.rs wasm/teep-agent/src/verified/live_acceptance.rs wasm/teep-agent/src/verified/state.rs $(TEEP_AGENT_TEST_DEPS) wasm/teep-agent/src/wasm_signature.rs $(WASM_SIGNER_DEPS)
	$(CARGO) build --manifest-path wasm/teep-agent/Cargo.toml --release --target wasm32-unknown-unknown --target-dir build/cargo-teep-agent-m9-1 --features m9-1-acceptance-only-smoke
	cp build/cargo-teep-agent-m9-1/wasm32-unknown-unknown/release/twep_teep_agent.wasm $@
	$(GO) run ./cmd/twep-wasm-sign -role teep-agent -in $@ -out $@

build/calcadd.wasm: wasm/apps/calcadd/Cargo.toml wasm/apps/calcadd/src/lib.rs $(WASM_SIGNER_DEPS)
	$(CARGO) build --manifest-path wasm/apps/calcadd/Cargo.toml --release --target wasm32-unknown-unknown
	cp wasm/apps/calcadd/target/wasm32-unknown-unknown/release/twep_calcadd.wasm $@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

build/negaposi.wasm: wasm/apps/negaposi/Cargo.toml wasm/apps/negaposi/src/lib.rs $(WASM_SIGNER_DEPS)
	$(CARGO) build --manifest-path wasm/apps/negaposi/Cargo.toml --release --target wasm32-unknown-unknown
	cp wasm/apps/negaposi/target/wasm32-unknown-unknown/release/twep_negaposi.wasm $@
	$(GO) run ./cmd/twep-wasm-sign -role app -in $@ -out $@

build/catalog.dev.json build/catalog.dev.cbor: build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm cmd/twep-catalog-gen/main.go
	$(GO) run ./cmd/twep-catalog-gen --json build/catalog.dev.json --cbor build/catalog.dev.cbor

attestam-remotehello-fixture: build/helloworld.wasm
	$(GO) run ./cmd/twep-attestam-fixture-gen --command remotehello --wasm build/helloworld.wasm --wasm-file remotehello.wasm --out build/attestam/remotehello.envelope.cbor --sequence 1

register-attestam-remotehello-fixture: build/helloworld.wasm
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make register-attestam-remotehello-fixture ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest"; exit 2; }
	$(GO) run ./cmd/twep-attestam-fixture-gen --command remotehello --wasm build/helloworld.wasm --wasm-file remotehello.wasm --out build/attestam/remotehello.envelope.cbor --sequence 1 --register-url "$(ATTESTAM_REGISTER_URL)"

attestam-helloworld-fixture: build/helloworld.wasm
	$(GO) run ./cmd/twep-attestam-fixture-gen --command helloworld --wasm build/helloworld.wasm --wasm-file helloworld.wasm --out build/attestam/helloworld.envelope.cbor --sequence 1

register-attestam-helloworld-fixture: build/helloworld.wasm
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make register-attestam-helloworld-fixture ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest"; exit 2; }
	$(GO) run ./cmd/twep-attestam-fixture-gen --command helloworld --wasm build/helloworld.wasm --wasm-file helloworld.wasm --out build/attestam/helloworld.envelope.cbor --sequence 1 --register-url "$(ATTESTAM_REGISTER_URL)"

attestam-catalog-fixture:
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --out build/attestam/catalog-default.envelope.cbor --sequence 1

attestam-catalog-test-fixtures:
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --out build/attestam/catalog-default.envelope.cbor --verified-update-out build/attestam/catalog-default.update.cose --verified-token-out build/attestam/catalog-default.token --sequence 1
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --out build/attestam/catalog-replacement.envelope.cbor --verified-update-out build/attestam/catalog-replacement.update.cose --sequence 2
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --catalog-name not-default --out build/attestam/catalog-wrong-name.envelope.cbor --verified-update-out build/attestam/catalog-wrong-name.update.cose --sequence 1
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --catalog-fixture malformed --out build/attestam/catalog-malformed.envelope.cbor --verified-update-out build/attestam/catalog-malformed.update.cose --sequence 1
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --catalog-fixture oversized --out build/attestam/catalog-oversized.envelope.cbor --verified-update-out build/attestam/catalog-oversized.update.cose --sequence 1
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --out build/attestam/catalog-inbound-max.envelope.cbor --verified-update-out build/attestam/catalog-inbound-max.update.cose --verified-update-size 131072 --sequence 1
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --out build/attestam/catalog-inbound-oversized.envelope.cbor --verified-update-out build/attestam/catalog-inbound-oversized.update.cose --verified-update-size 131073 --sequence 1

register-attestam-catalog-fixture:
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make register-attestam-catalog-fixture ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest"; exit 2; }
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --out build/attestam/catalog-default.envelope.cbor --sequence 1 --register-url "$(ATTESTAM_REGISTER_URL)"

register-attestam-app-catalog-fixture: build/catalog.dev.cbor
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make register-attestam-app-catalog-fixture ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest"; exit 2; }
	$(GO) run ./cmd/twep-attestam-fixture-gen --catalog --catalog-payload build/catalog.dev.cbor --out build/attestam/catalog-apps.envelope.cbor --sequence 1 --register-url "$(ATTESTAM_REGISTER_URL)"

veraison-generic-eat-corim: testdata/attestam/twep-generic-eat-corim.cbor.base64
	mkdir -p build/attestam
	base64 --decode $< > build/attestam/twep-generic-eat-corim.cbor
	printf '%s  %s\n' 43ec7ec291ac01e55f441910dea79ff570a826374761b6e8b629a067a7de52ac build/attestam/twep-generic-eat-corim.cbor | sha256sum --check --status

provision-veraison-generic-eat-fixture: veraison-generic-eat-corim
	curl -fsS --insecure -X POST --data-binary @build/attestam/twep-generic-eat-corim.cbor -H 'Content-Type: application/corim-unsigned+cbor; profile="http://example.com/corim/profile"' "$(VERAISON_PROVISION_URL)"

test: check-optee-trustzone-smokes build/libtwep_wr.so build/teep-agent.wasm build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm build/catalog.dev.json build/catalog.dev.cbor
	$(GO) test ./...

check-optee-trustzone-smokes:
	python3 scripts/check_optee_trustzone_smokes.py

e2e: build
	@set -eu; \
	state=$$(mktemp -d); \
	sock="$$state/twepd.sock"; \
	./bin/twepd --socket "$$sock" --state-dir "$$state" --once & \
	pid=$$!; \
	sleep 1; \
	./bin/twep-cli --socket "$$sock" helloworld; \
	wait $$pid; \
	./bin/twepd --socket "$$sock" --state-dir "$$state" --once & \
	pid=$$!; \
	sleep 1; \
	./bin/twep-cli --socket "$$sock" calcadd 3 4 5; \
	wait $$pid; \
	./bin/twepd --socket "$$sock" --state-dir "$$state" --once & \
	pid=$$!; \
	sleep 1; \
	./bin/twep-cli --socket "$$sock" negaposi -i testdata/images/medium.jpg -o "$$state/output.jpg"; \
	wait $$pid; \
	test -f "$$state/catalog/catalog.cbor"; \
	test -f "$$state/catalog/catalog.dev.json"; \
	test -f "$$state/teep-agent/teep-agent.wasm"; \
	test -f "$$state/tmp/teep-agent-probe"; \
	test -f "$$state/apps/helloworld.wasm"; \
	test -f "$$state/apps/calcadd.wasm"; \
	test -f "$$state/apps/negaposi.wasm"; \
	test -s "$$state/output.jpg"; \
	! cmp -s testdata/images/medium.jpg "$$state/output.jpg"

e2e-attestam-insecure: build
	TWEP_E2E_BIN_DIR=$(CURDIR)/bin TWEP_E2E_REPO_ROOT=$(CURDIR) $(GO) test ./tests/e2e -run 'TestAttestam(Insecure|Verified)' -count=1

e2e-attestam-live: build
	TWEP_E2E_BIN_DIR=$(CURDIR)/bin TWEP_E2E_REPO_ROOT=$(CURDIR) $(GO) test ./tests/e2e -run TestAttestamLiveChallengeResponseUpdate -count=1 -v

e2e-attestam-v26-generic-eat:
	ATTESTAM_ROOT="$(ATTESTAM_ROOT)" WAMR_DIR="$(WAMR_DIR)" VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)" VERAISON_CHALLENGE_URL="$(VERAISON_CHALLENGE_URL)" ATTESTAM_CONFORMANCE_ADDR="$(ATTESTAM_CONFORMANCE_ADDR)" ./scripts/compat/run-attestam-v26-generic-eat.sh

attestam-v26-conformance: e2e-attestam-v26-generic-eat

smoke-attestam-insecure:
	@set -eu; \
	test -n "$(ATTESTAM_URL)" || { echo "usage: make smoke-attestam-insecure ATTESTAM_URL=http://host/tam"; exit 2; }; \
	$(MAKE) build; \
	state=$$(mktemp -d); \
	sock="$$state/twepd.sock"; \
	echo "state=$$state"; \
	./bin/twepd --socket "$$sock" --state-dir "$$state" --resolver-mode attestam-insecure --attestam-url "$(ATTESTAM_URL)" --insecure-demo-mode --once >"$$state/twepd.log" 2>&1 & \
	pid=$$!; \
	sleep 1; \
	if ./bin/twep-cli --socket "$$sock" helloworld >"$$state/twep-cli.out" 2>"$$state/twep-cli.err"; then \
		cat "$$state/twep-cli.out"; \
		wait $$pid; \
		test -f "$$state/catalog/catalog.cbor"; \
		echo "catalog available: $$state/catalog/catalog.cbor"; \
	else \
		status=$$?; \
		wait $$pid || true; \
		echo "twep-cli failed with status $$status"; \
		cat "$$state/twep-cli.err"; \
		echo "twepd log:"; \
		cat "$$state/twepd.log"; \
		echo "state=$$state"; \
		exit $$status; \
	fi

smoke-attestam-challenge-observe:
	@set -eu; \
	test -n "$(ATTESTAM_URL)" || { echo "usage: make smoke-attestam-challenge-observe ATTESTAM_URL=http://host/tam"; exit 2; }; \
	$(MAKE) build; \
	state=$$(mktemp -d); \
	sock="$$state/twepd.sock"; \
	echo "state=$$state"; \
	./bin/twepd --socket "$$sock" --state-dir "$$state" --resolver-mode attestam-insecure --attestam-url "$(ATTESTAM_URL)" --insecure-demo-mode --insecure-demo-agent-key alternate --once >"$$state/twepd.log" 2>&1 & \
	pid=$$!; \
	sleep 1; \
	if ./bin/twep-cli --socket "$$sock" helloworld >"$$state/twep-cli.out" 2>"$$state/twep-cli.err"; then \
		echo "twep-cli succeeded"; \
		cat "$$state/twep-cli.out"; \
		wait $$pid; \
	else \
		status=$$?; \
		wait $$pid || true; \
		echo "twep-cli failed with status $$status"; \
		cat "$$state/twep-cli.err"; \
	fi; \
	echo "twepd log:"; \
	cat "$$state/twepd.log"; \
	echo "teep-agent artifacts:"; \
	find "$$state/teep-agent" -maxdepth 1 -type f -printf "%f %s bytes\n" 2>/dev/null | sort; \
	for f in last-teep-message-type.txt last-query-response-status.txt last-query-response-body-message-type.txt last-attestation-query-response-status.txt last-session-result.txt success-status.txt; do \
		if test -f "$$state/teep-agent/$$f"; then echo "--- $$f"; cat "$$state/teep-agent/$$f"; fi; \
	done; \
	echo "state=$$state"

# M10 representative checkpoint. This is intentionally an aggregate over existing
# OP-TEE targets so each guest scenario remains owned by its focused smoke.
m10-trustzone-checkpoint:
	$(MAKE) smoke-optee-trustzone
	$(MAKE) smoke-optee-trustzone-failures
	$(MAKE) smoke-optee-trustzone-public-abi-execute-helloworld
	$(MAKE) smoke-optee-trustzone-public-abi-execute-calcadd
	$(MAKE) smoke-optee-trustzone-public-abi-execute-negaposi
	$(MAKE) smoke-optee-trustzone-execute-hostcall-negative
	$(MAKE) smoke-optee-trustzone-host-io-resume
	$(MAKE) smoke-optee-trustzone-teep-agent-hostcall-bridge
	$(MAKE) smoke-optee-trustzone-attestam-live ATTESTAM_URL="$(ATTESTAM_URL)" ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)" VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)"

# OP-TEE direct TA smoke path: baseline diagnostics and focused failure cases.
smoke-optee-trustzone:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh all' \
		--expect-ree 'TA ping ok' \
		--expect-ree 'secure storage readback ok' \
		--expect-ree 'random smoke ok' \
		--expect-ree 'time smoke ok' \
		--expect-ree 'CBOR dry-run ok' \
		--expect-ree 'platform-backend=arm-optee' \
		--expect-ree 'sealed-storage-security=tee-ree-fs-secure-storage' \
		--expect-ree 'sealed-storage-rollback-protected=false' \
		--expect-ree 'final-verified=false' \
		--expect-ree 'TrustZone smoke suite ok' \
		--expect-tee 'twep-wr-ta'

smoke-optee-trustzone-failures:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh failures' \
		--expect-ree 'TrustZone protected storage failure smoke ok' \
		--expect-ree 'missing-read failed as expected' \
		--expect-ree 'short-buffer-read failed as expected' \
		--expect-ree 'protected-credential-store-load=absent' \
		--expect-ree 'final-verified=false' \
		--expect-tee 'twep-wr-ta'

# The C host decodes the same canonical source used by Go and Rust, then sends
# its literal execute/resume bytes across TEEC into the TA parsers.
smoke-optee-trustzone-abi-vectors:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh abi-vectors' \
		--expect-ree 'TA canonical ABI vectors parsed from shared bytes ok' \
		--expect-ree 'TrustZone canonical ABI vectors ok' \
		--expect-tee 'production execute envelope parsed'

# OP-TEE TA private production command path: INIT/EXECUTE/RESUME_HOST_IO and TA-local runtime boundaries.
smoke-optee-trustzone-execute-abi-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh execute-abi-negative' \
		--expect-ree 'TA production init envelope parsed' \
		--expect-ree 'TA production execute envelope parsed' \
		--expect-ree 'TA production resume-host-io rejected without pending request' \
		--expect-ree 'TA production init rejected short output buffer' \
		--expect-ree 'TA production execute rejected malformed envelope' \
		--expect-ree 'TA unsupported command rejected' \
		--expect-ree 'TA production rejected D043 private test command' \
		--expect-ree 'TrustZone TA execute ABI negative ok' \
		--expect-tee 'production init envelope parsed' \
		--expect-tee 'production execute rejected malformed envelope' \
		--expect-tee 'unsupported command'

smoke-optee-trustzone-execute-helloworld:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh execute-helloworld' \
		--expect-ree 'TA production execute helloworld ok' \
		--expect-ree 'TrustZone TA execute helloworld ok' \
		--expect-tee 'production executed helloworld'

smoke-optee-trustzone-execute-timeout-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh execute-timeout-negative' \
		--expect-ree 'TA production execute helloworld failed' \
		--expect-ree 'TrustZone TA instruction budget stopped infinite-loop Wasm'

smoke-optee-trustzone-execute-calcadd:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh execute-calcadd' \
		--expect-ree 'TA production execute calcadd ok' \
		--expect-ree 'TrustZone TA execute calcadd ok' \
		--expect-tee 'production executed calcadd'

smoke-optee-trustzone-execute-negaposi:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh execute-negaposi' \
		--expect-ree 'TA production execute negaposi ok' \
		--expect-ree 'TrustZone TA execute negaposi ok' \
		--expect-tee 'production executed negaposi'

smoke-optee-trustzone-execute-hostcall-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh execute-hostcall-negative' \
		--expect-ree 'TA production execute rejected env.* import' \
		--expect-ree 'TA production execute rejected twep_teep_env.* import' \
		--expect-ree 'TrustZone TA execute hostcall negative ok'

smoke-optee-trustzone-execute-cleanup-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh execute-cleanup-negative' \
		--expect-ree 'TA production execute rejected short output buffer' \
		--expect-ree 'TA production execute rejected nonzero app status' \
		--expect-ree 'TA production execute rejected oversized app output' \
		--expect-ree 'TA production execute rejected trap app' \
		--expect-ree 'TA production execute cleanup after failures ok' \
		--expect-ree 'TrustZone TA execute cleanup negative ok' \
		--expect-tee 'production executed helloworld'

smoke-optee-trustzone-execute-catalog-resource-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh execute-catalog-resource-negative' \
		--expect-ree 'TA production execute wrapped app.resource_limit ok' \
		--expect-ree 'TrustZone TA execute catalog resource limit negative ok' \
		--expect-ree 'TrustZone TA execute catalog resource negative ok'

smoke-optee-trustzone-teep-agent-resolve:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-resolve' \
		--expect-ree 'TA production teep-agent resolve executed ok' \
		--expect-ree 'TrustZone TA teep-agent resolve executed ok' \
		--expect-tee 'production teep-agent resolve executed'

smoke-optee-trustzone-teep-agent-signature-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-signature-negative' \
		--expect-ree 'TA production rejected tampered teep-agent signature ok' \
		--expect-ree 'TA production rejected app-role wasm as teep-agent ok' \
		--expect-ree 'TrustZone TA teep-agent signature negative ok' \
		--expect-tee 'teep-agent code signature rejected'

smoke-optee-trustzone-teep-agent-resolve-hash-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-resolve-hash-negative' \
		--expect-ree 'TA production teep-agent resolve rejected app.hash_mismatch ok' \
		--expect-ree 'TrustZone TA teep-agent resolve hash negative ok' \
		--expect-tee 'production teep-agent resolve executed'

smoke-optee-trustzone-teep-agent-resolve-catalog-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-resolve-catalog-negative' \
		--expect-ree 'TA production teep-agent resolve rejected catalog.invalid ok' \
		--expect-ree 'TA production teep-agent resolve rejected catalog.not_found ok' \
		--expect-ree 'TrustZone TA teep-agent resolve catalog negatives ok' \
		--expect-tee 'production teep-agent resolve executed'

smoke-optee-trustzone-teep-agent-resolve-wrapped-error-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-resolve-wrapped-error-negative' \
		--expect-ree 'TA production teep-agent wrapped error mapped catalog.invalid ok' \
		--expect-ree 'TA production teep-agent wrapped error mapped catalog.not_found ok' \
		--expect-ree 'TA production teep-agent wrapped error mapped app.hash_mismatch ok' \
		--expect-ree 'TrustZone TA teep-agent wrapped error mapping negatives ok' \
		--expect-tee 'production teep-agent resolve executed'

# OP-TEE production public C ABI path: twep_wr_execute marshals through libteec into the TA.
smoke-optee-trustzone-public-abi-wrapped-error-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh public-abi-wrapped-error-negative' \
		--expect-ree 'public C ABI TrustZone execute wrapped error catalog.not_found ok' \
		--expect-ree 'TrustZone public C ABI wrapped error negative ok' \
		--expect-tee 'production teep-agent resolve executed'

smoke-optee-trustzone-public-abi-app-hash-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh public-abi-app-hash-negative' \
		--expect-ree 'public C ABI TrustZone execute app.hash_mismatch wrapped error ok' \
		--expect-ree 'TrustZone public C ABI app hash negative ok' \
		--expect-tee 'production teep-agent resolved app'

smoke-optee-trustzone-public-abi-resource-limit-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh public-abi-resource-limit-negative' \
		--expect-ree 'public C ABI TrustZone execute app.resource_limit wrapped error ok' \
		--expect-ree 'TrustZone public C ABI resource limit negative ok'

smoke-optee-trustzone-public-abi-execute-helloworld:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh public-abi-execute-helloworld' \
		--expect-ree 'public C ABI TrustZone execute helloworld ok' \
		--expect-ree 'TrustZone public C ABI execute helloworld ok' \
		--expect-tee 'production teep-agent resolved app' \
		--expect-tee 'production executed helloworld'

smoke-optee-trustzone-public-abi-execute-calcadd:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh public-abi-execute-calcadd' \
		--expect-ree 'public C ABI TrustZone execute calcadd ok' \
		--expect-ree 'TrustZone public C ABI execute calcadd ok' \
		--expect-tee 'production teep-agent resolved app' \
		--expect-tee 'production executed calcadd'

smoke-optee-trustzone-public-abi-execute-negaposi:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh public-abi-execute-negaposi' \
		--expect-ree 'public C ABI TrustZone execute negaposi ok' \
		--expect-ree 'TrustZone public C ABI execute negaposi ok' \
		--expect-tee 'production teep-agent resolved app' \
		--expect-tee 'production executed negaposi'

# OP-TEE production public path with live AttesTAM/Veraison bridge.
smoke-optee-trustzone-attestam-live:
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-optee-trustzone-attestam-live ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit"; exit 2; }
	$(MAKE) provision-veraison-generic-eat-fixture VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)"
	$(MAKE) register-attestam-helloworld-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ATTESTAM_URL="$(ATTESTAM_URL)" ./run_trustzone_smokes.sh attestam-live' \
		--expect-ree 'Hello, World!!' \
		--expect-ree 'runtime-location=optee-ta' \
		--expect-ree 'teep-agent-location=optee-ta' \
		--expect-ree 'catalog-resolution-location=optee-ta' \
		--expect-ree 'final-verified=false' \
		--expect-ree 'TrustZone AttesTAM live smoke ok'

# OP-TEE PoC verified path: live TAM acceptance is persisted, installation stays blocked.
smoke-optee-trustzone-attestam-verified-acceptance:
	$(MAKE) build/teep-agent-m9-1-smoke.wasm
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-optee-trustzone-attestam-verified-acceptance ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit"; exit 2; }
	$(MAKE) provision-veraison-generic-eat-fixture VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)"
	$(MAKE) register-attestam-helloworld-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	TWEP_TEEP_AGENT_WASM="$(CURDIR)/build/teep-agent-m9-1-smoke.wasm" ./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ATTESTAM_URL="$(ATTESTAM_URL)" ./run_trustzone_smokes.sh attestam-verified-acceptance' \
		--expect-ree 'teep.verified_required' \
		--expect-ree 'evidence-acceptance-generation-current=true' \
		--expect-ree 'final-verified=false' \
		--expect-ree 'TrustZone AttesTAM verified acceptance smoke ok'

# OP-TEE M9.2 verified path: commit the default Catalog TC, acknowledge it,
# and verify protected restart/failure behavior without executing an app.
smoke-optee-trustzone-attestam-verified-catalog:
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-optee-trustzone-attestam-verified-catalog ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit"; exit 2; }
	$(MAKE) provision-veraison-generic-eat-fixture VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)"
	$(MAKE) register-attestam-catalog-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	@set -eu; \
		cleanup() { $(MAKE) -C optee/twep-wr-ta clean >/dev/null; }; \
		trap cleanup EXIT HUP INT TERM; \
		$(MAKE) -C optee/twep-wr-ta clean; \
		$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1 TWEP_TA_D043_TEST_HOOKS=1; \
		$(OPTEE_POSTRUN) \
			--project-path $(CURDIR)/optee/twep-wr-ta \
			--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ATTESTAM_URL="$(ATTESTAM_URL)" ./run_trustzone_smokes.sh attestam-verified-catalog' \
			--expect-ree 'teep.verified_required' \
			--expect-ree 'component-kind=twep-catalog-v1' \
			--expect-ree 'component-name=default' \
			--expect-ree 'Catalog Success acknowledged' \
			--expect-ree 'TA D047 live Catalog restart readback ok' \
			--expect-ree 'TA D047 Catalog staging fault matrix preserved prior Catalog ok' \
			--expect-ree 'TA D047 D043 publication fault preserved prior Catalog ok' \
			--expect-ree 'final-verified=false' \
			--expect-ree 'TrustZone AttesTAM verified Catalog smoke ok' \
			--expect-tee 'catalog generation 1 committed'

# OP-TEE academic verified-app path: protect the one requested app, authorize
# it with the protected Catalog, execute it, and prove restart/offline reuse.
smoke-optee-trustzone-attestam-verified-app:
	test -n "$(ATTESTAM_REGISTER_URL)" || { echo "usage: make smoke-optee-trustzone-attestam-verified-app ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit"; exit 2; }
	$(MAKE) provision-veraison-generic-eat-fixture VERAISON_PROVISION_URL="$(VERAISON_PROVISION_URL)"
	$(MAKE) register-attestam-app-catalog-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	$(MAKE) register-attestam-helloworld-fixture ATTESTAM_REGISTER_URL="$(ATTESTAM_REGISTER_URL)"
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ATTESTAM_URL="$(ATTESTAM_URL)" ./run_trustzone_smokes.sh attestam-verified-app' \
		--expect-ree 'Verified Catalog committed' \
		--expect-ree 'Verified app installed and executed' \
		--expect-ree 'Protected app restart and offline execution ok' \
		--expect-ree 'final-verified=false' \
		--expect-ree 'TrustZone AttesTAM verified app smoke ok' \
		--expect-tee 'catalog generation 1 committed' \
		--expect-tee 'app generation 2 committed'

# OP-TEE TA private host I/O resume and TEEP_Agent hostcall broker boundaries.
smoke-optee-trustzone-host-io-resume:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh host-io-resume' \
		--expect-ree 'TA production host io requested ok' \
		--expect-ree 'TA production host io resumed ok' \
		--expect-ree 'TrustZone TA host io resume ok' \
		--expect-tee 'production host io requested' \
		--expect-tee 'production host io resumed'

smoke-optee-trustzone-host-io-resume-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh host-io-resume-negative' \
		--expect-ree 'TA production host io rejected missing pending request' \
		--expect-ree 'TA production host io rejected request_id mismatch' \
		--expect-ree 'TA production host io rejected io_id mismatch' \
		--expect-ree 'TA production host io rejected kind mismatch' \
		--expect-ree 'TA production host io rejected nonzero status' \
		--expect-ree 'TA production host io rejected sequence mismatch' \
		--expect-ree 'TA production host io rejected request body digest mismatch' \
		--expect-ree 'TA production host io rejected normalized input digest mismatch' \
		--expect-ree 'TA production host io rejected cross-session resume' \
		--expect-ree 'TA production host io rejected closed-session resume' \
		--expect-ree 'TrustZone TA host io resume negatives ok' \
		--expect-tee 'production host io requested' \
		--expect-tee 'production host io resumed'

smoke-optee-trustzone-sha256-boundary-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh sha256-boundary-negative' \
		--expect-ree 'TA C SHA-256 boundary kept to transport and protected-commit binding' \
		--expect-ree 'TrustZone TA SHA-256 boundary negative ok'

smoke-optee-trustzone-teep-agent-hostcall-http:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-hostcall-http' \
		--expect-ree 'TA production teep-agent http hostcall requested ok' \
		--expect-ree 'TA production teep-agent http hostcall resumed ok' \
		--expect-ree 'TrustZone TA teep-agent hostcall http ok' \
		--expect-tee 'production teep-agent hostcall http requested' \
		--expect-tee 'production host io resumed'

smoke-optee-trustzone-teep-agent-hostcall-evidence:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-hostcall-evidence' \
		--expect-ree 'TA production teep-agent evidence hostcall requested ok' \
		--expect-ree 'TA production teep-agent evidence hostcall resumed ok' \
		--expect-ree 'TrustZone TA teep-agent hostcall evidence ok' \
		--expect-tee 'production teep-agent hostcall evidence requested' \
		--expect-tee 'production host io resumed'

smoke-optee-trustzone-teep-agent-transcript-limits:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-transcript-limits' \
		--expect-ree 'TA D043 transcript 32768-byte and 65536-byte aggregate boundary accepted' \
		--expect-ree 'TA D043 third pending HTTP transcript rejected with resource limit' \
		--expect-ree 'TA D043 create_evidence excluded from HTTP transcript quota' \
		--expect-ree 'TA D043 32769-byte replacement rejected and old transcript invalidated' \
		--expect-ree 'TA D043 accepted terminal failure released transcript quota' \
		--expect-ree 'TA D043 session close released transcript quota' \
		--expect-ree 'TA D043 accepted resume released transcript quota' \
		--expect-ree 'TrustZone TA D043 transcript resource limits ok'

smoke-optee-trustzone-teep-agent-hostcall-bridge:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-hostcall-bridge' \
		--expect-ree 'TA production teep-agent wasm http hostcall requested ok' \
		--expect-ree 'TA production teep-agent wasm http hostcall resumed ok' \
		--expect-ree 'TA production teep-agent wasm evidence hostcall requested ok' \
		--expect-ree 'TA production teep-agent wasm evidence hostcall resumed ok' \
		--expect-ree 'TrustZone TA teep-agent wasm hostcall bridge ok' \
		--expect-tee 'production host io resumed'

smoke-optee-trustzone-teep-agent-acceptance:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-acceptance' \
		--expect-ree 'TA production acceptance generation 1 committed ok' \
		--expect-ree 'TA production acceptance generation 2 committed ok' \
		--expect-ree 'TA production acceptance state two-slot persistence ok' \
		--expect-ree 'TA acceptance transcript mismatch rejected with state unchanged' \
		--expect-ree 'TA acceptance replay rejected with state unchanged' \
		--expect-ree 'TA acceptance stale generation rejected with state unchanged' \
		--expect-ree 'TA acceptance cross-session resume rejected with state unchanged' \
		--expect-ree 'TA acceptance restart without pending rejected with state unchanged' \
		--expect-ree 'TA production teep-agent verified result secure storage mirror ok' \
		--expect-ree 'TrustZone TA TEEP synthetic acceptance commit ok' \
		--expect-ree 'TrustZone TA TEEP acceptance persistence and negatives ok'

smoke-optee-trustzone-teep-agent-acceptance-faults:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	@set -eu; \
		cleanup() { $(MAKE) -C optee/twep-wr-ta clean >/dev/null; }; \
		trap cleanup EXIT HUP INT TERM; \
		$(MAKE) -C optee/twep-wr-ta clean; \
		$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1 TWEP_TA_D043_TEST_HOOKS=1; \
		$(OPTEE_POSTRUN) \
			--project-path $(CURDIR)/optee/twep-wr-ta \
			--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-acceptance-faults' \
			--expect-ree 'TA D043 protected-storage fault matrix ok' \
			--expect-ree 'TrustZone TA D043 protected-storage fault matrix ok'

smoke-optee-trustzone-teep-agent-two-session-generation:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	@set -eu; \
		cleanup() { $(MAKE) -C optee/twep-wr-ta clean >/dev/null; }; \
		trap cleanup EXIT HUP INT TERM; \
		$(MAKE) -C optee/twep-wr-ta clean; \
		$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1 TWEP_TA_D043_TEST_HOOKS=1; \
		$(OPTEE_POSTRUN) \
			--project-path $(CURDIR)/optee/twep-wr-ta \
			--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-two-session-generation' \
			--expect-ree 'TA D043 synchronized two-session generation ok' \
			--expect-ree 'TrustZone TA D043 synchronized two-session generation ok'

smoke-optee-trustzone-teep-agent-hostcall-object-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh teep-agent-hostcall-object-negative' \
		--expect-ree 'TA ordinary build rejected D043 test probe ok' \
		--expect-ree 'TA production teep-agent rejected bad read object id ok' \
		--expect-ree 'TA production teep-agent rejected bad write object id ok' \
		--expect-ree 'TA REE generic catalog-state reads and writes rejected ok' \
		--expect-ree 'TrustZone TA teep-agent hostcall object negative ok'

# OP-TEE WAMR spike regression path: isolated from production twep_wr_execute.
smoke-optee-trustzone-wamr-spike:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh wamr-spike' \
		--expect-ree 'WAMR spike blocker: TA command shape reached' \
		--expect-ree 'TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC returned TEEC_ERROR_NOT_SUPPORTED' \
		--expect-ree 'TrustZone WAMR spike blocker captured' \
		--expect-tee 'WAMR spike blocker'

smoke-optee-trustzone-wamr-spike-linked:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh wamr-spike-linked' \
		--expect-ree 'WAMR spike executed helloworld inside TA' \
		--expect-ree 'TrustZone WAMR spike linked execution ok' \
		--expect-tee 'WAMR spike executed helloworld'

smoke-optee-trustzone-wamr-spike-linked-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh wamr-spike-linked-negative' \
		--expect-ree 'WAMR spike rejected unsupported import inside TA' \
		--expect-ree 'TrustZone WAMR spike linked negative ok' \
		--expect-tee 'WAMR spike rejected unsupported Wasm import section'

smoke-optee-trustzone-wamr-spike-input-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh wamr-spike-input-negative' \
		--expect-ree 'WAMR spike input boundary rejection ok' \
		--expect-ree 'TrustZone WAMR spike input negative ok' \
		--expect-tee 'WAMR spike rejected empty app input' \
		--expect-tee 'WAMR spike rejected malformed app input' \
		--expect-tee 'WAMR spike rejected oversized app input'

smoke-optee-trustzone-wamr-spike-output-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh wamr-spike-output-negative' \
		--expect-ree 'WAMR spike output boundary rejection ok' \
		--expect-ree 'TrustZone WAMR spike output negative ok' \
		--expect-tee 'WAMR spike rejected short output buffer' \
		--expect-tee 'WAMR spike rejected oversized app output'

smoke-optee-trustzone-wamr-spike-cleanup-negative:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh wamr-spike-cleanup-negative' \
		--expect-ree 'WAMR spike rejected nonzero app status inside TA' \
		--expect-ree 'WAMR spike rejected trap app inside TA' \
		--expect-ree 'WAMR spike cleanup after failures ok' \
		--expect-ree 'TrustZone WAMR spike cleanup negative ok' \
		--expect-tee 'WAMR spike rejected app failure status' \
		--expect-tee 'WAMR spike rejected invalid app output descriptor' \
		--expect-tee 'WAMR spike executed helloworld'

smoke-optee-trustzone-wamr-spike-negatives:
	./optee/twep-wr-ta/prepare-diagnose-smoke.sh
	$(MAKE) -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
	$(OPTEE_POSTRUN) \
		--project-path $(CURDIR)/optee/twep-wr-ta \
		--guest-command 'TWEP_TRUSTZONE_RESET_STORAGE=1 ./run_trustzone_smokes.sh wamr-spike-negatives' \
		--expect-ree 'TrustZone WAMR spike linked negative ok' \
		--expect-ree 'TrustZone WAMR spike input negative ok' \
		--expect-ree 'TrustZone WAMR spike output negative ok' \
		--expect-ree 'TrustZone WAMR spike cleanup negative ok' \
		--expect-ree 'TrustZone WAMR spike negatives ok' \
		--expect-tee 'WAMR spike rejected unsupported Wasm import section' \
		--expect-tee 'WAMR spike rejected oversized app input' \
		--expect-tee 'WAMR spike rejected oversized app output' \
		--expect-tee 'WAMR spike rejected app failure status' \
		--expect-tee 'WAMR spike executed helloworld'

clean: clean-sgx
	rm -rf bin build wasm/teep-agent/target wasm/apps/helloworld/target wasm/apps/calcadd/target wasm/apps/negaposi/target
