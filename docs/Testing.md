# Testing.md: twep Test Plan

## KISS / DRY

Follow KISS and DRY in test design. Do not duplicate fixture generation, golden data, diagnostic keys, or E2E startup procedures; refer to shared helpers or canonical data. Before adding copy-and-paste tests, consider table-driven tests that express the same boundary conditions or integration into an existing make target.

`make smoke-optee-trustzone-abi-vectors` is the cross-language CBOR boundary
smoke. Go and Rust read `testdata/abi/vectors.hex` directly; the OP-TEE asset
preparation copies that same file into the guest, where the C client decodes
all vectors and passes the literal execute/resume envelope bytes through TEEC
to their TA commands. This is distinct from tests that independently construct
equivalent envelopes.

## Test Layers

| Layer | Target | Purpose |
| --- | --- | --- |
| Unit | Go packages | CBOR, CLI args, IPC framing, error mapping |
| Unit | C twep-wr | C ABI, buffer ownership, WAMR wrapper |
| Unit | Rust Wasm apps | app logic, CBOR parse/build |
| Integration | twep-cli+twepd | IPC and response display |
| Integration | twepd+twep-wr | cgo and C ABI integration |
| Integration | twep-wr+WAMR | Wasm load/execute |
| E2E | Entire system | helloworld, calcadd, JPEG version of negaposi |
| Security | Entire system | path traversal, hash mismatch, permissions |

## Required Commands

```sh
make fmt
make build
make test
make e2e
make e2e-attestam-insecure
make smoke-attestam-insecure ATTESTAM_URL=http://127.0.0.1:8080/tam
make e2e-attestam-live \
  ATTESTAM_URL=http://localhost:8080/tam \
  ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest \
  VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit
```

`make e2e-attestam-live` is an integration test that uses real AttesTAM and Veraison instances. Include it in normal post-change verification in environments where local AttesTAM and Veraison instances can be started. If it cannot run because they are not running, an external service has failed, a port conflicts, certificate or store state is invalid, or the execution environment restricts HTTP/TLS communication, report the exact blocker and request only the service startup or access needed to run the test.

For changes that compile a Rust/Wasm crate, always run `cargo clippy` in the corresponding crate. When building a Wasm target, also run clippy for the applicable target, such as `cargo clippy --target wasm32-unknown-unknown`, when appropriate.

## Verification Matrix

Select post-change verification according to the scope of the change using the following criteria. `make test` is the minimum baseline and must be run for normal code changes.

| Change Scope | Verification to Run | Purpose |
| --- | --- | --- |
| Go CLI/daemon/CBOR/IPC | `make test` | Detect regressions in unit tests and lightweight E2E helpers |
| Normal execution path, C ABI, WAMR, Catalog, mock resolver | `make test`, `make e2e` | Confirm that `helloworld`, `calcadd`, and the JPEG version of `negaposi` remain functional on the Linux backend |
| AttesTAM insecure, TEEP_Agent, verified dry-run, diagnostics | `make test`, `make e2e-attestam-insecure` | Verify fixture AttesTAM, the `attestam-verified` dry-run, diagnose text/JSON, and prohibition of unverified promotion |
| Live AttesTAM/Veraison integration | `make e2e-attestam-live ATTESTAM_URL=... ATTESTAM_REGISTER_URL=... VERAISON_PROVISION_URL=...` | Verify challenge-response, Update, Success, and app execution with real AttesTAM/Veraison instances |
| OP-TEE scaffold, `platform/trustzone`, TA Secure Storage/random/time/CBOR dry-run smoke, WAMR-in-TA spike regression, TA production runtime migration | `make check-optee-trustzone-smokes`, `make smoke-optee-trustzone`, `make smoke-optee-trustzone-failures` as needed; for spike regressions, `make smoke-optee-trustzone-wamr-spike`, `make smoke-optee-trustzone-wamr-spike-linked`, and `make smoke-optee-trustzone-wamr-spike-negatives`; for production runtime implementation slices, `make smoke-optee-trustzone-execute-helloworld`, `make smoke-optee-trustzone-execute-calcadd`, `make smoke-optee-trustzone-execute-negaposi`, `make smoke-optee-trustzone-execute-hostcall-negative`, `make smoke-optee-trustzone-execute-cleanup-negative`, `make smoke-optee-trustzone-execute-catalog-resource-negative`, `make smoke-optee-trustzone-public-abi-resource-limit-negative`, `make smoke-optee-trustzone-teep-agent-resolve`, `make smoke-optee-trustzone-host-io-resume`, `make smoke-optee-trustzone-host-io-resume-negative`, `make smoke-optee-trustzone-teep-agent-hostcall-http`, `make smoke-optee-trustzone-teep-agent-hostcall-evidence`, `make smoke-optee-trustzone-teep-agent-hostcall-bridge`, `make smoke-optee-trustzone-teep-agent-hostcall-object-negative`, and `make smoke-optee-trustzone-teep-agent-transcript-limits`; for live compatibility, `make smoke-optee-trustzone-attestam-live ATTESTAM_URL=... ATTESTAM_REGISTER_URL=... VERAISON_PROVISION_URL=...` | Statically verify alignment among Makefile targets, guest scenarios, and references in `docs/Testing.md`. On QEMU, verify the TEEC roundtrip, TrustZone diagnostics, protected object provisioning, TA random/time, CBOR memref command shape, failure paths, spike regressions, production WAMR execution in the TA, TEEP_Agent/Catalog resolution in the TA, rejection of general app hostcalls, host I/O resume, the TEEP_Agent hostcall broker, resource/output/cleanup boundaries, and live AttesTAM+Verifier compatibility |
| RISC-V OP-TEE v9 port | `make build-optee-riscv-v9`, then `make smoke-optee-riscv-v9` | Cross-build every normal-world artifact and the TA for RV64 LP64D, package the v9 Buildroot image, then verify OpenSBI/Linux/OP-TEE boot, TA-local WAMR, infinite-loop termination, public ABI v3, `twepd`/`twep-cli`, and absence of kernel panic/Oops/stall diagnostics |
| Rust/Wasm crate | `cargo test`, `cargo clippy`, and Wasm target build/clippy for the target crate | Preserve the `no_std`/Wasm ABI/hostcall boundaries |
| docs-only | `git diff --check`, and `make test` when needed | Avoid formatting drift and broken references |

### RISC-V OP-TEE v9

The RISC-V port expects a sibling `../riscv-optee` checkout whose `buildroot`
link selects v9. Build v9 first so that
`buildroot/output/host/bin/riscv64-buildroot-linux-gnu-*`, the staged libteec
headers/libraries, and `export-ta_rv64` exist. The port script also verifies
the pinned Buildroot and WAMR revisions before using them. Host prerequisites
are Go 1.22 or newer, Rust with `wasm32-unknown-unknown`, WABT `wat2wasm`,
CMake, `expect`, `telnet`, `tmux`, and the tools required by `riscv-optee`.

```sh
make build-optee-riscv-v9
make smoke-optee-riscv-v9
```

Override `RISCV_OPTEE_ROOT`, `RISCV_OPTEE_BUILDROOT`,
`RISCV_OPTEE_WAMR_DIR`, or `RISCV_OPTEE_OUT` for a non-sibling layout. The
build produces `build/riscv-optee-v9/SHA256SUMS` and updates the v9
`buildroot/output/images/sdcard.img`. The smoke log is written to
`build/riscv-optee-v9/qemu-smoke.log` and must end with
`TWEP_RISCV_OPTEE_V9_SMOKE_PASS`.

The test deliberately executes an infinite-loop Wasm module. It passes only
when TA-side WAMR instruction metering terminates the module before the
independent 180-second guest watchdog. Catalog `timeout_ms`, the configured
default, and a shorter request timeout use the same 100,000-instructions per
millisecond conversion as the Linux backend; this is a deterministic resource
budget, not a wall-clock deadline. The architecture-neutral focused entry
point is `make smoke-optee-trustzone-execute-timeout-negative`.

### M10 checkpoint

Representative verification of the TrustZone production path consists only of the existing individual smoke tests. Use the following command to run them together.

```sh
make m10-trustzone-checkpoint \
  ATTESTAM_URL=http://10.0.2.2:8080/tam \
  ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest \
  VERAISON_PROVISION_URL=https://localhost:9443/endorsement-provisioning/v1/submit
```

This aggregate has no new guest scenario and runs the following existing targets in order.

| Representative Scope | Existing Target |
| --- | --- |
| baseline/failures | `make smoke-optee-trustzone`, `make smoke-optee-trustzone-failures` |
| public C ABI success | `make smoke-optee-trustzone-public-abi-execute-helloworld`, `make smoke-optee-trustzone-public-abi-execute-calcadd`, `make smoke-optee-trustzone-public-abi-execute-negaposi` |
| hostcall negative | `make smoke-optee-trustzone-execute-hostcall-negative` |
| host I/O resume | `make smoke-optee-trustzone-host-io-resume` |
| TEEP_Agent hostcall bridge | `make smoke-optee-trustzone-teep-agent-hostcall-bridge` |
| AttesTAM live bridge | `make smoke-optee-trustzone-attestam-live ATTESTAM_URL=... ATTESTAM_REGISTER_URL=... VERAISON_PROVISION_URL=...` |

The M10 checkpoint is a representative regression test for the production path, not a full exhaustive suite. When the relevant slice changes, additionally run the individual targets for resource/output/cleanup, wrapped errors, hash/catalog negatives, host I/O negatives, object ID negatives, and WAMR spike regressions. From D038 onward, the permanent OP-TEE configuration policy is `CFG_REE_FS=y` and `CFG_RPMB_FS=n`, and REE FS Secure Storage is treated as the secure storage for the TrustZone final path. `sealed-storage-rollback-protected=false` is diagnostic information and by itself is not grounds for `trust-anchor-bound=false` or `final-verified=false`.

### TrustZone Verification Path Mapping

`optee/twep-wr-ta/README.md` and `optee/twep-wr-ta/ARCHITECTURE.md` divide TrustZone verification into the Production public path, Direct TA smoke path, and WAMR spike path. Use the following mapping when selecting make targets.

| Path | Primary make Targets | Boundary Verified |
| --- | --- | --- |
| Production public path: `twep-cli`/`twepd` -> cgo -> `libtwep_wr.so` -> `libteec` -> TA | `make smoke-optee-trustzone-attestam-live ATTESTAM_URL=... ATTESTAM_REGISTER_URL=... VERAISON_PROVISION_URL=...` | The user-facing path from the TrustZone backend versions of `twepd`/`twep-cli` in the guest to the TEEP_Agent in the TA, Catalog resolution, and app execution. The REE callback handles HTTP bytes; the Rust TEEP_Agent generates Generic EAT Evidence internally and keeps trust decisions in the TA |
| Public C ABI TrustZone path: C caller -> `libtwep_wr.so` -> `libteec` -> TA | `make smoke-optee-trustzone-public-abi-wrapped-error-negative`, `make smoke-optee-trustzone-public-abi-app-hash-negative`, `make smoke-optee-trustzone-public-abi-resource-limit-negative`, `make smoke-optee-trustzone-public-abi-execute-helloworld`, `make smoke-optee-trustzone-public-abi-execute-calcadd`, `make smoke-optee-trustzone-public-abi-execute-negaposi` | Without going through `twepd`, public C ABI v3 `twep_wr_execute` marshals to the TrustZone backend and returns success/error responses as owned CBOR bytes |
| TA production private command path: smoke client -> `libteec` -> TA `INIT`/`EXECUTE`/`RESUME_HOST_IO` | `make smoke-optee-trustzone-execute-abi-negative`, `make smoke-optee-trustzone-execute-helloworld`, `make smoke-optee-trustzone-execute-calcadd`, `make smoke-optee-trustzone-execute-negaposi`, `make smoke-optee-trustzone-execute-hostcall-negative`, `make smoke-optee-trustzone-execute-cleanup-negative`, `make smoke-optee-trustzone-execute-catalog-resource-negative`, `make smoke-optee-trustzone-teep-agent-resolve`, `make smoke-optee-trustzone-teep-agent-signature-negative`, `make smoke-optee-trustzone-teep-agent-resolve-hash-negative`, `make smoke-optee-trustzone-teep-agent-resolve-catalog-negative`, `make smoke-optee-trustzone-teep-agent-resolve-wrapped-error-negative`, `make smoke-optee-trustzone-host-io-resume`, `make smoke-optee-trustzone-host-io-resume-negative`, `make smoke-optee-trustzone-sha256-boundary-negative`, `make smoke-optee-trustzone-teep-agent-hostcall-http`, `make smoke-optee-trustzone-teep-agent-hostcall-evidence`, `make smoke-optee-trustzone-teep-agent-hostcall-bridge`, `make smoke-optee-trustzone-teep-agent-hostcall-object-negative` | TA private command ABI, TA-local WAMR production runtime, role-specific TEEP Agent signature verification, TA-local TEEP_Agent, Catalog/app trust decisions, host I/O resume, rejection of general app hostcalls, and resource/output/cleanup boundaries |
| Direct TA smoke path: `optee_example_twep_wr_ta` -> `libteec` -> TA smoke commands | `make smoke-optee-trustzone`, `make smoke-optee-trustzone-failures` | TEEC session, TA command dispatch, Secure Storage PUT/GET, random/time, CBOR dry-run, diagnostics, and protected object provisioning/failure. This is not the public `twepd` path |
| WAMR spike path: `TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC` | `make smoke-optee-trustzone-wamr-spike`, `make smoke-optee-trustzone-wamr-spike-linked`, `make smoke-optee-trustzone-wamr-spike-linked-negative`, `make smoke-optee-trustzone-wamr-spike-input-negative`, `make smoke-optee-trustzone-wamr-spike-output-negative`, `make smoke-optee-trustzone-wamr-spike-cleanup-negative`, `make smoke-optee-trustzone-wamr-spike-negatives` | Historical WAMR-in-TA feasibility spike and negative regressions. This is a separate path from Catalog resolution, TEEP_Agent, `calcadd`, `negaposi`, host I/O resume, and public `twep_wr_execute` |

On every path, smoke-test success alone is not grounds for `final-verified=true`. TrustZone smoke tests observe `sealed-storage-security=tee-ree-fs-secure-storage` and `sealed-storage-rollback-protected=false`. From D038 onward, `sealed-storage-rollback-protected=false` is not a blocker. The current D045/M9.3 targets use publicly embedded fixed development credentials and must retain `final-verified=false`. A future production-positive target may expect `trust-anchor-bound=true` and `final-verified=true` only after combining TEEP/COSE/SUIT verification, credential/policy object consistency, AttesTAM acceptance through a TAM-signed Update with current D043 acceptance generation, TEEP_Agent identity binding, and non-forgeable production credentials.

`optee/twep-wr-ta/README.md` is authoritative for the standard TrustZone smoke procedure and expected strings. Use `make smoke-optee-trustzone` as the standard success entry point and `make smoke-optee-trustzone-failures` as the standard failure entry point. Retain the WAMR-in-TA spike for regression testing, with separate entry points: `make smoke-optee-trustzone-wamr-spike` verifies the default unlinked blocker, `make smoke-optee-trustzone-wamr-spike-linked` verifies explicit opt-in linked execution, and `make smoke-optee-trustzone-wamr-spike-negatives` verifies negative regressions. For individual debugging, retain `make smoke-optee-trustzone-wamr-spike-linked-negative` for rejection of unregistered hostcall imports, `make smoke-optee-trustzone-wamr-spike-input-negative` for rejection at the app input boundary, `make smoke-optee-trustzone-wamr-spike-output-negative` for rejection at the app output boundary, and `make smoke-optee-trustzone-wamr-spike-cleanup-negative` for cleanup after abnormal termination. The spike command runs only `helloworld.wasm` in the WAMR interpreter inside the TA and validates the returned app output as a CBOR map. Do not extend the spike command to Catalog resolution, TEEP_Agent execution, hostcall resume, `calcadd`, or `negaposi`; cover them with smoke tests for the production `INIT`/`EXECUTE`/`RESUME_HOST_IO` commands.

In the TA production runtime migration slice, first use `make smoke-optee-trustzone-execute-abi-negative` to fix the command IDs for `INIT`, `EXECUTE`, and `RESUME_HOST_IO`, CBOR envelope parsing, short output buffers, malformed envelopes, and unsupported TA commands. Then add `make smoke-optee-trustzone-execute-helloworld` as the minimum entry point and verify that `helloworld` returns, through `TA_TWEP_WR_CMD_EXECUTE`, a CBOR response with the same schema as the existing `twep_wr_execute` response. In subsequent slices, add `make smoke-optee-trustzone-execute-calcadd`, `make smoke-optee-trustzone-execute-negaposi`, `make smoke-optee-trustzone-execute-hostcall-negative`, `make smoke-optee-trustzone-execute-cleanup-negative`, `make smoke-optee-trustzone-execute-catalog-resource-negative`, and `make smoke-optee-trustzone-teep-agent-resolve` to verify Catalog lookup in the TA, TC/app classification, payload hash verification, application of Catalog resource limits, `calcadd 3 4 5`, the `files.output` bytes from the JPEG version of `negaposi`, rejection of `env.*`/`twep_teep_env.*` imports by general apps, and TEEP_Agent hostcall resume. Negative smoke tests also cover rejection of bad object IDs, short output buffers, oversized output, and cleanup after traps.

`make smoke-optee-trustzone-execute-cleanup-negative` uses a minimal Wasm fixture with `twep_app_abi_version` for the production app runtime and verifies that `helloworld.wasm` can run again in the same TA session after rejecting a short output buffer, nonzero app status, oversized app output, or trap. This is not a spike regression; it fixes the module, instance, exec_env, and app allocation cleanup boundaries of the `TA_TWEP_WR_CMD_EXECUTE` production path.

`make smoke-optee-trustzone-execute-catalog-resource-negative` verifies that the TA production app runtime applies `resource_limits.max_output_bytes` from the TEEP_Agent resolve output inside the TA. The smoke harness does not interpret the Catalog trust decision in the REE; it transports a fixture in which only the `negaposi` entry in the existing Catalog bytes has a small `max_output_bytes`. The TA reads the resource limits from the TEEP_Agent Wasm resolve output, clamps them to the TA limit, and rejects the `negaposi.wasm` app output with an `app.resource_limit` error response. `make smoke-optee-trustzone-public-abi-resource-limit-negative` verifies that the same rejection is returned from public C ABI `twep_wr_execute` as `TWEP_WR_OK` with owned CBOR bytes and can be observed as `status="error"`, `error.code="app.resource_limit"`, and `error.details.source="app-runtime"`.

The current `make smoke-optee-trustzone-teep-agent-resolve` slice is the minimum execution check for the TEEP_Agent runtime entry point inside the TA. The REE only transports `teep-agent.wasm`, Catalog bytes, `helloworld.wasm`, and `resolve_app` request bytes; the test verifies that the TA runs `teep-agent.wasm` in TA-local WAMR and returns a `resolve-app`-shaped CBOR response. At this stage, TA hostcalls are limited to `catalog/catalog.cbor`, `apps/helloworld.wasm`, and `tmp/teep-agent-probe`; HTTP, Evidence, general-purpose object storage, app promotion, and `final-verified=true` are not yet performed.

`make smoke-optee-trustzone-teep-agent-signature-negative` changes one byte of the 64-byte signature in the final `twep.sig` section while preserving the signed Wasm prefix and CBOR structure, then separately supplies a valid `role="app"` module in the TEEP Agent position. It verifies that both cryptographic mismatch and role mismatch return `TEE_ERROR_SECURITY` before WAMR initialization, privileged native-hostcall registration, or module loading.

`make smoke-optee-trustzone-host-io-resume` verifies the TA private ABI round trip for `need_host_io`/`RESUME_HOST_IO`. The TA retains a pending I/O transcript in the session and returns an `http_post` request through `need_host_io`. The REE smoke test acts as a byte broker and returns only the result CBOR; the TA validates `request_id`, `io_id`, kind, and status, then returns `final_response_cbor`. This slice does not yet suspend and resume WAMR execution; it fixes the resume envelope boundary for HTTP and the legacy diagnostic Evidence hostcall without making either an arbitrarily executable REE decision.

`make smoke-optee-trustzone-host-io-resume-negative` verifies rejection of no pending request, mismatched `request_id`, mismatched `io_id`, mismatched kind, nonzero status, mismatched sequence, mismatched request body digest, and mismatched normalized input digest against the same pending I/O transcript. After a failure, drain the pending transcript with a correct resume and also verify that negative smoke cases do not contaminate one another's state within the same TA session.

`make smoke-optee-trustzone-sha256-boundary-negative` statically verifies that SHA-256 use in TA C code is limited to host I/O transcript binding and that payload/app hash verification for Catalog/app trust decisions has not been reintroduced into TA C code. This negative smoke test fixes the policy that trust hash verification for Catalog entries, SUIT payloads, and app binaries is centralized in TEEP_Agent Wasm.

`make smoke-optee-trustzone-teep-agent-resolve-hash-negative` intentionally mismatches the hash expected by the Catalog for `helloworld.wasm` and the app bytes transported to the TA, and verifies that TEEP_Agent Wasm running inside the TA returns `app.hash_mismatch`. This fixes the boundary where the TA production path maps the TEEP_Agent Wasm Catalog/app trust decision to execution rejection, rather than having TA C code decide the app hash.

`make smoke-optee-trustzone-teep-agent-resolve-catalog-negative` verifies that TEEP_Agent Wasm returns `catalog.invalid` when the Catalog bytes transported to the TA are not a Catalog map, and `catalog.not_found` when the requested target command is absent from the Catalog. TA C code does not interpret the Catalog schema or lookup as a trust decision; it transports the TEEP_Agent Wasm error output as the production path's rejection result.

`make smoke-optee-trustzone-teep-agent-resolve-wrapped-error-negative` verifies that the TA production path can map `catalog.invalid`, `catalog.not_found`, and `app.hash_mismatch` returned by TEEP_Agent Wasm inside the TA to `status="error"`, `exit_code=1`, `error.code`, `error.message`, and `error.details.source="teep-agent"` in the existing `twep_wr_execute` response schema. The REE host smoke receives output from `TA_TWEP_WR_CMD_EXECUTE` as transport-owned bytes and inspects it directly as a public `twep_wr_execute`-compatible response. `make smoke-optee-trustzone-public-abi-wrapped-error-negative` is the minimum connection slice that enters the same TA `EXECUTE` path through public C ABI `twep_wr_execute` in the TrustZone build and inspects the `catalog.not_found` wrapped error returned as `twep_wr_owned_bytes_t`. `make smoke-optee-trustzone-public-abi-app-hash-negative` corrupts the app Wasm bytes in the REE cache for a normal public C ABI app command and inspects the `app.hash_mismatch` returned by the TEEP_Agent inside the TA as a `twep_wr_execute`-compatible wrapped error response. `make smoke-optee-trustzone-public-abi-execute-helloworld` verifies that the same public C ABI transport carries `teep-agent.wasm`, Catalog bytes, and `helloworld.wasm` bytes from the REE cache to the TA and returns a production WAMR success response from inside the TA after successful TEEP_Agent Catalog resolution there. `make smoke-optee-trustzone-public-abi-execute-calcadd` uses the same TEEP_Agent resolution inside the TA through the public C ABI and inspects a production WAMR success response from inside the TA containing `stdout="12\n"` and `result.sum=12`, derived from `calcadd.wasm` and `inferred_params` CBOR. `make smoke-optee-trustzone-public-abi-execute-negaposi` reads the JPEG input path on the REE side while passing only CBOR containing `files.input` bytes to the TA, then saves and inspects at the REE output path the `files.output` JPEG bytes returned by production WAMR inside the TA after TEEP_Agent resolution there. The REE broker does not interpret the Catalog, and user-facing error responses are constructed from TEEP_Agent output inside the TA.

`make smoke-optee-trustzone-teep-agent-hostcall-http` is the minimum check that places an `http_post` request from the TEEP_Agent hostcall broker on the same `need_host_io`/`RESUME_HOST_IO` boundary. The TA retains the `teep-http-1` transcript, and the REE only transports response bytes rather than performing actual HTTP communication. This slice also does not yet suspend and resume the actual WAMR call frame.

`make smoke-optee-trustzone-teep-agent-hostcall-evidence` is the ABI diagnostic check that places a legacy `create_evidence` request from the TEEP_Agent hostcall probe on the same boundary. The TA retains the `teep-evidence-1` transcript containing the challenge and agent public key bytes, and the REE transports the diagnostic result bytes. Normal sessions generate Generic EAT inside the Rust TEEP_Agent and must not emit this continuation; this diagnostic slice also does not suspend and resume an actual WAMR call frame.

`make smoke-optee-trustzone-teep-agent-hostcall-bridge` is the ABI diagnostic check that creates pending `http_post` and legacy `create_evidence` transcripts from native hostcalls by `teep-agent.wasm` running in WAMR inside the TA and converts them to the same `need_host_io`/`RESUME_HOST_IO` boundary. These are explicit diagnostic commands rather than the normal session flow; the check verifies hostcall triggering and broker envelope construction without performing actual HTTP, normal Generic EAT generation, or Catalog promotion.

`make smoke-optee-trustzone-teep-agent-hostcall-object-negative` passes invalid object IDs from diagnostic commands in `teep-agent.wasm` running under WAMR inside the TA to the `read_file`/`write_file` hostcalls and verifies that the TA rejects arbitrary paths and unauthorized object IDs. It also invokes the public REE Secure Storage GET and PUT commands directly. The target must prove that neither surface can publish `verified-evidence-result.cbor` or overwrite the D043 state, that no generic path can write the logical Catalog or directly read/write either physical D047 slot, and that public REE GET cannot read the logical Catalog. The dedicated D043 and Catalog commit hostcalls are the sole live publication boundaries; the TEEP_Agent's permitted `read_file("catalog/catalog.cbor")` resolves only the D043-selected active protected Catalog. In the current slice, ordinary probe object IDs are limited to `catalog/catalog.cbor`, `apps/helloworld.wasm`, and `tmp/teep-agent-probe`. Malformed/current/stale acceptance-state diagnostics use the compile-guarded M9.1H test interface; production GET/PUT never becomes a D043 or D047 bypass.

`make smoke-optee-trustzone-attestam-live` provisions the Veraison Generic EAT CoRIM fixture and registers the `helloworld` SUIT manifest with AttesTAM on the host, then runs the TrustZone backend versions of `twepd`/`twep-cli` in the QEMU guest. The default URL for reaching host AttesTAM from the guest is `http://10.0.2.2:8080/tam`. Because `prepare-diagnose-smoke.sh` copies the same host build artifacts, `build/teep-agent.wasm`, `build/helloworld.wasm`, `build/calcadd.wasm`, and `build/negaposi.wasm`, into guest input, record `sha256sum build/teep-agent.wasm build/helloworld.wasm build/calcadd.wasm build/negaposi.wasm` before or after Linux-live and TrustZone-live compatibility verification. This existing target intentionally uses `attestam-insecure`, so it must expect `trust-anchor-bound=false` and `final-verified=false` even after success.

`make smoke-optee-trustzone-attestam-verified-acceptance` is the positive acceptance-only target. It builds and signs `build/teep-agent-m9-1-smoke.wasm` with the private Cargo feature `m9-1-acceptance-only-smoke`; this artifact exists only to reproduce the historical M9.1 boundary, while the default `build/teep-agent.wasm` implements M9.3. With real host AttesTAM and Veraison, the target runs TrustZone `attestam-verified` using the fixed D045 development signers, requires a TAM-signed app Update from the live Evidence challenge-response, verifies that D043 is current after a single commit, and then expects `teep.verified_required`. It must also prove that Success, staged payload, Catalog/app files, and application execution remain absent and that `final-verified=false`. This target does not substitute for Catalog or application installation tests and the smoke-only artifact must not be deployed as the production/default TEEP Agent.

`make smoke-optee-trustzone-attestam-verified-catalog` is the live Catalog target. With real host AttesTAM and Veraison, it registers the exact default `twep-catalog-v1` TC, commits the accepted Catalog into protected inactive-slot state, sends the signed Success only after commit, and still returns `teep.verified_required` with `final-verified=false` and no app execution or REE Catalog mirror. A hook-enabled, non-mutating fresh-session probe verifies live Catalog restart/readback; the same target then runs deterministic inactive-slot update, equal-sequence/different-payload rejection, replay, pre-publication fault, D043-publication fault, and later non-Catalog preservation checks. The target removes hook-enabled host and TA artifacts on exit and does not authorize application installation. Use a fresh AttesTAM development database, or a Catalog sequence greater than the retained registration, so prior replay state is not mistaken for a new candidate.

`make smoke-optee-trustzone-attestam-verified-app` is the M9.3 live academic-reference target. With real host AttesTAM and Veraison, it registers the default Catalog containing the standard app entries and the `helloworld` app TC. The first invocation protects the Catalog and returns `teep.verified_required`; the second obtains, authorizes, protects, reloads, and executes `helloworld`. The current AttesTAM normally recognizes the already accepted agent in that second session and returns the app Update directly after the component-list QueryResponse, so the test also verifies reuse of the current protected acceptance generation with fresh session tokens and transcript binding. A third invocation starts fresh host processes with an unreachable TAM URL and proves that the protected Catalog and app can execute offline. It also verifies that no REE Catalog or app mirror was created and that diagnostics retain `final-verified=false`. Use a fresh disposable AttesTAM database because component sequence freshness is persistent.

The RISC-V v9 equivalents are `make smoke-optee-riscv-v9-attestam-live`, `make smoke-optee-riscv-v9-attestam-verified-catalog`, and `make smoke-optee-riscv-v9-attestam-verified-app`. They run the same guest smoke modes against host AttesTAM/Veraison through `ATTESTAM_URL` (normally `http://10.0.2.2:8080/tam`), check the Linux kernel for panic/Oops/stall signatures, and power off QEMU cleanly. The Catalog target cross-builds with `TWEP_TA_D043_TEST_HOOKS=1`; the normal build and app target default it back to zero. Registration and CoRIM provisioning remain explicit prerequisites so test databases and component sequences cannot be silently reused.

For live Generic EAT, QueryResponse option 12 must identify `application/eat+cwt; eat_profile="urn:ietf:rfc:rfc9711"`. The compatible AttesTAM Veraison client derives the new-session nonce from the submitted Evidence. Unit coverage must reject regressions to a fixed Veraison nonce while preserving the historical fallback only for evidence formats whose claims AttesTAM cannot decode locally.

For D046, unit tests and the live target must distinguish two contracts. Fixed-input Linux dry-run fixtures require the expected token file to byte-match the Update token. The live AttesTAM path requires a non-empty bounded initial QueryRequest token and a non-empty bounded immediate-Update token, permits them to differ, and relies on the ordered continuation plus the exact D043-consumed Evidence QueryResponse transcript for session binding. Empty or oversized tokens, an Update outside the Evidence continuation, a missing pending transcript, or a failed D043 commit must not publish a positive result.

In TrustZone production diagnostics, expect `runtime-location=trustzone-ta`, `teep-agent-location=trustzone-ta`, and `catalog-resolution-location=trustzone-ta` only on paths moved to TA execution. However, OP-TEE Secure Storage smoke, random/time smoke, CBOR dry-run, the WAMR spike, and successful TA-local production WAMR execution must never individually serve as grounds for trust-anchor binding. Every TrustZone smoke test retains `sealed-storage-security=tee-ree-fs-secure-storage` and `sealed-storage-rollback-protected=false`. The latter is diagnostic information, not a blocker.
For successful TrustZone smoke tests, no-kid diagnostics provisioned with only protected objects expect `protected-credential-store-issuer-allowlist-match=false`, `protected-store-freshness-epoch-match=true`, and `protected-revocation-state-match=true`; without an observed matching AttesTAM `kid`, the credential store and issuer allowlist remain unbound. Under the implemented D038 policy, matched policy objects on TrustZone REE FS Secure Storage can advance to `bound`, while the Linux backend remains observation-only. Subsequent diagnostics with verified input expect `protected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound` and `protected-credential-store-bound=true` when the observed AttesTAM `kid` matches a protected credential store entry. A matching issuer allowlist additionally yields `protected-credential-store-issuer-allowlist-match=true`, `protected-store-freshness-epoch-match=true`, `protected-revocation-state-match=true`, and `issuer-allowlist-bound=true`. These individual bindings are necessary but not sufficient for final verification; the live TAM-signed Update, current D043 acceptance generation, and TEEP_Agent identity must also bind in the formal verified session.
In the same TrustZone smoke test, when the observed AttesTAM `kid` matches a protected credential store entry but that entry's `issuer_id` is absent from the issuer allowlist, expect `protected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound`, `protected-credential-store-issuer-allowlist-match=false`, `protected-credential-store-bound=true`, and `issuer-allowlist-bound=false`. This verifies credential selection and issuer-policy binding as separate conditions.

## Go Tests

### cborcodec

- request encode/decode roundtrip
- response encode/decode roundtrip
- handling of unknown fields
- rejection of malformed CBOR
- rejection of oversized payloads

### cliargs

- `helloworld`
- `calcadd 3 4 5`
- `calcadd -1 2`
- `negaposi -i image.jpg -o output.jpg`
- `--cbor-hex`
- `--cbor-file`

### ipc

- frame encode/decode
- partial read
- invalid length
- maximum size exceeded
- error when the daemon is not running

### daemon

- request validation
- command not found
- twep-wr error mapping
- response construction

## C Tests

- `twep_wr_get_abi_version` returns 3.
- Invalid config returns `TWEP_WR_ERR_INVALID_ARGUMENT`.
- init/shutdown can be run multiple times.
- execute returns a CBOR response.
- Owned bytes can be freed.
- Null pointers are rejected safely.

After introducing WAMR:

- Valid Wasm can be loaded.
- ABI version mismatches are detected.
- Missing exports are detected.
- An app error code is converted to a host error.
- Apps that exceed the output size limit are rejected.
- `timeout_ms` is converted to instruction metering, deterministically stopping infinite-loop Wasm.

## Rust/Wasm Tests

Unit tests within Rust crates may use the std feature. However, the Wasm build target must remain `no_std`. When adding or changing dependencies in a Wasm implementation, use a `wasm32-unknown-unknown` build and clippy to confirm that no crate requiring `std` has been introduced. Before adopting a crate that requires `std`, explicitly document the exception and its rationale in the relevant authoritative specification.

### helloworld

- Return `Hello, World!!` for empty input.
- Error for an invalid schema_version.

### calcadd

- Return `12` for `[3,4,5]`.
- Handling of an empty array.
- Handling of non-int values.
- Error on overflow.

### negaposi

- Decode, color inversion, and encode of a small JPEG fixture.
- Reject non-JPEG formats with an unsupported-format error.
- Error for corrupt JPEG input.
- Generate output JPEG bytes.
- Return `metadata.output_mime="image/jpeg"`.

## E2E Tests

### e2e-helloworld

```sh
state="$(mktemp -d)"
sock="$state/twepd.sock"
./bin/twepd --socket "$sock" --state-dir "$state" --once &
./bin/twep-cli --socket "$sock" helloworld
```

Expected:

```text
Hello, World!!
```

### e2e-calcadd

```sh
./bin/twepd --socket "$sock" --state-dir "$state" --once &
./bin/twep-cli --socket "$sock" calcadd 3 4 5
./bin/twepd --socket "$sock" --state-dir "$state" --once &
./bin/twep-cli --socket "$sock" calcadd 3 4 5 6 7
./bin/twepd --socket "$sock" --state-dir "$state" --once &
./bin/twep-cli --socket "$sock" calcadd 3
```

Expected:

```text
12
25
3
```

### e2e-negaposi

```sh
./bin/twepd --socket "$sock" --state-dir "$state" --once &
./bin/twep-cli --socket "$sock" negaposi -i testdata/images/input.jpg -o /tmp/twep-output.jpg
```

Expected:

- exit code 0
- `/tmp/twep-output.jpg` exists
- The output can be decoded as JPEG
- Pixel values are inverted
- Specifying a non-JPEG input file produces an unsupported-format error

## Security Tests

### path traversal

- Reject a catalog `wasm_file` of `../evil.wasm`.
- Reject absolute paths.
- Reject paths containing a NUL byte.

### hash mismatch

- Modify one byte of a Wasm file and verify that execution is rejected.

### UDS permission

- The socket directory permission is `0700`.
- After listening, the default socket has socket file mode `0600`.
- For a custom socket path, the parent directory is owned by the current user, and startup is rejected if it is group/world writable.
- When deployed as a system service, connections from outside the group are prohibited.

### Resolver Mode and Insecure Mode

- `resolver.mode="mock"` can install from local testdata.
- AttesTAM demo can be contacted only with `resolver.mode="attestam-insecure"` and `insecure_demo_mode=true`.
- With `resolver.mode="attestam-insecure"` and `insecure_demo_mode=false`, reject the TEEP_Agent `http_post`.
- If the AttesTAM endpoint cannot be reached with `resolver.mode="attestam-insecure"` and `insecure_demo_mode=true`, the user-facing error code is `teep.network`.
- Permit `twepd --insecure-demo-agent-key alternate` only with `attestam-insecure` and `insecure_demo_mode=true`, and use a signing key that does not match the real AttesTAM default demo agent key registration. Through fixture tests and `make smoke-attestam-challenge-observe ATTESTAM_URL=...`, verify that a QueryRequest with a challenge is observed as the second response after a QueryRequest with a token, and that a QueryResponse containing mock EAT Evidence can be sent in the third POST.
- With the Milestone 8 fixture HTTP server, verify that the TEEP_Agent sends an empty-body POST and the TEEP_Broker adds `Accept: application/teep+cbor` and `Content-Type: application/teep+cbor`.
- When the fixture HTTP server returns a COSE_Sign1 TEEP response body containing a QueryRequest payload, save the raw response, payload, and message type to state. Generate the SUIT Component Identifier `[ bstr("twep-app-v1"), bstr(command) ]` from the target command, sign the QueryResponse payload with COSE_Sign1 inside the Rust TEEP_Agent, and perform a second POST. If the second POST returns an Update, save the raw body, payload, message type, first `manifest-list` element, manifest count, and component ID in the SUIT manifest to state. If the requested component identifier does not match the component identifier in the Update, do not proceed to payload staging, Success POST, TC artifact installation, or app catalog promotion.
- With the fixture HTTP server prepared for Milestone 9, when it returns a Wasm payload Update whose SUIT Component Identifier matches the requested value, verify that the hash-verified payload is promoted to `apps/remotehello.wasm` and the Catalog File even without development-only `twep-app-v1-metadata`, and that `twep-cli remotehello` returns `Hello, World!!` through the existing WAMR execution path.
- Even when `twep-app-v1-metadata` is present, do not use it as the basis for classification or path derivation. Reject component identifier mismatches and payload hash mismatches with `teep.protocol`, leaving no target app in the `apps/` cache or Catalog File.
- The TEEP_Agent `write_file` renames through `<path>.tmp` on the host side. In E2E tests, verify that `apps/remotehello.wasm.tmp` and `catalog/catalog.cbor.tmp` do not remain after promotion.
- `tc-inventory` displays metadata for a successfully installed supported App or Catalog from `components/install-metadata.cbor`, `components/install-status.txt`, and the relative `payload_file` named by the metadata. Return `tc.inventory_empty` when metadata is absent, including after an unsupported or mismatched Update, and reject cases where `payload_file` escapes state, `payload_sha256` is not 32 bytes, or the actual payload SHA-256 does not match the metadata.
- `tc-inventory --output-format cbor` returns a machine-readable CBOR map to stdout. Unit tests decode it with `fxamacker/cbor` and verify `schema_version`, `component_id_cbor`, `payload_uri`, `payload_file`, `payload_sha256`, `payload_hash_status`, `status`, and `size`.
- Implement actual HTTP communication through TEEP_Broker callbacks. C-side `twep-wr` is responsible only for resolver mode, `insecure_demo_mode`, allowed-URL policy checks, and buffer copying. Catalog lookup and app-file SHA-256 verification occur in the TEEP_Agent inside the TEE; the C-side pre-load hash check is a defensive recheck for race detection.
- Use `make e2e-attestam-insecure` to verify the same path through the fixture HTTP server and real `twepd` and `twep-cli` processes.
- Use `make register-attestam-remotehello-fixture ATTESTAM_REGISTER_URL=...` to verify that a `twep-app-v1` SUIT Envelope can be registered with a real AttesTAM demo endpoint.
- Use `make smoke-attestam-insecure ATTESTAM_URL=...` or manual `twep-cli remotehello` to verify HTTP communication with a real AttesTAM demo endpoint, receipt of Update, Success POST, and Wasm app installation/execution.
- See `docs/AttesTAM.md` for how to start the local AttesTAM repository and precautions for TEEP payload processing.
- For a real Verifier smoke test of AttesTAM challenge-response, use the local Veraison checkout and native deployment under the user's home directory as the Verifier. See `docs/AttesTAM.md` for Veraison startup, endpoints, and Generic EAT trust anchor/endorsement provisioning. With the Generic EAT plugin active, observe that the twep mock EAT reaches the Verifier and, when no trust anchor is registered, proceeds to EAR `contraindicated` and `no trust anchor for evidence`. To use the development Generic EAT fixture, generate CoRIM CBOR with `make veraison-generic-eat-corim`, register it with Veraison using `make provision-veraison-generic-eat-fixture`, and then run `make smoke-attestam-challenge-observe ATTESTAM_URL=http://localhost:8080/tam`. Unit tests fix TEEP message COSE and SUIT-related signatures to ESP256, and EAT Evidence COSE to ES256 for the Veraison Generic EAT verifier. When the `helloworld` SUIT manifest has been registered with AttesTAM using `make register-attestam-helloworld-fixture ATTESTAM_REGISTER_URL=http://localhost:8080/SUITManifestService/RegisterManifest`, verify the complete path after challenge-response through Update, Success POST, promotion of `apps/helloworld.wasm` and the Catalog, and `Hello, World!!` output from `twep-cli helloworld`. In environments where external AttesTAM/Veraison instances are running, automatically run the same vertical slice with `make e2e-attestam-live ATTESTAM_URL=... ATTESTAM_REGISTER_URL=... VERAISON_PROVISION_URL=...`. This live test skips when URL environment variables are unset; when set, it verifies CoRIM provisioning, `helloworld` SUIT manifest registration, challenge-response, Update, Success, and `helloworld` execution.
- With `resolver.mode="attestam-verified"`, reject unverified TEEP/COSE/SUIT bypasses.
- With `resolver.mode="attestam-verified"` on plain Linux, verify that the fixed-input dry-run returns `teep.verified_required` without HTTP/COSE hostcalls or insecure callbacks and leaves Catalog/app/Success state absent. On TrustZone, verify that the D045 live route uses only the exact configured URL, generates Generic EAT with the fixed Evidence signer inside the Rust TEEP_Agent, does not emit a `create_evidence` continuation, and accepts only a TAM-signed immediate Update in the session-owned HTTP continuation. The M9.1 acceptance-only target must leave Catalog/app/Success state absent. The M9.2 target may commit only the exact D047 Catalog TC and send Success after protected readback and D043 publication; it must leave app state absent and retain `final-verified=false`. No backend may promote based on `twep-app-v1-metadata` or an unverified Update. For internal observation, write `fixture-verified=false`, `evidence-affirming=false`, `agent-identity-bound=false`, `trust-anchor-bound=false`, `final-verified=false`, the first missing fixture step, and the missing final step to `teep-agent/verified-state.txt`. The `evidence-affirming` name is retained for compatibility; in the acceptance object it means AttesTAM acceptance proven by a TAM-signed Update, not direct Veraison result verification by TEEP_Agent. `twep-cli diagnose verified --output-format json` structures these as `summary.fixture_verified`, `summary.final_verified`, `summary.missing_step`, `summary.final_missing_step`, and `summary.final_blockers`, and returns in `summary.trust_anchor_blockers` whether the trust anchor is blocked at the credential store, issuer allowlist, store freshness, or revocation state. It returns bound boundaries in `summary.bound` and matched-but-unbound boundaries in `summary.matched_unbound`. It also maps `suit-auth` from `suit-auth-status.txt` to `summary.suit_auth`, and `component-kind`, `component-name`, and `promotion` from `update-component-status.txt` to `summary.update_component.component_kind`, `summary.update_component.component_name`, and `summary.update_component.promotion`, making app TC and Catalog TC dry-run observations and `blocked-final-verified` machine-readable. For platform observation, write the backend name, sealed storage security, protected storage support, and file/random/time support to `teep-agent/platform-status.txt`. For AttesTAM acceptance observation, verify the TAM-signed Update and D043 acceptance generation state; legacy `verified-evidence-result.cbor` and `evidence-status.txt` outputs are compatibility diagnostics and must not imply that TEEP_Agent consumed a Veraison Attestation Result. For TEEP_Agent identity observation, write the backend, runtime location, TEEP_Agent location, sealed storage status, observation source, `protected-agent-identity-load`, and match state against platform status to `teep-agent/agent-identity-status.txt`. Linux remains `agent-identity-binding=matched-unbound` and `agent-identity-bound=false`; on TrustZone, a matching backend/location and `teep-agent.wasm` measurement can advance the identity binding, but it still cannot create a production-positive decision under D045. For credential-management observation, write to `teep-agent/credential-status.txt` that required credentials are defined but unbound; the COSE `kid` extracted from `verified-input.cose`; `attestam-message-verification-key-binding=observed-kid-unbound`, or `observed-kid-entry-unbound` when it matches a development trust anchor entry; load status for development `teep-agent/dev-trust-anchors.cbor`; load status for the formal `teep-agent/protected-credential-store.cbor` fixture; key count by purpose; AttesTAM KID match state; and that issuer binding/rotation/revocation/store freshness are unverified. Observe a development trust anchor file with malformed CBOR as `trust-anchor-load=malformed`, and one with a schema or purpose mismatch as `trust-anchor-load=unsupported`; neither may proceed to final verified. Likewise, only observe malformed CBOR in the formal Protected credential store fixture as `protected-credential-store-load=malformed`, and a purpose/algorithm mismatch as `protected-credential-store-load=unsupported`; do not use either as grounds for Catalog/app promotion. Even when every step equivalent to `fixture-verified=true` is present in the dry-run state file, verify that Success processing and Catalog/app promotion do not proceed while `final-verified=false`.
- Handle `summary.final_blockers` in two stages. When `summary.missing_step` is not `none`, return only the missing fixture step even if the trust anchor, Evidence, TEEP_Agent identity, and credential model are incomplete. Only when `summary.missing_step=none` should final trust deficiencies such as `teep.trust_anchor_unbound`, `teep.evidence_unaffirmed`, and `teep.agent_identity_unbound` be listed.
- Credential/policy objects alone must not produce `trust-anchor-bound=true`. In `wasm/teep-agent` unit tests and `twep-cli diagnose verified --output-format json` tests, verify that even when `protected-credential-store-bound=true`, `issuer-allowlist-bound=true`, `store-freshness-bound=true`, and `revocation-state-bound=true` are all present, if fixture verification, AttesTAM acceptance, or TEEP_Agent identity binding is incomplete, `teep.trust_anchor_bound` is absent from `summary.bound` and `teep.trust_anchor_unbound`, `teep.evidence_unaffirmed`, and `teep.agent_identity_unbound` remain in `final_blockers`.
- For the default M9.3 TrustZone path, verify that a protected Catalog is required before app acquisition, that the app command and exact payload digest match the active Catalog, that one active app record is published only after protected readback, and that execution reloads that record and matches its digest to the resolver result. A fresh process with an unreachable TAM must be able to reuse the protected Catalog and app, while REE Catalog/app mirrors remain absent and `final-verified=false` remains explicit.
- For legacy Evidence observations on Linux, expect compatibility diagnostics only. They must not imply that TEEP_Agent consumed a Veraison result, and they must not advance to `evidence-affirming=true` or `final-verified=true`.
- For the live AttesTAM-derived result, permit the Rust TEEP_Agent to create the compatibility `evidence-affirming=true` state only when the response to its Evidence-bearing QueryResponse is a non-empty TEEP Update, the outer COSE_Sign1 verifies with the provisioned AttesTAM trust anchor in that live challenge-response session, and D043 acceptance generation is current. A later component session may consume a direct signed Update only when that protected result remains current, the new session has its own non-empty bounded rolling tokens, and D043 consumes the exact immediately preceding component-list QueryResponse. Verify that the persisted result identifies this as AttesTAM acceptance rather than direct EAR receipt.
- For D043 one-time consumption, verify that the TA accepts at most one outstanding Evidence transcript per real session context, rejects resume or commit from another session, invalidates it on session close, TA restart, panic, timeout exhaustion, continuation abort, verification failure, or acceptance-write failure, and never restores the exact QueryResponse bytes after restart. Reject zero-manifest and multi-manifest Updates in this tranche. Reject immediate reuse of the same digest and reject A-B-A transcript reuse through strict sequence monotonicity for the mandatory sequence-bearing component.
- Verify the D043 commit boundary with fault injection around inactive-slot create, write, close, and reopen. Failure before a complete higher-generation slot exists must preserve the prior valid slot and must not publish a positive result. When one slot is valid, ignore an incomplete or structurally malformed peer and select the valid slot; fail closed when slots exist but neither is valid, equal highest-generation slots differ, or a complete canonical peer has an unsupported schema version. Include the downgrade case of valid generation N plus unsupported-schema generation N+1. A complete supported higher-generation slot is committed even if the caller observes an ambiguous late failure; the transcript remains consumed. Failure after commit but before positive-result persistence must make any older result stale by generation mismatch and require a fresh challenge. Cover both slots absent, duplicate keys, non-canonical CBOR, state over 4096 bytes, more than 32 components, generation 0 migration, and `UINT64_MAX` overflow. When both slots are absent, malformed or non-canonical legacy state must fail closed; once a valid slot exists, verify that a divergent legacy object is ignored rather than treated as a second authority.
- When both slots are absent and a legacy sequence object exists, verify mandatory import of valid canonical state and fail closed for malformed, non-canonical, oversize, or more-than-32-entry legacy state. Start with an empty generation 0 only when the slots and legacy object are all absent. Verify the 32 KiB per-transcript, two-pending-transcript, and 64 KiB TA-wide limits at and above each boundary; a rejected replacement invalidates that session's old transcript without affecting another session.
- Verify concurrent-session serialization and expected-generation compare-and-commit. A stale commit must fail without changing either slot. If another acceptance advances the generation before an older session writes its positive result, that older result must fail the current-generation read gate. For compatibility v2 parsing, require `acceptance_generation` for `attestam-signed-update` and keep `direct-verifier` non-final-capable.
- `make smoke-optee-trustzone-teep-agent-acceptance` runs the TrustZone `teep-agent-acceptance` smoke using only TEEP_Agent hostcalls and a real session-owned HTTP transcript. It commits generations 1 and 2 in separate resumed executions and verifies that both alternating slots remain readable across the continuation boundary. It is a persistence/ABI probe, not a substitute for D041 COSE and SUIT verification or the dedicated compile-guarded D043 fault target.
- `make smoke-optee-trustzone-teep-agent-acceptance-faults` performs a clean, test-only `TWEP_TA_D043_TEST_HOOKS=1` build and runs the protected-storage fault matrix. The private command accepts only fixed object and one-shot fault selectors; the target removes hook-enabled build artifacts on exit. It covers inactive-slot create/write and ambiguous after-close/reopen failures, positive-result persistence and its stale-generation read gate, continuation allocation cleanup, duplicate-key and non-canonical CBOR, malformed/divergent/unsupported state, size/count limits, legacy migration, and generation overflow. The production Secure Storage PUT and TEEP_Agent file-write boundaries remain unchanged. `make smoke-optee-trustzone-teep-agent-hostcall-object-negative` verifies that the Wasm-side stale-result diagnostic command is rejected by an ordinary build.
- `make smoke-optee-trustzone-teep-agent-two-session-generation` uses the same isolated test build to synchronize two real client sessions from one starting generation. It proves that only session A commits, session B's stale expected generation consumes its transcript without changing the post-A slots/result, and a fresh request advances the next generation.
- `make smoke-optee-trustzone-teep-agent-transcript-limits` verifies D043 pending-state accounting with real concurrent OP-TEE client sessions. It accepts an HTTP transcript of exactly 32 KiB, accepts two pending HTTP transcripts totaling exactly 64 KiB, rejects a third pending transcript and a 32 KiB-plus-one request, excludes `create_evidence` from the HTTP-byte quota, invalidates the old pending transcript when an oversized replacement is rejected, and proves release on accepted resume, a checked terminal verification failure, and session close. Deterministic continuation-save allocation cleanup is covered by `smoke-optee-trustzone-teep-agent-acceptance-faults`, and synchronized two-session stale-generation interleaving is covered by `smoke-optee-trustzone-teep-agent-two-session-generation`.
- Treat HTTP `204 No Content` and empty-body responses only as session outcomes. Verify that they do not create a positive AttesTAM acceptance result object and do not set `tam_response_verified=true`, `challenge_response_bound=true`, or the compatibility `evidence-affirming=true` state. Also reject unsigned or tampered Updates, Updates signed by the wrong TAM key, responses with no outstanding challenge, and replayed or unrelated Updates.
- For TEEP_Agent identity on Linux, expect `agent-identity-binding=matched-unbound` and `agent-identity-bound=false` even when the backend/runtime/TEEP_Agent location in `protected-agent-identity.cbor` matches platform status. On the TrustZone final path, expect `agent-identity-binding=bound` and `agent-identity-bound=true` when the backend/runtime/TEEP_Agent location matches and `measurement_sha256` matches the SHA-256 of `teep-agent.wasm` loaded inside the TA.
- When the observed AttesTAM `kid` matches a formal protected credential store entry on TrustZone REE FS Secure Storage, observe `protected-credential-store-attestam-key-binding=observed-kid-entry-protected-storage-bound`. This is an intermediate state toward `protected-credential-store-bound=true` and alone must not advance to `trust-anchor-bound=true` or `final-verified=true`.
- When store freshness and revocation state match on TrustZone REE FS Secure Storage, expect `protected-credential-store-freshness=bound`, `protected-credential-store-revocation-status=bound`, `store-freshness-bound=true`, and `revocation-state-bound=true`. The same matches on Linux remain `matched-unbound`. Neither backend may promote these individual policy results to a positive final decision without the other formal gates.
- Initial final verified mode does not self-update TEEP_Agent Wasm through AttesTAM. Treat measurement or pinning of TEEP_Agent Wasm as a platform root-of-trust prerequisite, and verify that no path updates the TEEP_Agent itself in the same TEEP session.
- In `make e2e-attestam-insecure`, verify through real `twepd` and `twep-cli` processes that the `attestam-verified` dry-run stops with `teep.verified_required` and does not generate `last-teep-response.cose`, `success.cose`, `tmp/update-payload-0.bin`, `apps/remotehello.wasm`, or Catalog promotion.
- In the same E2E target, when an Update signed with the demo TAM key is placed in `teep-agent/verified-input.cose`, verify that even if outer COSE, session token, SUIT auth, sequence freshness, and payload hash are observed as successful, an unbound formal trust anchor causes processing to stop with `teep.verified_required` without generating a Success POST, payload staging, app cache, or Catalog promotion.
- In the same E2E target, verify both positive and replay dry-runs with `protected-sequence-freshness.cbor` in the `platform/linux` sealed-object mapping. For an Update greater than the last sequence, expect `sequence-fresh=true`, `missing-step=none`, and `promotion=blocked-final-verified`; for a replay with the same sequence, expect `sequence-fresh=false`, `missing-step=teep.sequence_unverified`, and `summary.final_blockers=["teep.sequence_unverified"]`. Run both without the `teep-agent/dev-sequence-freshness.cbor` fallback and verify that `protected-sequence-freshness.cbor` is preserved byte for byte, fallback `dev-sequence-freshness.cbor` is not created, and no HTTP POST, Success, payload staging, app cache, or Catalog promotion occurs.
- In the same E2E target, also verify a dry-run with the protected credential store, issuer allowlist, store freshness, and revocation state in the platform/linux sealed-object mapping. Because the plain Linux backend has `protected-storage-binding=observation-only`, even when the observed AttesTAM `kid` matches a protected credential store entry for both app TC and Catalog TC, expect `protected-credential-store-bound=false`, `issuer-allowlist-bound=false`, `trust-anchor-bound=false`, and `final-verified=false`, and verify that `summary.trust_anchor_blockers` contains `teep.protected_credential_store_unbound`, `teep.issuer_allowlist_unbound`, `teep.store_freshness_unbound`, and `teep.revocation_state_unbound`. On a positive observation path with a matching issuer allowlist, advance to `protected-credential-store-issuer-allowlist-match=true`; when store freshness/revocation match, advance to `protected-credential-store-freshness=matched-unbound` and `protected-credential-store-revocation-status=matched-unbound`, but do not promote to formally bound on Linux. Also verify that observing a revoked credential entry does not proceed to HTTP POST, Success, payload staging, app cache, or Catalog promotion. TrustZone smoke tests and `wasm/teep-agent` unit tests must continue to verify the implemented D038 transition to bound credential/policy state on TrustZone REE FS Secure Storage without treating those individual bindings as a final decision.
- When an Update COSE_Sign1 signed with the demo TAM key is placed in `teep-agent/verified-input.cose`, the TEE-side Rust TEEP_Agent verifies the outer COSE_Sign1 and saves observation artifacts for an Update whose requested component ID and payload hash match. In this fixed-input dry-run only, advance to `session_token_bound=true` when `teep-agent/verified-expected-token.bin` byte-matches the Update token. In the D046 live path, advance that state only when both rolling tokens are non-empty and bounded and the Update is the immediate response in the session-owned Evidence continuation; equality is not required. Advance to `suit_auth_verified=true` and write the observation result to `teep-agent/suit-auth-status.txt` only when the auth digest in the SUIT envelope matches the raw SHA-256 digest of the manifest bstr and the detached COSE_Sign1 auth block verifies with the demo TAM key. When `protected-sequence-freshness.cbor` exists, advance to `sequence_fresh=true` only for an Update greater than the last sequence for that component ID, and reject equal or rollback sequences as `teep.sequence_unverified`. Fall back to development-only `teep-agent/dev-sequence-freshness.cbor` on plain Linux only when this protected object is absent. The Linux verified dry-run intentionally does not update accepted sequence state or D043 acceptance state: it retains `final-verified=false` and `teep.verified_required` and does not proceed to staging, Success, app cache, or Catalog update. The TrustZone M9.1 live path uses the D043 acceptance commit after full immediate-Update verification, then intentionally returns the same terminal error without installation.
- For D047 M9.2, permit Catalog File updates only from the exact `[bstr("twep-catalog-v1"), bstr("default")]` Catalog TC. Verify positive initial install, higher-sequence replacement, selection after restart, and continued selection after a non-Catalog D043 generation change. Verify that an app TC, another Catalog name, debug JSON, an AttesTAM management artifact, personalization data, or insecure app metadata cannot update it. Reject signature, token, payload digest, component id, sequence, generation, canonical-CBOR, schema, unsafe-basename, more-than-256-entry, more-than-16-level, 64-KiB-plus-one Catalog, and 128-KiB-plus-one inbound-response failures.
- Exercise every protected Catalog transaction boundary: inactive-slot create/write/close/reopen/readback faults, digest mismatch, malformed or unsupported slot, ambiguous matching slots, D043 compare conflict, and restart between candidate storage and D043 publication. Before publication the old Catalog must remain byte-for-byte active and usable. After publication the new Catalog and D043 Catalog sequence must advance exactly once, Success may be generated, replay must fail, and `final-verified=false` must remain explicit. Generic protected-object PUT/provision and general Wasm hostcalls must reject all logical and physical D047 object names.
- Fix the EAT Evidence entry point with `wasm/teep-agent` unit tests. Verify that the `challenge` can be extracted from a TEEP QueryRequest; challenges shorter than 8 bytes or longer than 64 bytes, malformed or unsupported public COSE_Key values, output-buffer shortage, and tampered signatures are rejected. Verify that the Rust TEEP_Agent constructs the Generic EAT and signs it with the fixed ES256 Evidence key previously used by the REE fixture. In `attestam-insecure`, fixture tests fix that the development EAT is included in QueryResponse `attestation-payload` and sent in the second POST; that the EAT nonce matches the QueryRequest challenge; that EAT `cnf.key` refers to the TEEP Agent key used to sign QueryResponse; and that UEID, profile, and measurement digest match the Generic EAT CoRIM fixture. Test both default and alternate TEEP Agent keys: only `cnf.key` and the QueryResponse signer change, while the Evidence signer remains fixed. Run the Go/E2E challenge-response with the REE `create_evidence` callback unset. Keep the legacy hostcall probe tests to confirm ABI round trips and the existing `unsupported` result when no callback is registered.

## Final Verified Mode Tests

Add the following in Milestone 9 and later.

- In `internal/verifiedteep` unit tests, extract the SUIT Envelope, Component Identifier, sequence number, payload URI, integrated payload, and payload digest from a fixture COSE_Sign1 TEEP Update, and verify the payload SHA-256 match. Verify the outer TEEP message COSE_Sign1 and the detached COSE_Sign1 in the SUIT authentication wrapper with the fixture developer key, rejecting tampering with COSE or the auth block. Verify that the session token retained from QueryRequest/QueryResponse matches the Update token, rejecting missing and mismatched tokens. Permit only Updates greater than the last sequence for each component ID, rejecting equal and rollback sequences. Apply the four fixture checks in order with `VerifyFixtureUpdateCOSE`, and verify that even success yields `FixtureVerified=true` and `Verified=false`. At this stage the parser is not final verified because a formal trust anchor and persistent freshness storage inside the TEE are not implemented.
- In `wasm/teep-agent` unit tests, fix the state model for verification steps moved into the TEE. Verify that the first missing step and error code are returned until `cose_outer_verified`, `session_token_bound`, `suit_auth_verified`, and `sequence_fresh` are satisfied in order, and that the result is still not final verified when all fixture steps are present. For CBOR maps equivalent to `protected-sequence-freshness.cbor` and fallback `teep-agent/dev-sequence-freshness.cbor`, verify that only Updates greater than the last sequence for each component ID are fresh, and reject equal and rollback sequences.
- Fetch the Catalog File and Trusted Wasm App from a real AttesTAM instance or test fixture server.
- Install only components that pass COSE/SUIT verification.
- Reject invalid signatures, hash mismatches, and old sequences.
- Update the Catalog File only from payloads verified as a `twep-catalog-v1` Catalog TC, never from a `twep-app-v1` app TC.
- Do not allow `resolver.mode="mock"` or `attestam-insecure` settings to leak into `attestam-verified`.
- On `platform/linux`, do not advance to `trust-anchor-bound=true` or `final-verified=true`, even when Protected credential store and issuer allowlist schemas, simulated sealed storage, and revocation/store freshness can be observed.
- On TrustZone/SGX/Keystone backends, include sealed storage rollback, issuer allowlist matching, revocation updates, component sequence freshness, and Evidence generation in platform tests.
- In the current D045 PoC, do not apply a Trusted Component without the milestone-specific verified Catalog/app transition; M9.1 is acceptance-only. TEEP_Agent must not consume a Veraison Attestation Result directly. In a Linux dry-run, legacy `verified-evidence-result.cbor` observations may remain compatibility diagnostics but must not advance to `evidence-affirming=true` or `final-verified=true`. In TrustZone REE FS Secure Storage tests, positive AttesTAM acceptance requires a TAM-signed Update and current D043 acceptance generation, plus `protected-agent-identity.cbor` matching the TA-local TEEP_Agent identity. D045 requires `final-verified=false` even when all PoC checks pass.

## Golden data

Store the following in `testdata/cbor/`.

- `request_helloworld.cbor`
- `request_calcadd_3_4_5.cbor`
- `response_helloworld_ok.cbor`
- `response_calcadd_ok.cbor`
- `response_error_catalog_not_found.cbor`

Store the following in `testdata/images/`.

- `input.jpg`
- `expected_negaposi.jpg` or a fixture for pixel comparison
- `invalid.txt`
- `broken.jpg`

Store the following in `testdata/catalog/`.

- `catalog.dev.json`
- `catalog.dev.cbor`
- `catalog.hash_mismatch.cbor`
- `catalog.path_traversal.cbor`

## CI Policy

The following is sufficient for the initial CI.

```sh
make fmt
make build
make test
```

If WAMR builds are expensive, add separate CI targets for C ABI smoke tests and WAMR integration tests.

## Test Report Format

Record test results in the following form.

```text
Executed:
- make fmt: pass/fail
- make build: pass/fail
- make test: pass/fail
- make e2e: pass/fail/not run
- make e2e-attestam-insecure: pass/fail/not run
- make e2e-attestam-live: pass/fail/not run

Reason not run:
Failure details:
Remediation plan:
```
