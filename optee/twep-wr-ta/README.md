# twep-wr OP-TEE TrustZone Backend Project

This directory contains the current OP-TEE scaffold for the `twep-wr`
TrustZone backend. It started as a smoke-test project and now implements the
TrustZone `twep_wr_execute` path through TA-local WAMR execution while
preserving public C ABI v3. TA-local TEEP_Agent, Catalog resolution, and
ordinary app execution are implemented behind the same opt-in WAMR link flag
documented in [TA WAMR build flag](#ta-wamr-build-flag).

For a three-level Mermaid view of this directory, see
`optee/twep-wr-ta/ARCHITECTURE.md`. For the production `twepd` to TA
connection path as a rendered SVG, see `docs/optee_trustzone_production.svg`.

## How to Read This Directory

There are three distinct paths in this directory. Keep them separate when
reading code, logs, or smoke results.

| Path | Entry point | Purpose | Trust decision owner |
| --- | --- | --- | --- |
| Production public path | `twepd` -> `internal/twepwr` -> `libtwep_wr.so` -> `libteec` -> TA `EXECUTE`/`RESUME_HOST_IO` | The target TrustZone backend path for user commands. It preserves public C ABI v3 while moving TEEP_Agent, Catalog resolution, and app execution into the TA. Wasm execution requires the TA to be built with `TWEP_TA_WAMR_LINK=1`. | TA-local TEEP_Agent and TA-local production runtime |
| Direct TA smoke path | `optee_example_twep_wr_ta` -> `libteec` -> TA private commands | Fast boundary validation for TEEC session handling, TA command ABI, secure storage, random/time, diagnostics, and focused negative cases. | The smoke checks transport and TA behavior; it is not the public `twepd` path |
| WAMR spike path | `TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC` | Regression-only feasibility check for the original WAMR-in-TA spike command. Uses the same `TWEP_TA_WAMR_LINK=1` build as production TA WAMR, but remains a separate command entrypoint. | None for production trust; do not treat it as `twep_wr_execute` |

The normal user-facing TrustZone flow is the production public path:

```text
twep-cli
  -> twepd
  -> internal/twepwr cgo wrapper
  -> libtwep_wr.so platform/trustzone
  -> libteec / TEEC_InvokeCommand
  -> twep-wr TA
```

## Scope

The TA and REE host app currently validate these boundaries:

- TEEC session open, command invoke, and close.
- TA platform status reporting.
- OP-TEE secure storage PUT/GET roundtrip.
- OP-TEE random/time command smoke through private TA commands
  (`TA_TWEP_WR_CMD_GET_RANDOM`, `TA_TWEP_WR_CMD_GET_TIME`). The TA platform
  status string still reports `random=false` and `time=false` because the
  public `libtwep_wr.so` TrustZone platform API does not expose those
  primitives to REE callers.
- CBOR request/response memref command shape smoke.
- TrustZone `twep-cli diagnose verified` artifacts through the
  `platform/trustzone` backend, including `agent-identity-status.txt` with
  `agent-identity-source=platform-status-ta-local`,
  `protected-agent-identity-load=loaded-unbound` after provisioning, and
  `agent-identity-binding=matched-unbound` when the provisioned identity
  expectation matches the TA-local platform status. D038 makes REE FS Secure
  Storage the permanent TrustZone storage target, so the next implementation
  step can promote a matching TrustZone identity to `agent-identity-bound=true`
  without introducing RPMB.
- Provisioning smoke for protected credential and policy object names.
- Failure smoke for missing object reads, empty object provisioning, and
  short-buffer reads.
- Regression smoke for the original WAMR-in-TA spike command.
- Production TA execution for TEEP_Agent, Catalog resolution, and ordinary app
  runtime through `TA_TWEP_WR_CMD_INIT` / `EXECUTE` / `RESUME_HOST_IO`.
  These paths require `TWEP_TA_WAMR_LINK=1` at TA build time; the
  repository `Makefile` sets that flag for the relevant smoke targets.

The TrustZone backend is labeled `tee-ree-fs-secure-storage` for the permanent
`CFG_REE_FS=y`, `CFG_RPMB_FS=n` configuration. This repository adopts OP-TEE
REE FS Secure Storage as the TrustZone secure storage policy and excludes
rollback attacks from the threat model. `sealed-storage-rollback-protected=false`
is diagnostic information, not a final verified blocker. Secure storage
roundtrips alone are still not enough for `trust-anchor-bound=true` or
`final-verified=true`; the positive path also needs TEEP/COSE/SUIT verification,
credential/policy object consistency, Veraison Generic EAT `affirming`, and
TEEP_Agent identity binding.

TA-local WAMR execution is also not a final verified claim by itself. Until
the final trust-anchor binding, freshness/revocation policy, Generic EAT, and
identity conditions are implemented, current TrustZone diagnostics still keep
`trust-anchor-bound=false` and `final-verified=false`.

## TA Command ABI

The scaffold currently fixes these command IDs:

| Command | ID | Shape |
| --- | ---: | --- |
| `TA_TWEP_WR_CMD_PING` | 0 | value in/out |
| `TA_TWEP_WR_CMD_GET_PLATFORM_STATUS` | 1 | output memref |
| `TA_TWEP_WR_CMD_SECURE_STORAGE_PUT` | 2 | object-name input memref, value input memref |
| `TA_TWEP_WR_CMD_SECURE_STORAGE_GET` | 3 | object-name input memref, value output memref |
| `TA_TWEP_WR_CMD_GET_RANDOM` | 4 | output memref |
| `TA_TWEP_WR_CMD_GET_TIME` | 5 | value output: seconds, millis |
| `TA_TWEP_WR_CMD_CBOR_DRY_RUN` | 6 | request input memref, response output memref |
| `TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC` | 7 | Wasm input memref, app input memref, response output memref |
| `TA_TWEP_WR_CMD_INIT` | 8 | production init CBOR input memref, response output memref |
| `TA_TWEP_WR_CMD_EXECUTE` | 9 | production execute CBOR input memref, response output memref |
| `TA_TWEP_WR_CMD_RESUME_HOST_IO` | 10 | host I/O resume CBOR input memref, response output memref |
| `TA_TWEP_WR_CMD_MEASURE_WASM` | 11 | REE-supplied Wasm bytes measurement input memref, measurement output memref |

`TA_TWEP_WR_CMD_CBOR_DRY_RUN` returns a static canonical CBOR response. It
does not parse requests or execute WAMR.

`TA_TWEP_WR_CMD_MEASURE_WASM` is a diagnostic helper that hashes REE-supplied
Wasm bytes inside the TA. It is not a TA-loaded/executed module identity
binding signal and does not establish final trust evidence. There is no direct
`optee_example_twep_wr_ta` smoke for this command; `libtwep_wr.so`
`platform/trustzone` invokes it during verified diagnostics and provisioning
smokes (for example `protected-agent-identity-measurement-source=trustzone-ta-measure-wasm`).

`TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC` is an isolated feasibility spike command. The
default build does not link WAMR, so the expected default result is
`TEEC_ERROR_NOT_SUPPORTED` with the TA log message that the WAMR runtime is not
linked into the TA.

## TA WAMR build flag

The production makefile flag is `TWEP_TA_WAMR_LINK`; it gates **all** TA-local
WAMR code, including the retained historical spike command in
`ta/ta_wamr_spike.c`. The former `TWEP_TA_WAMR_SPIKE_LINK` input remains a deprecated exact
alias. Supplying both names with different values is an error.

| `TWEP_TA_WAMR_LINK` | TA behavior |
| --- | --- |
| `0` (default for `make -C optee/twep-wr-ta`) | Boundary smokes, secure storage, envelope parsing, synthetic host-I/O smoke commands, and `TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC` rejection. `EXECUTE` with Wasm bytes returns `TEE_ERROR_NOT_SUPPORTED`. |
| `1` | Builds `wamr-ta/` into `build/wamr-ta/libiwasm.a`, links it into the TA, and enables production TEEP_Agent/app execution plus the spike command. |

Typical local builds:

```sh
# Default scaffold only
make -C optee/twep-wr-ta

# Production/runtime smokes and spike-linked regressions
make -C optee/twep-wr-ta TWEP_TA_WAMR_LINK=1
```

Repository entry points such as `make smoke-optee-trustzone-execute-helloworld`
run `prepare-diagnose-smoke.sh` and then build the TA with
`TWEP_TA_WAMR_LINK=1` automatically.

When WAMR is linked, `TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC` loads supplied
`helloworld.wasm` bytes, calls `twep_app_main`, and returns raw app CBOR
output. That command remains a regression spike entrypoint and is not the
production `twep_wr_execute` path.

The production TrustZone path uses CBOR envelope v1:

- `INIT`: resolver mode, AttesTAM URL, insecure flag, default timeout, maximum
  request size, and maximum response size.
- `EXECUTE`: `request_id`, `command`, `app_input_cbor`, and
  `request_timeout_ms`.
- `EXECUTE`/`RESUME_HOST_IO` response: either `final_response_cbor` using the
  existing `twep_wr_execute` response schema, or `need_host_io`.

`need_host_io` is intentionally narrow. The settled ABI also permits
`read_state_object` and `write_state_object`, but the current TA emits only
`http_post` and `create_evidence` in `need_host_io` responses. TEEP_Agent
object reads and writes that stay inside the TA use synchronous
`twep_host_read_file` / `twep_host_write_file` natives over TA-managed object
names; they do not round-trip through REE resume. `twep_host_read_protected` is
registered for the protected object allowlist and maps to OP-TEE REE FS Secure
Storage. Generic TEEP_Agent writes to
`teep-agent/verified-evidence-result.cbor` are rejected. The public REE Secure
Storage PUT command also rejects `verified-evidence-result.cbor`, the logical
`teep-acceptance-state.cbor` name, and both TA-internal physical slot names.
Only the dedicated D043 acceptance commit updates the slots and persists the
positive-result object for the final-capable reader. REE code carries bytes,
performs HTTP transport, and brokers
Evidence bytes; it does not make Catalog trust decisions.

Host I/O continuation follows Decision D027. The production path does not keep
a live WAMR call frame across an REE roundtrip. Instead, the TA stores
session-local continuation state for the `request_id`, normalized TEEP_Agent
input, policy, `io_id`, hostcall kind, request bytes, and transcript sequence
or digest. `RESUME_HOST_IO` validates the result against that state and then
re-executes the same TEEP_Agent Wasm binary or enters an explicit continuation
entrypoint. REE-provided bytes are hostcall result material only.

SHA-256 ownership is split by trust boundary. Catalog entry, SUIT payload, and
app binary trust decisions belong to the platform-independent TEEP_Agent Wasm
binary so Linux, TrustZone, SGX, and other backends run the same verification
logic. The TA C runtime may use SHA-256 only for TA-private transport and
continuation binding, such as `request_body_sha256` and
`normalized_input_sha256` in host I/O resume envelopes. Those digests reject
REE broker resume mismatches; they are not Catalog, Trusted Component, or app
promotion decisions.

The production TA runtime owns the following when
`TWEP_TA_WAMR_LINK=1`:

- TEEP_Agent execution inside TA-local WAMR.
- Catalog lookup, TC/app classification, payload hash verification, and app
  execution authorization.
- General app ABI version check, Catalog resource limit application,
  `twep_app_main`, `twep_app_free`, app output CBOR wrapping, and cleanup after
  each execution.
- TEEP_Agent-only `twep_teep_env` hostcalls backed by TA/TEE APIs or explicit
  host I/O resume.

General apps do not receive TEEP_Agent capability. Imports from `env.*` or
`twep_teep_env.*` in a general app are rejected in the production runtime.
`helloworld`, `calcadd`, and `negaposi` are the parity targets. For `negaposi`,
CLI/REE keeps user file path reads and writes; the TA receives JPEG bytes in
CBOR input and returns `files.output` bytes.

The `teep-agent-resolve-hash-negative` smoke intentionally passes app bytes
that do not match the Catalog hash. The expected result is the TEEP_Agent Wasm
error code `app.hash_mismatch`, proving the Catalog/app hash decision is made
by the TEEP_Agent Wasm logic and not by REE broker code or a TA C Catalog
parser.

The `teep-agent-resolve-catalog-negative` smoke covers the same ownership for
Catalog parse and lookup failures. Invalid Catalog bytes must surface as
`catalog.invalid`, and a missing target command must surface as
`catalog.not_found`, both from TEEP_Agent Wasm output. The TA C path transports
those errors but does not become the Catalog parser or trust-decision owner.

The `teep-agent-resolve-wrapped-error-negative` smoke covers the production
response boundary. TEEP_Agent Wasm errors for `catalog.invalid`,
`catalog.not_found`, and `app.hash_mismatch` are wrapped into the existing
`twep_wr_execute` error response shape with `status="error"`, `exit_code=1`,
the original TEEP_Agent error code/message, and `error.details.source` set to
`teep-agent`. The REE host smoke receives that output as transport-owned bytes
from `TA_TWEP_WR_CMD_EXECUTE` and validates it as the public
`twep_wr_execute`-compatible response; it does not parse Catalog contents or
reconstruct the user-facing trust decision. The
`public-abi-wrapped-error-negative` smoke then exercises the first TrustZone
build public C ABI connection: `twep_wr_execute` marshals
`teep-agent-resolve-wrapped` to `TA_TWEP_WR_CMD_EXECUTE` and returns the wrapped
`catalog.not_found` error as `twep_wr_owned_bytes_t`. The
`public-abi-app-hash-negative` smoke exercises the normal public ABI app
command path with a corrupted cached app wasm: the TA-local TEEP_Agent returns
`app.hash_mismatch`, and the TA maps it to the existing `twep_wr_execute`
wrapped error response. The
`public-abi-execute-helloworld` smoke uses the same public C ABI transport for a
success path: REE carries `teep-agent.wasm`, Catalog bytes, and
`helloworld.wasm` bytes from its cache to the TA. The TA-local TEEP_Agent
resolves the Catalog entry first, and only then does the TA-local production
WAMR runtime return the wrapped `twep_wr_execute` success response. The
`public-abi-execute-calcadd` smoke extends that public ABI success path to
`calcadd.wasm` with `inferred_params` CBOR for `3 4 5`, and checks the TA-local
response carries `stdout="12\n"` and `result.sum=12`. The
`public-abi-execute-negaposi` smoke keeps user path I/O in the REE smoke
harness: it reads the JPEG input path, sends only `files.input` bytes in CBOR to
the TA, then saves the returned `files.output` JPEG bytes to the REE output
path.

## Files

- `project.conf`: OP-TEE app metadata used by `optee_postrun.py`
  (`APP_NAME=twep_wr_ta`; the deployed REE smoke binary remains
  `optee_example_twep_wr_ta`).
- `deploy.sh`: installs the host app and TA inside the QEMU guest.
- `host/`: REE `libteec` client. `host/Makefile` builds
  `optee_example_twep_wr_ta` from `main.c`. `prepare-diagnose-smoke.sh`
  separately cross-builds `guest/bin/twep_wr_public_abi_smoke` from
  `public_abi_smoke.c`.
- `ta/`: OP-TEE TA entrypoint and UUID header.
- `prepare-diagnose-smoke.sh`: builds Linux guest binaries, a TrustZone
  `libtwep_wr.so`, protected-object CBOR fixtures, and WAMR spike payloads
  under ignored `guest/`.
- `run_trustzone_smokes.sh`: guest-side runner for smoke modes.
- `diagnose_verified_trustzone.sh`: verified dry-run diagnostics smoke.
- `provision_and_diagnose_trustzone.sh`: provisioning plus diagnostics smoke.
- `protected_storage_failure_smoke.sh`: protected storage failure smoke.
- `wamr-ta/`: OP-TEE TA WAMR platform shim built and linked when
  `TWEP_TA_WAMR_LINK=1`. It backs both the production TA runtime and the
  regression spike command; only the `TA_TWEP_WR_CMD_WAMR_SPIKE_EXEC` entrypoint
  is spike-specific.

## Guest Runner

The guest-side runner is `run_trustzone_smokes.sh`.

```sh
run_trustzone_smokes.sh default
run_trustzone_smokes.sh diagnose
run_trustzone_smokes.sh provision
run_trustzone_smokes.sh failures
run_trustzone_smokes.sh abi-vectors
run_trustzone_smokes.sh execute-abi-negative
run_trustzone_smokes.sh execute-helloworld
run_trustzone_smokes.sh execute-calcadd
run_trustzone_smokes.sh execute-negaposi
run_trustzone_smokes.sh execute-hostcall-negative
run_trustzone_smokes.sh execute-cleanup-negative
run_trustzone_smokes.sh execute-catalog-resource-negative
run_trustzone_smokes.sh teep-agent-resolve
run_trustzone_smokes.sh teep-agent-resolve-hash-negative
run_trustzone_smokes.sh teep-agent-resolve-catalog-negative
run_trustzone_smokes.sh teep-agent-resolve-wrapped-error-negative
run_trustzone_smokes.sh public-abi-wrapped-error-negative
run_trustzone_smokes.sh public-abi-app-hash-negative
run_trustzone_smokes.sh public-abi-resource-limit-negative
run_trustzone_smokes.sh public-abi-execute-helloworld
run_trustzone_smokes.sh public-abi-execute-calcadd
run_trustzone_smokes.sh public-abi-execute-negaposi
run_trustzone_smokes.sh attestam-live
run_trustzone_smokes.sh attestam-verified-acceptance
run_trustzone_smokes.sh attestam-verified-catalog
run_trustzone_smokes.sh host-io-resume
run_trustzone_smokes.sh host-io-resume-negative
run_trustzone_smokes.sh sha256-boundary-negative
run_trustzone_smokes.sh teep-agent-hostcall-http
run_trustzone_smokes.sh teep-agent-hostcall-evidence
run_trustzone_smokes.sh teep-agent-transcript-limits
run_trustzone_smokes.sh teep-agent-hostcall-bridge
run_trustzone_smokes.sh teep-agent-acceptance
run_trustzone_smokes.sh teep-agent-acceptance-faults
run_trustzone_smokes.sh teep-agent-two-session-generation
run_trustzone_smokes.sh teep-agent-hostcall-object-negative
run_trustzone_smokes.sh wamr-spike
run_trustzone_smokes.sh wamr-spike-linked
run_trustzone_smokes.sh wamr-spike-linked-negative
run_trustzone_smokes.sh wamr-spike-input-negative
run_trustzone_smokes.sh wamr-spike-output-negative
run_trustzone_smokes.sh wamr-spike-cleanup-negative
run_trustzone_smokes.sh wamr-spike-negatives
run_trustzone_smokes.sh all
```

The `attestam-verified-catalog`, `teep-agent-acceptance-faults`, and
`teep-agent-two-session-generation` modes use test-only protected-storage
checks. Run them through the
corresponding repository-root `make smoke-optee-trustzone-*` targets; those
targets build with `TWEP_TA_D043_TEST_HOOKS=1` and remove the hook-enabled host
and TA artifacts when the run ends. An ordinary build does not expose the D043
test command.

`all` runs only the bundled guest checkpoint:
`default`, `diagnose`, and `provision`. Run the other modes individually, or
use the repository `Makefile` targets such as `make smoke-optee-trustzone` and
`make check-optee-trustzone-smokes` for broader coverage.

The fixed command-to-artifact mapping used by the public TrustZone smoke path
is **PoC candidate artifact preloading**, not an authorization database. The
REE recognizes the demo commands so it can transport candidate Wasm bytes to
the TA. Those bytes remain untrusted input: the TA-local TEEP Agent validates
Catalog metadata and hashes, and the TA-local general-app runtime makes the
execution authorization decision. An REE mapping, cache hit, filename, or
successful transport cannot authorize Catalog publication, app promotion, or
execution by itself.
