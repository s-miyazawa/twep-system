# twep-wr

`twep-wr` is the C shared-library boundary between Go `twepd` and WAMR. Go code
must call this layer through `include/twep_wr.h`; it must not hold WAMR
internal pointers, Wasm memory pointers, or native runtime handles.

## Public Surface

- `include/twep_wr.h` is the only public header.
- `twep_wr_execute` receives a normalized ABI v3 request:
  `request_id`, `command`, `app_input_cbor`, and `request_timeout_ms`.
- Buffers returned to Go are owned by C and must be released with
  `twep_wr_free_bytes`.

`twep_host_attestation_payload_format` is internal to `twep_teep_env`, not a
public callback or ABI-v3 field. General applications cannot import it. Linux
and the `arm-optee` and `riscv-optee` profiles provide Generic EAT. Keystone is
an explicit stub whose public ABI initialization returns `TWEP_WR_ERR_INIT`
before WAMR starts.
Selecting `TWEP_WR_PLATFORM_BACKEND=sgx` builds the SGX hardware runtime.
`TWEP_WR_SGX_BACKEND_TESTS=ON` instead creates a non-deployable backend-test
harness that uses the SDK Simulation transport; it is not a runtime or security
profile. Neither build falls back to REE execution.

The inactive Agent public-key and ESP256 signing compatibility imports have
been removed from the Wasm hostcall ABI. The Rust TEEP Agent owns and selects
the fixed development key and signs QueryResponse/Success itself. Public C ABI
v3 is unchanged.

## SGX Private Implementation

SGX hardware and private backend-test builds place WAMR only in the Enclave. The untrusted
library supplies lifecycle and allowlisted byte transport; the Enclave owns
TEEP Agent privilege, protected state, Catalog/app authorization, and app
execution. This is private implementation behind unchanged public C ABI v3.
See [the SGX backend profile](../../docs/sgx/Backend.md) for the authoritative design,
[the ABI](../../docs/ABI.md) for contracts and limits, and
[the test plan](../../docs/Testing.md) for build and smoke commands.

## Source Layout

- `src/runtime.c`: public ABI validation, common context lifecycle, request and
  response limits, state layout, and shared CBOR helpers.
- `src/app_runtime.c`: general Trusted Wasm App loading, resource-limit
  application, app ABI calls, output extraction, and response assembly.
- `src/catalog_resolver.c`: catalog lookup policy, TEEP_Agent resolve-app
  invocation, resolve output validation, and catalog resource-limit parsing.
- `src/teep_agent_runtime.c`: TEEP_Agent-only native hostcall registration and
  hostcall policy checks.
- `src/response_cbor.c`: twep response CBOR construction for successful app
  output and app error output.
- `src/runtime_internal.h`: private implementation boundary shared only by
  `src/*.c`.
- `src/platform/`: file, random, time, and protected-storage primitives plus
  direct OP-TEE and SGX execution helpers. `runtime.c` selects exactly one
  backend at compile time; only SGX retains opaque Enclave lifecycle state.

The SGX trusted/untrusted source map is maintained in
[the SGX backend profile](../../docs/sgx/Backend.md#implementation-map).

OP-TEE is selected explicitly as `arm-optee` or `riscv-optee`. Both choices
compile `src/platform/optee-common/` plus one minimal descriptor from
`src/platform/<profile>/`. The former ambiguous `platform/trustzone` backend
no longer exists, and CMake rejects a profile whose target CPU does not match.

## Security Boundary Notes

General Trusted Wasm Apps receive no native hostcalls.
TEEP_Agent hostcalls are registered under `twep_teep_env` and additionally
require the TEEP_Agent exec-env capability before they act on state.

Linux protected storage is development-only and reports observation-level
security. It must not be treated as a final trust anchor for verified mode.
