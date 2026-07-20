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

## Source Layout

- `src/runtime.c`: public ABI entry points, context lifecycle, state layout,
  shared CBOR parsing helpers, and shared WAMR app-call helpers.
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
- `src/platform/`: backend-specific file, random, time, and protected-storage
  primitives.

## Security Boundary Notes

General Trusted Wasm Apps receive no native hostcalls.
TEEP_Agent hostcalls are registered under `twep_teep_env` and additionally
require the TEEP_Agent exec-env capability before they act on state.

Linux protected storage is development-only and reports observation-level
security. It must not be treated as a final trust anchor for verified mode.
