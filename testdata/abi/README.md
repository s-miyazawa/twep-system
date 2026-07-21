# Canonical CBOR ABI vectors

`vectors.hex` is the reviewable representation of the shared canonical CBOR
byte vectors. Each non-comment line is `name|hex`; decoding the hexadecimal
field yields the exact `.cbor` bytes. Text storage avoids platform-specific
binary-file tooling while the tests still compare the decoded bytes exactly.

| Vector | Expected fields |
| --- | --- |
| `public-request` | `schema_version=1`, `request_id="req"`, `command="helloworld"`, empty `argv` and `inferred_params`, empty `cwd` |
| `public-response` | `schema_version=1`, matching `request_id`, `status="ok"`, `exit_code=0` |
| `agent-resolve-request` | `command="resolve_app"`, `target_command="helloworld"`, `resolver_mode="mock"`, state and URL text fields |
| `agent-resolve-response` | minimal successful TEEP Agent result |
| `trustzone-execute-envelope` | `request_id`, normalized `command`, opaque `app_input_cbor`, and `request_timeout_ms` |
| `trustzone-resume-envelope` | `request_id` plus opaque `host_io_result_cbor` |

Go and Rust decode and canonically re-encode every vector. The public vectors
also pass through the typed Go codec. TrustZone parser and QEMU smoke coverage
use the same field contracts; the C/TA boundary intentionally treats embedded
CBOR values as opaque byte strings.
