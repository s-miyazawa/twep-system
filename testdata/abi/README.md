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
also pass through the typed Go codec. `make smoke-optee-trustzone-abi-vectors`
copies this file unchanged into the QEMU guest; the C host decodes all six
entries and sends the exact `trustzone-execute-envelope` and
`trustzone-resume-envelope` bytes through TEEC to the TA parsers. The execute
vector must parse successfully, while the resume vector must reach the parser
and fail because no continuation is pending. Embedded CBOR remains opaque at
the C/TA boundary.
